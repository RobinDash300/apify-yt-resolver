// server.mjs
import http from "node:http";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { URL } from "node:url";
import { Readable } from "node:stream";

// ---------- env ----------
const PORT = process.env.ACTOR_WEB_SERVER_PORT || process.env.PORT || 8080;
const SIGN_SECRET = process.env.SIGN_SECRET || "CHANGE_ME";
const TOKEN_TTL_SEC = parseInt(process.env.TOKEN_TTL_SEC || "300", 10);
const CORS_ALLOW = process.env.CORS_ALLOW || "*";
const UA_DEFAULT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";
const UA_TIKTOK =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1";
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || "25000", 10);
const AUTO_EXIT_IDLE_MS = parseInt(process.env.AUTO_EXIT_IDLE_MS || "0", 10);
const PROXY_PARAM = process.env.PROXY_PARAM || "sig";

// yt-dlp related env
const YT_COOKIES_PATH = process.env.YT_COOKIES_PATH || ""; // optional cookies file for YouTube
const YTDLP_ARGS = (process.env.YTDLP_ARGS || "").trim(); // optional extra args, space separated
const YTDLP_PATH = process.env.YTDLP_PATH || "yt-dlp"; // override binary if needed

// proxy env
const STATIC_PROXY_URL =
  process.env.PROXY_URL ||
  process.env.APIFY_PROXY_URL ||
  process.env.HTTP_PROXY ||
  process.env.HTTPS_PROXY ||
  "";

// ---------- proxy support (fetch and yt-dlp) ----------
let PROXY_CONTEXT = null;
async function getProxyContext() {
  if (PROXY_CONTEXT) return PROXY_CONTEXT;

  let proxyUrl = STATIC_PROXY_URL || null;
  let dispatcher = null;

  if (!proxyUrl) {
    // Try Apify proxy if available
    try {
      const { Actor } = await import("apify");
      const proxyConfig = await Actor.createProxyConfiguration();
      proxyUrl = await proxyConfig.newUrl();
    } catch {
      // not running on Apify or apify not installed
    }
  }

  if (proxyUrl) {
    try {
      const undici = await import("undici");
      const { ProxyAgent } = undici;
      dispatcher = new ProxyAgent(proxyUrl);
    } catch {
      // undici not available, fetch will run without proxy
    }
  }

  PROXY_CONTEXT = { proxyUrl, dispatcher };
  return PROXY_CONTEXT;
}

// ---------- utils ----------
let lastActivityAt = Date.now();

const b64url = (b) =>
  Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const nowSec = () => Math.floor(Date.now() / 1000);

function signToken(payloadObj) {
  const body = b64url(JSON.stringify(payloadObj));
  const sig = b64url(crypto.createHmac("sha256", SIGN_SECRET).update(body).digest());
  return `${body}.${sig}`;
}
function verifyToken(token) {
  const [body, sig] = token.split(".");
  if (!body || !sig) throw new Error("Bad token");
  const expSig = b64url(crypto.createHmac("sha256", SIGN_SECRET).update(body).digest());
  if (sig !== expSig) throw new Error("Bad signature");
  const payload = JSON.parse(unb64url(body).toString("utf8"));
  if (!payload || !payload.u || !payload.exp) throw new Error("Bad payload");
  if (payload.exp < nowSec()) throw new Error("Expired");
  return payload;
}
function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", CORS_ALLOW);
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Range,Authorization,X-Requested-With,Origin,Accept"
  );
  res.setHeader(
    "Access-Control-Expose-Headers",
    "Content-Range,Accept-Ranges,Content-Length,Content-Type"
  );
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.setHeader("Timing-Allow-Origin", CORS_ALLOW);
  res.setHeader("Vary", "Origin, Range");
  res.setHeader("Connection", "close");
}
function getSelfOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || "localhost";
  return `${proto}://${host}`;
}

// ---------- URL helpers ----------
function toAbsoluteUrl(base, ref) {
  try {
    return new URL(ref).toString();
  } catch {
    return new URL(ref, base).toString();
  }
}
function looksLikeM3U8(urlObj, contentType) {
  if (
    contentType &&
    /application\/vnd\.apple\.mpegurl|application\/x-mpegURL|audio\/mpegurl/i.test(contentType)
  )
    return true;
  return /\.m3u8($|\?)/i.test(urlObj.pathname);
}
function looksDirectMedia(urlStr) {
  try {
    const { pathname } = new URL(urlStr);
    return /\.(mp4|webm|m4v|mov|m3u8)(\?|$)/i.test(pathname);
  } catch {
    return false;
  }
}
function isTikTokShort(u) {
  try {
    const h = new URL(u).host;
    return /(^|\.)vm\.tiktok\.com$/i.test(h);
  } catch {
    return false;
  }
}
function isTikTokHost(u) {
  try {
    const h = new URL(u).host;
    return /tiktok\.com$/i.test(h);
  } catch {
    return false;
  }
}
function isYouTube(u) {
  try {
    const host = new URL(u).host.replace(/^www\./, "");
    return host === "youtube.com" || host === "m.youtube.com" || host === "youtu.be";
  } catch {
    return false;
  }
}

// ---------- HLS rewrite ----------
function proxify(selfOrigin, absUrl, ttlSec, headers) {
  const exp = nowSec() + ttlSec;
  const token = signToken({ u: absUrl, exp, h: headers || null });
  return `${selfOrigin}/proxy?${PROXY_PARAM}=${encodeURIComponent(token)}`;
}
function rewriteM3U8(text, sourceUrl, selfOrigin, ttlSec, headers) {
  const lines = text.split(/\r?\n/);
  return lines
    .map((line) => {
      if (!line || line.startsWith("#")) {
        if (line.startsWith("#EXT-X-KEY") || line.startsWith("#EXT-X-MAP")) {
          return line.replace(/URI="([^"]+)"/, (_m, uriVal) => {
            const abs = toAbsoluteUrl(sourceUrl, uriVal);
            return `URI="${proxify(selfOrigin, abs, ttlSec, headers)}"`;
          });
        }
        return line;
      }
      const abs = toAbsoluteUrl(sourceUrl, line.trim());
      return proxify(selfOrigin, abs, ttlSec, headers);
    })
    .join("\n");
}

// ---------- header builder ----------
const CANON = {
  "user-agent": "User-Agent",
  referer: "Referer",
  origin: "Origin",
  cookie: "Cookie",
  accept: "Accept",
  "accept-language": "Accept-Language",
  "sec-fetch-mode": "Sec-Fetch-Mode",
  "sec-fetch-site": "Sec-Fetch-Site",
  "sec-fetch-dest": "Sec-Fetch-Dest",
};
const ALLOW_SET = new Set(Object.keys(CANON));

function buildUpstreamHeaders(baseHeaders, pageOrMediaUrl, canonicalPageUrl) {
  const H = {};
  const src = baseHeaders || {};

  for (const [k, v] of Object.entries(src)) {
    if (!v) continue;
    const lower = k.toLowerCase();
    if (ALLOW_SET.has(lower)) H[CANON[lower]] = v;
  }

  if (!H["Accept"]) H["Accept"] = "*/*";
  if (!H["Accept-Language"]) H["Accept-Language"] = "en-US,en;q=0.5";

  if (canonicalPageUrl && !H["Referer"]) H["Referer"] = canonicalPageUrl;

  try {
    if (!H["Origin"] && H["Referer"]) H["Origin"] = new URL(H["Referer"]).origin;
  } catch {}
  if (!H["Origin"]) {
    try {
      H["Origin"] = new URL(pageOrMediaUrl).origin;
    } catch {}
  }

  try {
    const host = new URL(pageOrMediaUrl).host || "";
    if (host.includes("tiktok")) {
      if (!H["User-Agent"]) H["User-Agent"] = UA_TIKTOK;
      if (!H["Referer"]) H["Referer"] = "https://www.tiktok.com/";
      if (!H["Origin"]) H["Origin"] = "https://www.tiktok.com";
      if (!H["Sec-Fetch-Mode"]) H["Sec-Fetch-Mode"] = "cors";
      if (!H["Sec-Fetch-Site"]) H["Sec-Fetch-Site"] = "cross-site";
      if (!H["Sec-Fetch-Dest"]) H["Sec-Fetch-Dest"] = "video";
    }
  } catch {
    if (!H["User-Agent"]) H["User-Agent"] = UA_DEFAULT;
  }

  if (!H["User-Agent"]) H["User-Agent"] = UA_DEFAULT;

  return H;
}

// ---------- TikTok short link resolver ----------
async function resolveTikTokShort(inputUrl) {
  if (!isTikTokShort(inputUrl)) return inputUrl;

  const { dispatcher } = await getProxyContext();
  let current = inputUrl;
  for (let i = 0; i < 5; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
    let resp;
    try {
      resp = await fetch(current, {
        method: "GET",
        redirect: "manual",
        headers: {
          "User-Agent": UA_TIKTOK,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        signal: controller.signal,
        dispatcher,
      });
    } finally {
      clearTimeout(timer);
    }

    const loc = resp.headers.get("location") || resp.headers.get("Location");
    if (!loc) break;

    // Absolute vs relative
    if (/^https?:\/\//i.test(loc)) {
      current = loc;
    } else {
      const base = new URL(current);
      current = new URL(loc, `${base.protocol}//${base.host}`).toString();
    }

    // stop once it lands on tiktok.com video page
    if (isTikTokHost(current) && /\/video\//.test(current)) return current;
  }
  return current;
}

// ---------- yt-dlp ----------
function parseExtraArgs(raw) {
  if (!raw) return [];
  // simple split by spaces, no quotes support to keep deps minimal
  return raw.split(/\s+/).filter(Boolean);
}

async function ytdlpJson(userUrl, opts = {}) {
  const { referer = "", ua = "", useCookies = false } = opts;

  const args = ["-j", "--no-warnings", "--skip-download", "--geo-bypass"];
  // Prefer no playlist expansion when single item intended
  args.push("--no-playlist");

  // add headers for certain sites
  const addHeaders = [];
  if (ua) addHeaders.push(`User-Agent:${ua}`);
  if (referer) addHeaders.push(`Referer:${referer}`);
  // also pass Accept to mimic browser better
  addHeaders.push("Accept:*/*");
  addHeaders.push("Accept-Language:en-US,en;q=0.5");
  for (const h of addHeaders) {
    args.push("--add-header", h);
  }

  // cookies for YouTube if supplied
  if (useCookies && YT_COOKIES_PATH) {
    args.push("--cookies", YT_COOKIES_PATH);
  }

  // proxy
  const { proxyUrl } = await getProxyContext();
  if (proxyUrl) {
    args.push("--proxy", proxyUrl);
  }

  // user supplied extras
  args.push(...parseExtraArgs(YTDLP_ARGS));

  args.push(userUrl);

  return new Promise((resolve, reject) => {
    const p = spawn(YTDLP_PATH, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => {
      if (code !== 0 || !out.trim()) return reject(new Error(err || `yt-dlp exited ${code}`));
      try {
        const lines = out
          .trim()
          .split(/\r?\n/)
          .map((l) => JSON.parse(l));
        resolve(lines);
      } catch (e) {
        reject(e);
      }
    });
  });
}

function pickBest(lines) {
  const allFormats = lines.flatMap((j) => j.formats || []).filter(Boolean);
  const hls = allFormats.find(
    (f) => f && (f.protocol?.includes("m3u8") || /\.m3u8/i.test(f.url || ""))
  );
  if (hls)
    return {
      url: hls.url,
      type: "hls",
      headers: lines[0]?.http_headers || hls.http_headers || null,
      metaFrom: lines[0],
    };
  const best = allFormats.filter((f) => f.url).sort((a, b) => (b.tbr || 0) - (a.tbr || 0))[0];
  if (best)
    return {
      url: best.url,
      type: best.ext || "mp4",
      headers: lines[0]?.http_headers || best.http_headers || null,
      metaFrom: lines[0],
    };
  const single = lines.find((j) => j.url);
  if (single)
    return {
      url: single.url,
      type: single.ext || "unknown",
      headers: single.http_headers || null,
      metaFrom: single,
    };
  return null;
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  lastActivityAt = Date.now();
  const started = Date.now();
  const selfOrigin = getSelfOrigin(req);
  const u = new URL(req.url, `${selfOrigin}`);
  cors(res);

  console.log(`[REQ] ${req.method} ${u.pathname}${u.search || ""}`);

  if (req.headers["x-apify-container-server-readiness-probe"]) {
    res.writeHead(200, { "Content-Type": "text/plain" }).end("OK");
    return;
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }

  try {
    if (u.pathname === "/_health") {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
      return;
    }

    if (req.method === "GET" && u.pathname === "/") {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("resolver+proxy up");
      return;
    }

    // POST /extract
    if (req.method === "POST" && u.pathname === "/extract") {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", async () => {
        const startedInner = Date.now();
        try {
          const { url: rawUrl } = JSON.parse(body || "{}");
          if (!rawUrl) {
            res.writeHead(400).end('{"ok":false,"error":"Missing url"}');
            return;
          }

          // resolve TikTok short links before yt-dlp
          let pageUrl = await resolveTikTokShort(rawUrl);

          let mediaUrl = pageUrl;
          let headers = null;
          let metaFrom = null;

          if (!looksDirectMedia(pageUrl)) {
            const useCookies = isYouTube(pageUrl);
            const ua = isTikTokHost(pageUrl) ? UA_TIKTOK : UA_DEFAULT;
            const lines = await ytdlpJson(pageUrl, {
              referer: pageUrl,
              ua,
              useCookies,
            });
            const best = pickBest(lines);
            if (!best) {
              res.writeHead(404).end(JSON.stringify({ ok: false, error: "No playable URL" }));
              return;
            }
            mediaUrl = best.url;
            headers = best.headers || null;
            metaFrom = best.metaFrom || null;
          }

          const canonical = metaFrom?.webpage_url || pageUrl;
          const upstreamHeaders = buildUpstreamHeaders(headers, mediaUrl, canonical);

          const meta = metaFrom
            ? {
                title: metaFrom.title,
                duration: metaFrom.duration,
                width: metaFrom.width || metaFrom.width_height?.[0],
                height: metaFrom.height || metaFrom.width_height?.[1],
                extractor: metaFrom.extractor,
                webpage_url: metaFrom.webpage_url,
              }
            : null;

          const expiresAt = nowSec() + TOKEN_TTL_SEC;
          const signed = signToken({ u: mediaUrl, exp: expiresAt, h: upstreamHeaders });
          const proxyUrl = `${selfOrigin}/proxy?${PROXY_PARAM}=${encodeURIComponent(signed)}`;

          res
            .writeHead(200, { "Content-Type": "application/json" })
            .end(JSON.stringify({ ok: true, mode: "proxy", type: "auto", proxyUrl, expiresAt, meta }));
        } catch (e) {
          console.error("extract error:", e);
          res
            .writeHead(502, { "Content-Type": "application/json" })
            .end(JSON.stringify({ ok: false, error: String(e) }));
        } finally {
          console.log(`[END] /extract in ${Date.now() - startedInner}ms`);
        }
      });
      return;
    }

    // GET /sign?u=...
    if (req.method === "GET" && u.pathname === "/sign") {
      const input = u.searchParams.get("u");
      if (!input) {
        res.writeHead(400).end('{"ok":false,"error":"Missing u"}');
        return;
      }

      let abs;
      try {
        abs = new URL(input).toString();
      } catch {
        res.writeHead(400).end('{"ok":false,"error":"Bad URL"}');
        return;
      }

      try {
        // resolve TikTok short link first
        let pageUrl = await resolveTikTokShort(abs);

        let mediaUrl = pageUrl;
        let headers = null;
        let metaFrom = null;

        if (!looksDirectMedia(pageUrl)) {
          const useCookies = isYouTube(pageUrl);
          const ua = isTikTokHost(pageUrl) ? UA_TIKTOK : UA_DEFAULT;
          const lines = await ytdlpJson(pageUrl, {
            referer: pageUrl,
            ua,
            useCookies,
          });
          const best = pickBest(lines);
          if (!best) {
            res.writeHead(404).end(JSON.stringify({ ok: false, error: "No playable URL" }));
            return;
          }
          mediaUrl = best.url;
          headers = best.headers || null;
          metaFrom = best.metaFrom || null;
        }

        const canonical = metaFrom?.webpage_url || pageUrl;
        const upstreamHeaders = buildUpstreamHeaders(headers, mediaUrl, canonical);

        const expiresAt = nowSec() + TOKEN_TTL_SEC;
        const signed = signToken({ u: mediaUrl, exp: expiresAt, h: upstreamHeaders });
        const proxyUrl = `${selfOrigin}/proxy?${PROXY_PARAM}=${encodeURIComponent(signed)}`;

        res
          .writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ ok: true, proxyUrl, expiresAt }));
        console.log(`[END] /sign -> proxy in ${Date.now() - started}ms`);
        return;
      } catch (e) {
        console.error("sign error:", e);
        res
          .writeHead(502, { "Content-Type": "application/json" })
          .end(JSON.stringify({ ok: false, error: String(e) }));
        return;
      }
    }

    // GET or HEAD /proxy?sig=...
    if ((req.method === "GET" || req.method === "HEAD") && u.pathname === "/proxy") {
      const signed = u.searchParams.get(PROXY_PARAM);
      if (!signed) {
        res.writeHead(400).end("Missing signature");
        return;
      }

      let payload;
      try {
        payload = verifyToken(signed);
      } catch {
        res.writeHead(403).end("Invalid signature");
        return;
      }

      const upstreamUrl = new URL(payload.u);
      const clientRange = req.headers.range;
      const ua = req.headers["user-agent"] || UA_DEFAULT;

      // Build forwarded headers
      const h = {};
      h["User-Agent"] =
        (payload.h && (payload.h["User-Agent"] || payload.h["user-agent"])) ||
        (upstreamUrl.host.includes("tiktok") ? UA_TIKTOK : ua);

      const COPY = [
        "Referer",
        "Origin",
        "Cookie",
        "Accept",
        "Accept-Language",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-Dest",
      ];
      for (const name of COPY) {
        const v = payload.h?.[name] ?? payload.h?.[name.toLowerCase()];
        if (v) h[name] = v;
      }

      // Avoid gzip for video
      h["Accept-Encoding"] = "identity";

      // Force Range for obvious file URLs if client did not send it
      let range = clientRange;
      if (!range) {
        const p = upstreamUrl.pathname.toLowerCase();
        if (p.endsWith(".mp4") || p.endsWith(".m4v") || p.endsWith(".webm") || p.endsWith(".mov")) {
          range = "bytes=0-";
        }
      }
      const reqHeaders = { ...(range ? { Range: range } : {}), ...h };

      const controller = new AbortController();
      const { dispatcher } = await getProxyContext();
      const t = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

      let upstream;
      try {
        upstream = await fetch(upstreamUrl.toString(), {
          method: req.method,
          redirect: "follow",
          headers: reqHeaders,
          signal: controller.signal,
          dispatcher,
        });
      } catch (err) {
        clearTimeout(t);
        console.error("fetch upstream failed:", err);
        res.writeHead(502).end("Upstream fetch failed");
        return;
      } finally {
        clearTimeout(t);
      }

      let ct = upstream.headers.get("content-type") || "";

      // Retry once for TikTok if HTML or not ok
      if ((!upstream.ok || /^text\/html/i.test(ct)) && upstreamUrl.host.includes("tiktok")) {
        const retryHeaders = {
          ...reqHeaders,
          "User-Agent": UA_TIKTOK,
          "Referer": reqHeaders["Referer"] || "https://www.tiktok.com/",
          "Origin": reqHeaders["Origin"] || "https://www.tiktok.com",
          "Accept-Encoding": "identity",
        };
        if (!retryHeaders.Range) retryHeaders.Range = "bytes=0-";

        upstream = await fetch(upstreamUrl.toString(), {
          method: req.method,
          redirect: "follow",
          headers: retryHeaders,
          signal: controller.signal,
          dispatcher,
        });

        ct = upstream.headers.get("content-type") || "";
      }

      if (!upstream.ok && !/^(video|application\/vnd\.apple\.mpegurl|application\/x-mpegURL)/i.test(ct)) {
        console.log("[UPSTREAM]", upstream.status, ct, "URL:", upstreamUrl.toString());
      }

      // HLS playlist rewrite
      if (req.method === "GET" && looksLikeM3U8(upstreamUrl, ct)) {
        const manifest = await upstream.text();
        const rewritten = rewriteM3U8(
          manifest,
          upstreamUrl,
          selfOrigin,
          TOKEN_TTL_SEC,
          payload.h || null
        );
        res.setHeader("Cache-Control", "no-store");
        res
          .writeHead(200, { "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8" })
          .end(rewritten);
        console.log(`[END] /proxy (m3u8) in ${Date.now() - started}ms`);
        return;
      }

      // Pass through important headers
      const acceptRanges = upstream.headers.get("accept-ranges");
      const contentRange = upstream.headers.get("content-range");
      const contentLength = upstream.headers.get("content-length");
      const contentType = upstream.headers.get("content-type");

      if (acceptRanges) res.setHeader("Accept-Ranges", acceptRanges);
      if (contentRange) res.setHeader("Content-Range", contentRange);
      if (contentLength) res.setHeader("Content-Length", contentLength);
      if (contentType) res.setHeader("Content-Type", contentType);
      if (!res.getHeader("Cache-Control")) res.setHeader("Cache-Control", "no-store");

      res.writeHead(upstream.status);

      if (req.method === "HEAD") {
        res.end();
        console.log(`[END] /proxy HEAD in ${Date.now() - started}ms`);
        return;
      }

      try {
        if (upstream.body) {
          const nodeReadable = Readable.fromWeb(upstream.body);
          nodeReadable.on("data", () => {
            lastActivityAt = Date.now();
          });
          nodeReadable.on("error", () => {
            try {
              res.end();
            } catch {}
          });
          nodeReadable.pipe(res);
        } else {
          res.end();
        }
      } catch (e) {
        console.error("stream pipe error:", e);
        try {
          res.end();
        } catch {}
      } finally {
        console.log(`[END] /proxy passthrough in ${Date.now() - started}ms`);
      }
      return;
    }

    // 404
    res.writeHead(404, { "Content-Type": "text/plain" }).end("Not found");
  } catch (e) {
    console.error("server error:", e);
    try {
      res.writeHead(500).end(String(e));
    } catch {}
  }
});

// ---------- server tune ----------
server.keepAliveTimeout = 5000;
server.headersTimeout = 8000;

server.listen(PORT, () => console.log(`resolver+proxy listening on :${PORT}`));

// ---------- idle exit ----------
if (AUTO_EXIT_IDLE_MS > 0) {
  setInterval(() => {
    const idle = Date.now() - lastActivityAt;
    if (idle > AUTO_EXIT_IDLE_MS) {
      console.log(`[EXIT] idle ${idle}ms > ${AUTO_EXIT_IDLE_MS}ms, exiting`);
      setTimeout(() => process.exit(0), 200);
    }
  }, Math.min(AUTO_EXIT_IDLE_MS, 10000));
}
