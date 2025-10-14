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
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || "25000", 10);
const UPSTREAM_INACTIVITY_MS_RAW = process.env.UPSTREAM_INACTIVITY_MS;
const UPSTREAM_INACTIVITY_MS = Number.isFinite(Number(UPSTREAM_INACTIVITY_MS_RAW))
  ? Math.max(parseInt(UPSTREAM_INACTIVITY_MS_RAW, 10) || 0, 0)
  : Math.max(Math.floor(UPSTREAM_TIMEOUT_MS / 2), 8000);
const AUTO_EXIT_IDLE_MS = parseInt(process.env.AUTO_EXIT_IDLE_MS || "0", 10);
const PROXY_PARAM = process.env.PROXY_PARAM || "sig"; // do not use "token" here
const HLS_TOKEN_TTL_SEC = parseInt(process.env.HLS_TOKEN_TTL_SEC || "1800", 10);

let lastActivityAt = Date.now();

// ---------- utils ----------
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
}
function getSelfOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || "localhost";
  return `${proto}://${host}`;
}

// ---------- HLS helpers ----------
function toAbsoluteUrl(base, ref) {
  try {
    return new URL(ref).toString();
  } catch {
    return new URL(ref, base).toString();
  }
}
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
function looksLikeM3U8(urlObj, contentType) {
  if (
    contentType &&
    /application\/vnd\.apple\.mpegurl|application\/x-mpegURL|audio\/mpegurl/i.test(contentType)
  )
    return true;
  return /\.m3u8($|\?)/i.test(urlObj.pathname);
}

// ---------- media detection ----------
function looksDirectMedia(urlStr) {
  try {
    const { pathname } = new URL(urlStr);
    return /\.(mp4|webm|m4v|mov|m3u8)(\?|$)/i.test(pathname);
  } catch {
    return false;
  }
}

// ---------- yt-dlp ----------
function ytdlpJson(userUrl) {
  return new Promise((resolve, reject) => {
    // Add UA + Referer to improve extraction reliability from DC IPs
    let referer = "";
    try {
      const u = new URL(userUrl);
      referer = u.origin;
      if (u.host.includes("tiktok")) referer = "https://www.tiktok.com/";
      if (u.host.includes("youtube.") || u.host.includes("youtu.be")) referer = "https://www.youtube.com/";
      if (u.host.includes("reddit.")) referer = "https://www.reddit.com/";
    } catch {}

    const args = [
      "-j",
      "--no-warnings",
      "--skip-download",
      "--no-call-home",
      "--geo-bypass",
      "--user-agent",
      UA_DEFAULT,
      "--add-header",
      `Referer:${referer || userUrl}`,
      userUrl,
    ];

    const p = spawn("yt-dlp", args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "",
      err = "";
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

// Prefer HLS master or progressive (audio+video) over video-only DASH
function pickBest(lines) {
  const allFormats = lines.flatMap((j) => j.formats || []).filter(Boolean);

  const hasAudio = (f) => !f || f.acodec === undefined || (f.acodec && f.acodec !== "none");
  const isHls = (f) =>
    f && (f.protocol?.includes("m3u8") || /\.m3u8/i.test(f.url || "") || f.manifest_url);

  // 1) Prefer HLS master (tends to be A+V and browser-friendly)
  const hls = allFormats.find((f) => isHls(f));
  if (hls) {
    return {
      url: hls.url || hls.manifest_url,
      type: "hls",
      headers: lines[0]?.http_headers || hls.http_headers || null,
      metaFrom: lines[0],
    };
  }

  // 2) Prefer progressive with audio (ext mp4/webm and acodec != none)
  const progressiveAV = allFormats
    .filter(
      (f) =>
        f.url &&
        hasAudio(f) &&
        (/(mp4|webm)$/i.test(f.ext || "") || /(mp4|webm)/i.test(f.container || "")) &&
        !/dash|segment/i.test(f.protocol || "")
    )
    .sort((a, b) => (b.tbr || 0) - (a.tbr || 0))[0];
  if (progressiveAV) {
    return {
      url: progressiveAV.url,
      type: progressiveAV.ext || "mp4",
      headers: lines[0]?.http_headers || progressiveAV.http_headers || null,
      metaFrom: lines[0],
    };
  }

  // 3) Fall back to any http(s) URL (may be video-only)
  const bestAny = allFormats.filter((f) => f.url).sort((a, b) => (b.tbr || 0) - (a.tbr || 0))[0];
  if (bestAny) {
    return {
      url: bestAny.url,
      type: bestAny.ext || "unknown",
      headers: lines[0]?.http_headers || bestAny.http_headers || null,
      metaFrom: lines[0],
    };
  }

  // 4) Single URL on the root (rare)
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

// ---------- robust upstream fetch (GET even for HEAD) ----------
async function fetchUpstreamWithRetry(urlStr, opts, inactivityMs, maxRetries = 1) {
  let attempt = 0;
  let lastErr;
  while (attempt <= maxRetries) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
    try {
      const resp = await fetch(urlStr, {
        ...opts,
        method: "GET",
        signal: controller.signal,
        redirect: "follow",
      });
      clearTimeout(timeout);

      if (!resp.ok && resp.status >= 500 && attempt < maxRetries) {
        attempt++;
        lastErr = new Error(`Upstream ${resp.status}`);
        continue;
      }

      let nodeStream = null;

      if (resp.body) {
        if (inactivityMs > 0) {
          const reader = resp.body.getReader();
          let inactivityTimer = setTimeout(() => controller.abort(), inactivityMs);

          nodeStream = new Readable({ read() {} });

          (async () => {
            try {
              for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                lastActivityAt = Date.now();
                clearTimeout(inactivityTimer);
                inactivityTimer = setTimeout(() => controller.abort(), inactivityMs);
                nodeStream.push(Buffer.from(value));
              }
              clearTimeout(inactivityTimer);
              nodeStream.push(null);
            } catch (e) {
              clearTimeout(inactivityTimer);
              nodeStream.destroy(e);
            }
          })();
        } else {
          nodeStream = Readable.fromWeb(resp.body);
        }
      }

      return { resp, nodeStream, usedGetForHead: opts.method === "HEAD" };
    } catch (e) {
      clearTimeout(timeout);
      lastErr = e;
      if (attempt < maxRetries) {
        attempt++;
        continue;
      }
      throw lastErr;
    }
  }
  throw lastErr || new Error("Unknown upstream error");
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  lastActivityAt = Date.now();
  const started = Date.now();
  const selfOrigin = getSelfOrigin(req);
  const u = new URL(req.url, `${selfOrigin}`);
  cors(res);

  console.log(`[REQ] ${req.method} ${u.pathname}${u.search || ""}`);

  // standby readiness
  if (req.headers["x-apify-container-server-readiness-probe"]) {
    res.writeHead(200, { "Content-Type": "text/plain" }).end("OK");
    return;
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }

  try {
    // health
    if (u.pathname === "/_health") {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
      return;
    }

    // root
    if (req.method === "GET" && u.pathname === "/") {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("resolver+proxy up");
      return;
    }

    // POST /extract -> always proxy (page URL or direct URL)
    if (req.method === "POST" && u.pathname === "/extract") {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", async () => {
        try {
          const { url: pageUrl } = JSON.parse(body || "{}");
          if (!pageUrl) {
            res.writeHead(400).end('{"ok":false,"error":"Missing url"}');
            return;
          }

          let mediaUrl = pageUrl;
          let headers = null;
          let metaFrom = null;

          if (!looksDirectMedia(pageUrl)) {
            const lines = await ytdlpJson(pageUrl);
            const best = pickBest(lines);
            if (!best) {
              res.writeHead(404).end(JSON.stringify({ ok: false, error: "No playable URL" }));
              return;
            }
            mediaUrl = best.url;
            headers = best.headers || null;
            metaFrom = best.metaFrom || null;
          }

          // default headers and TikTok referer hardening
          const upstreamHeaders = headers ? { ...headers } : {};
          if (!upstreamHeaders["User-Agent"]) upstreamHeaders["User-Agent"] = UA_DEFAULT;
          if (!upstreamHeaders["Referer"]) {
            try {
              const host = new URL(pageUrl).host || "";
              if (host.includes("tiktok")) upstreamHeaders["Referer"] = "https://www.tiktok.com/";
              else upstreamHeaders["Referer"] = new URL(pageUrl).origin;
            } catch {}
          }

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
          console.log(`[END] /extract in ${Date.now() - started}ms`);
        }
      });
      return;
    }

    // GET /sign?u=... -> universal: accepts page or direct, always returns proxy
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
        let mediaUrl = abs;
        let headers = null;
        let metaFrom = null;

        if (!looksDirectMedia(abs)) {
          const lines = await ytdlpJson(abs);
          const best = pickBest(lines);
          if (!best) {
            res.writeHead(404).end(JSON.stringify({ ok: false, error: "No playable URL" }));
            return;
          }
          mediaUrl = best.url;
          headers = best.headers || null;
          metaFrom = best.metaFrom || null;
        }

        const upstreamHeaders = headers ? { ...headers } : {};
        if (!upstreamHeaders["User-Agent"]) upstreamHeaders["User-Agent"] = UA_DEFAULT;
        if (!upstreamHeaders["Referer"]) {
          try {
            const host = new URL(abs).host || "";
            if (host.includes("tiktok")) upstreamHeaders["Referer"] = "https://www.tiktok.com/";
            else upstreamHeaders["Referer"] = new URL(abs).origin;
          } catch {}
        }

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
      const range = req.headers.range;
      const ua = req.headers["user-agent"] || UA_DEFAULT;

      const h = {
        "User-Agent": ua,
        Accept: "*/*",
        "Accept-Language": "en-US,en;q=0.8",
      };
      if (payload.h?.["Referer"]) h["Referer"] = payload.h["Referer"];
      if (payload.h?.["Cookie"]) h["Cookie"] = payload.h["Cookie"];
      if (range) h["Range"] = range;
      // forwarding Origin helps some CDNs (safe for GET)
      if (req.headers.origin) h["Origin"] = req.headers.origin;

      let upstream;
      try {
        upstream = await fetchUpstreamWithRetry(
          upstreamUrl.toString(),
          { method: req.method, headers: h },
          UPSTREAM_INACTIVITY_MS,
          1
        );
      } catch (err) {
        console.error("fetch upstream failed:", err);
        res.writeHead(502).end("Upstream fetch failed");
        return;
      }

      const resp = upstream.resp;
      const ct = resp.headers.get("content-type") || "";

      if (req.method === "GET" && looksLikeM3U8(upstreamUrl, ct)) {
        const manifest = upstream.nodeStream
          ? await streamToString(upstream.nodeStream)
          : await resp.text();
        const rewritten = rewriteM3U8(
          manifest,
          upstreamUrl,
          selfOrigin,
          HLS_TOKEN_TTL_SEC,
          payload.h || null
        );
        res.setHeader("Cache-Control", "no-store");
        res
          .writeHead(200, { "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8" })
          .end(rewritten);
        console.log(`[END] /proxy (m3u8) in ${Date.now() - started}ms`);
        return;
      }

      const acceptRanges = resp.headers.get("accept-ranges");
      const contentRange = resp.headers.get("content-range");
      const contentLength = resp.headers.get("content-length");
      const contentType = resp.headers.get("content-type");

      if (acceptRanges) res.setHeader("Accept-Ranges", acceptRanges);
      else if (range) res.setHeader("Accept-Ranges", "bytes");

      if (contentRange) res.setHeader("Content-Range", contentRange);
      if (contentLength) res.setHeader("Content-Length", contentLength);
      if (contentType) res.setHeader("Content-Type", contentType);
      if (!res.getHeader("Cache-Control")) res.setHeader("Cache-Control", "no-store");

      res.writeHead(resp.status);

      if (req.method === "HEAD") {
        res.end();
        console.log(`[END] /proxy HEAD in ${Date.now() - started}ms`);
        return;
      }

      try {
        if (upstream.nodeStream) {
          upstream.nodeStream.on("data", () => (lastActivityAt = Date.now()));
          upstream.nodeStream.on("error", () => {
            try {
              res.end();
            } catch {}
          });
          upstream.nodeStream.pipe(res);
        } else if (resp.body) {
          const nodeReadable = Readable.fromWeb(resp.body);
          nodeReadable.on("data", () => (lastActivityAt = Date.now()));
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

// Helper for reading a stream into string (used for m3u8 rewrite)
function streamToString(stream) {
  return new Promise((resolve, reject) => {
    let data = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => (data += chunk));
    stream.on("end", () => resolve(data));
    stream.on("error", reject);
  });
}

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
