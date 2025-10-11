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
const AUTO_EXIT_IDLE_MS = parseInt(process.env.AUTO_EXIT_IDLE_MS || "0", 10); // e.g. 90000
const FORCE_PROXY = (process.env.FORCE_PROXY || "").toLowerCase() === "true";
const PROXY_PARAM = process.env.PROXY_PARAM || "sig"; // name for our signed blob param (do not use "token")

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
  res.setHeader("Connection", "close");
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

// ---------- direct-play heuristic ----------
async function isDirectPlayable(url) {
  try {
    const r = await fetch(url, { method: "HEAD", redirect: "follow" });
    const rangeOk = (r.headers.get("accept-ranges") || "").toLowerCase().includes("bytes");
    const notHls = !/\.m3u8($|\?)/i.test(new URL(url).pathname);
    return rangeOk && notHls;
  } catch {
    return false;
  }
}

// ---------- yt-dlp ----------
function ytdlpJson(userUrl) {
  return new Promise((resolve, reject) => {
    const args = ["-j", "--no-warnings", "--skip-download", userUrl];
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

function pickBest(lines) {
  const allFormats = lines.flatMap((j) => j.formats || []).filter(Boolean);
  let hls = allFormats.find(
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

  // Apify standby readiness
  if (req.headers["x-apify-container-server-readiness-probe"]) {
    res.writeHead(200, { "Content-Type": "text/plain" }).end("OK");
    return;
  }

  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }

  try {
    // Health
    if (u.pathname === "/_health") {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
      return;
    }

    // Root
    if (req.method === "GET" && u.pathname === "/") {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("resolver+proxy up");
      return;
    }

    // POST /extract
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

          const lines = await ytdlpJson(pageUrl);
          const best = pickBest(lines);
          if (!best) {
            res.writeHead(404).end(JSON.stringify({ ok: false, error: "No playable URL" }));
            return;
          }

          const upstreamHeaders = {};
          if (best.headers?.["User-Agent"]) upstreamHeaders["User-Agent"] = best.headers["User-Agent"];
          upstreamHeaders["Referer"] = best.headers?.["Referer"] || new URL(pageUrl).origin;

          const metaFrom = best.metaFrom || {};
          const meta = {
            title: metaFrom.title,
            duration: metaFrom.duration,
            width: metaFrom.width || metaFrom.width_height?.[0],
            height: metaFrom.height || metaFrom.width_height?.[1],
            extractor: metaFrom.extractor,
            webpage_url: metaFrom.webpage_url,
          };

          // Prefer direct when safe
          if (!FORCE_PROXY && (await isDirectPlayable(best.url))) {
            const expiresAt = nowSec() + TOKEN_TTL_SEC; // hint
            res
              .writeHead(200, { "Content-Type": "application/json" })
              .end(
                JSON.stringify({
                  ok: true,
                  mode: "direct",
                  type: best.type,
                  directUrl: best.url,
                  expiresAt,
                  meta,
                })
              );
            console.log("[INFO] /extract -> direct URL");
            return;
          }

          // Sign for proxy
          const expiresAt = nowSec() + TOKEN_TTL_SEC;
          const signed = signToken({ u: best.url, exp: expiresAt, h: upstreamHeaders });
          const proxyUrl = `${selfOrigin}/proxy?${PROXY_PARAM}=${encodeURIComponent(signed)}`;

          res
            .writeHead(200, { "Content-Type": "application/json" })
            .end(JSON.stringify({ ok: true, mode: "proxy", type: best.type, proxyUrl, expiresAt, meta }));
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

    // GET /sign?u=...
    if (req.method === "GET" && u.pathname === "/sign") {
      const direct = u.searchParams.get("u");
      if (!direct) {
        res.writeHead(400).end('{"ok":false,"error":"Missing u"}');
        return;
      }
      let directUrl;
      try {
        directUrl = new URL(direct).toString();
      } catch {
        res.writeHead(400).end('{"ok":false,"error":"Bad URL"}');
        return;
      }
      const expiresAt = nowSec() + TOKEN_TTL_SEC;
      const signed = signToken({ u: directUrl, exp: expiresAt, h: null });
      const proxyUrl = `${selfOrigin}/proxy?${PROXY_PARAM}=${encodeURIComponent(signed)}`;
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: true, proxyUrl, expiresAt }));
      console.log(`[END] /sign in ${Date.now() - started}ms`);
      return;
    }

    // GET or HEAD /proxy?sig=...
    if ((req.method === "GET" || req.method === "HEAD") && u.pathname === "/proxy") {
      // Our signed blob is in PROXY_PARAM. Do not use "token" here.
      const signed = u.searchParams.get(PROXY_PARAM);
      if (!signed) {
        res.writeHead(400).end("Missing signature");
        return;
      }

      let payload;
      try {
        payload = verifyToken(signed);
      } catch (e) {
        res.writeHead(403).end("Invalid signature");
        return;
      }

      const upstreamUrl = new URL(payload.u);
      const range = req.headers.range;
      const ua = req.headers["user-agent"] || UA_DEFAULT;

      const h = { "User-Agent": ua };
      if (payload.h?.["Referer"]) h["Referer"] = payload.h["Referer"];
      if (payload.h?.["Cookie"]) h["Cookie"] = payload.h["Cookie"];

      // timeout guard
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

      let upstream;
      try {
        upstream = await fetch(upstreamUrl.toString(), {
          method: req.method, // GET or HEAD
          redirect: "follow",
          headers: { ...(range ? { Range: range } : {}), ...h },
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(t);
        console.error("fetch upstream failed:", err);
        res.writeHead(502).end("Upstream fetch failed");
        return;
      } finally {
        clearTimeout(t);
      }

      const ct = upstream.headers.get("content-type") || "";
      // HLS manifest rewrite
      if (req.method === "GET" && looksLikeM3U8(upstreamUrl, ct)) {
        const manifest = await upstream.text();
        const rewritten = rewriteM3U8(manifest, upstreamUrl, selfOrigin, TOKEN_TTL_SEC, payload.h || null);
        res.setHeader("Cache-Control", "no-store");
        res.writeHead(200, { "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8" }).end(rewritten);
        console.log(`[END] /proxy (m3u8) in ${Date.now() - started}ms`);
        return;
      }

      // Pass headers that matter for playback and canvas
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
          nodeReadable.on("end", () => {});
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
