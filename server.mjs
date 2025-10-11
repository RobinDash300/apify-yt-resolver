// server.mjs
import http from "node:http";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { URL } from "node:url";
import { Readable } from "node:stream";

const PORT = process.env.ACTOR_WEB_SERVER_PORT || process.env.PORT || 8080;
const SIGN_SECRET = process.env.SIGN_SECRET || "CHANGE_ME";
const TOKEN_TTL_SEC = parseInt(process.env.TOKEN_TTL_SEC || "300", 10);
const CORS_ALLOW = process.env.CORS_ALLOW || "*";
const UA_DEFAULT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || "25000", 10);

// ---- auto-exit on idle ----
const AUTO_EXIT_IDLE_MS = parseInt(process.env.AUTO_EXIT_IDLE_MS || "0", 10); // e.g. 90000
let lastActivityAt = Date.now();

// ---------- utils ----------
const b64url = (b) => Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64url = (s) => Buffer.from(s.replace(/-/g,"+").replace(/_/g,"/"), "base64");
const nowSec = () => Math.floor(Date.now()/1000);

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
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Range,Authorization,X-Requested-With");
  res.setHeader("Access-Control-Expose-Headers", "Content-Range,Accept-Ranges,Content-Length,Content-Type");
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.setHeader("Timing-Allow-Origin", CORS_ALLOW);
  res.setHeader("Connection", "close"); // encourage quick idle
}

function getSelfOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || "localhost";
  return `${proto}://${host}`;
}

// ---------- HLS helpers ----------
function toAbsoluteUrl(base, ref) {
  try { return new URL(ref).toString(); } catch { return new URL(ref, base).toString(); }
}
function proxify(selfOrigin, absUrl, ttlSec, headers) {
  const exp = nowSec() + ttlSec;
  const token = signToken({ u: absUrl, exp, h: headers || null });
  return `${selfOrigin}/proxy?token=${encodeURIComponent(token)}`;
}
function rewriteM3U8(text, sourceUrl, selfOrigin, ttlSec, headers) {
  const lines = text.split(/\r?\n/);
  return lines.map(line => {
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
  }).join("\n");
}
function looksLikeM3U8(urlObj, contentType) {
  if (contentType && /application\/vnd\.apple\.mpegurl|application\/x-mpegURL|audio\/mpegurl/i.test(contentType)) return true;
  return /\.m3u8($|\?)/i.test(urlObj.pathname);
}

// ---------- yt-dlp ----------
function ytdlpJson(userUrl) {
  return new Promise((resolve, reject) => {
    const args = ["-j", "--no-warnings", "--skip-download", userUrl];
    const p = spawn("yt-dlp", args, { stdio: ["ignore","pipe","pipe"] });
    let out = "", err = "";
    p.stdout.on("data", d => out += d);
    p.stderr.on("data", d => err += d);
    p.on("close", code => {
      if (code !== 0 || !out.trim()) return reject(new Error(err || `yt-dlp exited ${code}`));
      try {
        const lines = out.trim().split(/\r?\n/).map(l => JSON.parse(l));
        resolve(lines);
      } catch (e) { reject(e); }
    });
  });
}
function pickBest(lines) {
  const allFormats = lines.flatMap(j => j.formats || []).filter(Boolean);
  let hls = allFormats.find(f => (f.protocol?.includes("m3u8") || /\.m3u8/i.test(f.url || "")));
  if (hls) return { url: hls.url, type: "hls", headers: lines[0]?.http_headers || hls.http_headers || null, metaFrom: lines[0] };
  const best = allFormats.filter(f => f.url).sort((a,b)=> (b.tbr||0)-(a.tbr||0))[0];
  if (best) return { url: best.url, type: best.ext || "mp4", headers: lines[0]?.http_headers || best.http_headers || null, metaFrom: lines[0] };
  const single = lines.find(j => j.url);
  if (single) return { url: single.url, type: single.ext || "unknown", headers: single.http_headers || null, metaFrom: single };
  return null;
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  lastActivityAt = Date.now(); // mark any incoming request
  const started = Date.now();
  const selfOrigin = getSelfOrigin(req);
  const u = new URL(req.url, `${selfOrigin}`);
  cors(res);

  // Minimal access log
  console.log(`[REQ] ${req.method} ${u.pathname}${u.search || ""}`);

  // Readiness probe (required by Apify Standby)
  if (req.headers["x-apify-container-server-readiness-probe"]) {
    res.writeHead(200, { "Content-Type": "text/plain" }).end("OK");
    return;
  }

  if (req.method === "OPTIONS") { res.writeHead(204).end(); return; }

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
      req.on("data", d => body += d);
      req.on("end", async () => {
        try {
          const { url: pageUrl } = JSON.parse(body || "{}");
          if (!pageUrl) { res.writeHead(400).end('{"ok":false,"error":"Missing url"}'); return; }

          const lines = await ytdlpJson(pageUrl);
          const best = pickBest(lines);
          if (!best) { res.writeHead(404).end(JSON.stringify({ ok:false, error:"No playable URL" })); return; }

          const upstreamHeaders = {};
          if (best.headers?.["User-Agent"]) upstreamHeaders["User-Agent"] = best.headers["User-Agent"];
          upstreamHeaders["Referer"] = best.headers?.["Referer"] || new URL(pageUrl).origin;

          const expiresAt = nowSec() + TOKEN_TTL_SEC;
          const token = signToken({ u: best.url, exp: expiresAt, h: upstreamHeaders });
          const proxyUrl = `${selfOrigin}/proxy?token=${encodeURIComponent(token)}`;

          const metaFrom = best.metaFrom || {};
          const meta = {
            title: metaFrom.title,
            duration: metaFrom.duration,
            width: metaFrom.width || metaFrom.width_height?.[0],
            height: metaFrom.height || metaFrom.width_height?.[1],
            extractor: metaFrom.extractor,
            webpage_url: metaFrom.webpage_url
          };

          res.writeHead(200, { "Content-Type":"application/json" })
            .end(JSON.stringify({ ok:true, type: best.type, proxyUrl, expiresAt, meta }));

        } catch (e) {
          console.error("extract error:", e);
          res.writeHead(502, { "Content-Type":"application/json" })
            .end(JSON.stringify({ ok:false, error:String(e) }));
        } finally {
          console.log(`[END] /extract in ${Date.now()-started}ms`);
        }
      });
      return;
    }

    // GET /sign?u=...
    if (req.method === "GET" && u.pathname === "/sign") {
      const direct = u.searchParams.get("u");
      if (!direct) { res.writeHead(400).end('{"ok":false,"error":"Missing u"}'); return; }
      let directUrl;
      try { directUrl = new URL(direct).toString(); } catch { res.writeHead(400).end('{"ok":false,"error":"Bad URL"}'); return; }
      const expiresAt = nowSec() + TOKEN_TTL_SEC;
      const token = signToken({ u: directUrl, exp: expiresAt, h: null });
      const proxyUrl = `${selfOrigin}/proxy?token=${encodeURIComponent(token)}`;
      res.writeHead(200, { "Content-Type":"application/json" })
        .end(JSON.stringify({ ok:true, proxyUrl, expiresAt }));
      console.log(`[END] /sign in ${Date.now()-started}ms`);
      return;
    }

    // GET /proxy?token=...
    if (req.method === "GET" && u.pathname === "/proxy") {
      const token = u.searchParams.get("token");
      if (!token) { res.writeHead(400).end("Missing token"); return; }

      let payload;
      try { payload = verifyToken(token); } catch (e) { res.writeHead(403).end("Invalid token"); return; }

      const upstreamUrl = new URL(payload.u);
      const range = req.headers.range;
      const ua = req.headers["user-agent"] || UA_DEFAULT;

      const h = { "User-Agent": ua };
      if (payload.h?.["Referer"]) h["Referer"] = payload.h["Referer"];
      if (payload.h?.["Cookie"])  h["Cookie"]  = payload.h["Cookie"];

      // Timeout for upstream
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

      let upstream;
      try {
        upstream = await fetch(upstreamUrl.toString(), {
          method: "GET",
          redirect: "follow",
          headers: { ...(range ? { Range: range } : {}), ...h },
          signal: controller.signal
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
      if (looksLikeM3U8(upstreamUrl, ct)) {
        const manifest = await upstream.text();
        const rewritten = rewriteM3U8(manifest, upstreamUrl, selfOrigin, TOKEN_TTL_SEC, payload.h || null);
        res.writeHead(200, { "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8" }).end(rewritten);
        console.log(`[END] /proxy (m3u8) in ${Date.now()-started}ms`);
        return;
      }

      if (upstream.headers.get("accept-ranges")) res.setHeader("Accept-Ranges", upstream.headers.get("accept-ranges"));
      if (upstream.headers.get("content-range")) res.setHeader("Content-Range", upstream.headers.get("content-range"));
      if (upstream.headers.get("content-length")) res.setHeader("Content-Length", upstream.headers.get("content-length"));
      if (upstream.headers.get("content-type")) res.setHeader("Content-Type", upstream.headers.get("content-type"));
      if (!res.getHeader("Cache-Control")) res.setHeader("Cache-Control", "no-store");

      res.writeHead(upstream.status);

      try {
        if (upstream.body) {
          const nodeReadable = Readable.fromWeb(upstream.body);
          // keep the process "active" while streaming
          nodeReadable.on("data", () => { lastActivityAt = Date.now(); });
          nodeReadable.on("error", () => { try { res.end(); } catch(_){} });
          nodeReadable.on("end",   () => { /* done */ });
          nodeReadable.pipe(res);
        } else {
          res.end();
        }
      } catch (e) {
        console.error("stream pipe error:", e);
        try { res.end(); } catch(_) {}
      } finally {
        console.log(`[END] /proxy passthrough in ${Date.now()-started}ms`);
      }
      return;
    }

    // 404
    res.writeHead(404, { "Content-Type":"text/plain" }).end("Not found");
  } catch (e) {
    console.error("server error:", e);
    try { res.writeHead(500).end(String(e)); } catch(_) {}
  }
});

// tighten idle sockets a bit
server.keepAliveTimeout = 5000; // 5s
server.headersTimeout   = 8000; // 8s

server.listen(PORT, () => console.log(`resolver+proxy listening on :${PORT}`));

// graceful auto-exit watchdog
if (AUTO_EXIT_IDLE_MS > 0) {
  setInterval(() => {
    const idle = Date.now() - lastActivityAt;
    if (idle > AUTO_EXIT_IDLE_MS) {
      console.log(`[EXIT] idle ${idle}ms > ${AUTO_EXIT_IDLE_MS}ms, exiting`);
      setTimeout(() => process.exit(0), 200);
    }
  }, Math.min(AUTO_EXIT_IDLE_MS, 10000));
}
