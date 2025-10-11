import express from "express";
import morgan from "morgan";
import crypto from "crypto";
import { spawn } from "child_process";
import { URL } from "url";

const app = express();
const PORT = process.env.PORT || 8080;
const CORS_ALLOW = process.env.CORS_ALLOW || "*";
const SIGN_SECRET = process.env.SIGN_SECRET || "dev-secret";
const TOKEN_TTL_SEC = Number(process.env.TOKEN_TTL_SEC || 300);

// --------- CORS ----------
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", CORS_ALLOW);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,Range");
  res.setHeader("Access-Control-Expose-Headers", "Content-Length,Content-Range,Accept-Ranges,Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

// --------- Health / readiness ----------
app.get("/", (req, res) => {
  if (req.headers["x-apify-container-server-readiness-probe"]) return res.status(200).send("ready");
  res.status(200).json({ ok: true, service: "apify-yt-resolver" });
});
app.get("/_health", (_req, res) => res.status(200).json({ ok: true }));

// --------- Helpers: base64url + HMAC token ----------
const b64u = (buf) =>
  Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

function signToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj));
  const sig = crypto.createHmac("sha256", SIGN_SECRET).update(payload).digest();
  return b64u(payload) + "." + b64u(sig);
}

function verifyToken(token) {
  const [p, s] = token.split(".");
  if (!p || !s) return null;
  const payload = Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const expected = crypto.createHmac("sha256", SIGN_SECRET).update(payload).digest();
  const sig = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (!crypto.timingSafeEqual(expected, sig)) return null;
  const obj = JSON.parse(payload.toString("utf8"));
  if (typeof obj.exp !== "number" || Date.now() > obj.exp) return null;
  return obj;
}

// --------- yt-dlp extract (CLI) ----------
function ytDlJson(url) {
  return new Promise((resolve, reject) => {
    const args = [
      "-j",
      "--no-warnings",
      "--no-call-home",
      "--geo-bypass",
      "-f", "bestvideo+bestaudio/best",
      url,
    ];
    const child = spawn("yt-dlp", args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (err += d.toString()));
    child.on("close", (code) => {
      if (code === 0 && out.trim()) {
        try {
          const lines = out.trim().split("\n");
          const last = lines[lines.length - 1];
          resolve(JSON.parse(last));
        } catch (e) {
          reject(new Error("Failed to parse yt-dlp JSON: " + e.message));
        }
      } else {
        reject(new Error(err || `yt-dlp exited with code ${code}`));
      }
    });
  });
}

// Pick a playable URL from yt-dlp info
function pickPlayable(info) {
  if (info.url) {
    const proto = (info.protocol || info.ext || "").toString().toLowerCase();
    return { url: info.url, kind: proto.includes("m3u8") ? "hls" : proto.includes("dash") ? "dash" : "file" };
  }
  if (Array.isArray(info.requested_formats)) {
    const prog = info.requested_formats.find(f => f.acodec && f.acodec !== "none" && f.vcodec && f.vcodec !== "none" && f.url);
    if (prog) return { url: prog.url, kind: "file" };
    const first = info.requested_formats.find(f => f.url);
    if (first) {
      const isHls = String(first.protocol || first.ext || "").includes("m3u8");
      return { url: first.url, kind: isHls ? "hls" : "file" };
    }
  }
  if (Array.isArray(info.formats)) {
    const progressiveMp4 = info.formats
      .filter(f => f.ext === "mp4" && f.acodec && f.acodec !== "none" && f.vcodec && f.vcodec !== "none" && f.url)
      .sort((a, b) => (b.height || 0) - (a.height || 0));
    if (progressiveMp4[0]) return { url: progressiveMp4[0].url, kind: "file" };
    const hlsFmt = info.formats.find(f => ("" + (f.protocol || f.ext)).includes("m3u8") && f.url);
    if (hlsFmt) return { url: hlsFmt.url, kind: "hls" };
    const any = info.formats.find(f => f.url);
    if (any) return { url: any.url, kind: "file" };
  }
  throw new Error("No playable URL found in yt-dlp info");
}

// --------- /extract ----------
app.post("/extract", async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: "Missing 'url' in body" });
    try { new URL(url); } catch { return res.status(400).json({ error: "Invalid URL" }); }

    const info = await ytDlJson(url);
    const playable = pickPlayable(info);

    const exp = Date.now() + TOKEN_TTL_SEC * 1000;
    const token = signToken({
      u: playable.url,
      h: { "User-Agent": "Mozilla/5.0" }, // carry headers; extend later
      kind: playable.kind,                 // "file" | "hls" | "dash"
      exp
    });

    const base = process.env.ACTOR_STANDBY_URL || process.env.PUBLIC_URL || `http://localhost:${PORT}`;
    const proxyUrl = `${base.replace(/\/$/, "")}/proxy?token=${encodeURIComponent(token)}`;

    const meta = {
      type: playable.kind === "hls" ? "hls" : "file",
      title: info.title,
      duration: info.duration,
      ext: info.ext,
      source: info.extractor || info.extractor_key,
      thumbnail: info.thumbnail
    };

    res.json({ proxyUrl, expiresAt: new Date(exp).toISOString(), meta });
  } catch (err) {
    console.error("extract error:", err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// --------- /sign (utility) ----------
app.get("/sign", (req, res) => {
  const u = req.query.u;
  if (!u) return res.status(400).json({ error: "Missing 'u' query param" });
  try { new URL(u); } catch { return res.status(400).json({ error: "Invalid URL" }); }
  const exp = Date.now() + TOKEN_TTL_SEC * 1000;
  const token = signToken({ u, h: { "User-Agent": "Mozilla/5.0" }, kind: "file", exp });
  const base = process.env.ACTOR_STANDBY_URL || process.env.PUBLIC_URL || `http://localhost:${PORT}`;
  const proxyUrl = `${base.replace(/\/$/, "")}/proxy?token=${encodeURIComponent(token)}`;
  res.json({ proxyUrl, expiresAt: new Date(exp).toISOString() });
});

// --------- /proxy placeholder ----------
app.get("/proxy", (_req, res) => res.status(501).json({ error: "Not implemented yet" }));

app.listen(PORT, () => console.log(`Server listening on :${PORT}`));
