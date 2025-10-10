import express from "express";
import morgan from "morgan";

const app = express();
const PORT = process.env.PORT || 8080;

const CORS_ALLOW = process.env.CORS_ALLOW || "*";

// Basic CORS for every response
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", CORS_ALLOW);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,Range"
  );
  res.setHeader(
    "Access-Control-Expose-Headers",
    "Content-Length,Content-Range,Accept-Ranges,Content-Type"
  );
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

// Apify readiness probe hits "/" with this header
app.get("/", (req, res) => {
  if (req.headers["x-apify-container-server-readiness-probe"]) {
    res.status(200).send("ready");
    return;
  }
  res.status(200).json({ ok: true, service: "apify-yt-resolver" });
});

// Simple health endpoint
app.get("/_health", (_req, res) => res.status(200).json({ ok: true }));

// Stubs we will implement next steps
app.post("/extract", (_req, res) =>
  res.status(501).json({ error: "Not implemented yet" })
);
app.get("/sign", (_req, res) =>
  res.status(501).json({ error: "Not implemented yet" })
);
app.get("/proxy", (_req, res) =>
  res.status(501).json({ error: "Not implemented yet" })
);

app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
