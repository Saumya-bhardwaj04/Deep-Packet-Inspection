const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();

if (!process.env.JWT_SECRET && process.env.NODE_ENV !== "production") {
  console.warn("JWT_SECRET not set, using development fallback secret.");
}

const authRoutes = require("./routes/auth");
const dpiRoutes = require("./routes/dpi");
const historyRoutes = require("./routes/history");

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api/dpi", dpiRoutes);
app.use("/api/history", historyRoutes);

// Compatibility paths for existing frontend.
app.get("/api/health", (req, res) => {
  return res.json({ ok: true, status: "online", message: "Node DPI backend running" });
});
app.get("/api/apps", (req, res) => {
  req.url = "/apps";
  dpiRoutes.handle(req, res);
});
app.get("/api/rules", (req, res) => {
  req.url = "/rules";
  dpiRoutes.handle(req, res);
});
app.post("/api/rules", (req, res) => {
  req.url = "/rules";
  dpiRoutes.handle(req, res);
});
app.post("/api/process", (req, res) => {
  req.url = "/process";
  dpiRoutes.handle(req, res);
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  const status = Number(err?.status || err?.statusCode || 500);
  const message = err?.message || "Internal server error";
  return res.status(status).json({ error: message });
});

const port = Number(process.env.PORT || 8000);
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Working directory: ${process.cwd()}`);
  console.log(`Python script path: ${path.resolve(process.cwd(), process.env.PYTHON_SCRIPT_PATH || "../python_engine/cli.py")}`);
});
