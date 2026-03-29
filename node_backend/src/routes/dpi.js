const express = require("express");
const multer = require("multer");
const { spawn } = require("child_process");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const PDFDocument = require("pdfkit");

const authMiddleware = require("../middleware/auth");
const { requireAdmin } = require("../middleware/roles");
const { upsertRules, getRules, addRun, getRunById } = require("../config/store");

const router = express.Router();

const ROOT_DIR = path.resolve(__dirname, "../../..");
const UPLOAD_DIR = path.resolve(__dirname, "../../uploads");
const OUTPUT_DIR = path.resolve(__dirname, "../../outputs");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const APPS = [
  "Unknown",
  "HTTP",
  "HTTPS",
  "DNS",
  "TLS",
  "QUIC",
  "Google",
  "Facebook",
  "YouTube",
  "Twitter/X",
  "Instagram",
  "Netflix",
  "Amazon",
  "Microsoft",
  "Apple",
  "WhatsApp",
  "Telegram",
  "TikTok",
  "Spotify",
  "Zoom",
  "Discord",
  "GitHub",
  "Cloudflare",
];

const emptyRules = {
  blocked_ips: [],
  blocked_apps: [],
  blocked_domains: [],
  blocked_ports: [],
};

const liveStreamState = {
  running: false,
  started_at: null,
  stopped_at: null,
  pid: null,
  interface: null,
  output_file: null,
  last_error: null,
  stats: {
    uptime_seconds: 0,
    total_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0,
    tcp_packets: 0,
    udp_packets: 0,
    drop_rate: 0,
    app_counts: {},
    block_reasons: {},
  },
  ticks: [],
  process: null,
  stdoutBuffer: "",
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}_${file.originalname}`),
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (!file.originalname.toLowerCase().endsWith(".pcap")) {
      return cb(new Error("Only .pcap files allowed"));
    }
    return cb(null, true);
  },
});

function singlePcapUpload(fieldName) {
  const middleware = upload.single(fieldName);
  return (req, res, next) => {
    middleware(req, res, (err) => {
      if (err) {
        return res.status(400).json({ error: err.message || "File upload failed" });
      }
      return next();
    });
  };
}

function resolveExistingInputPath(inputPath) {
  if (!inputPath) {
    return null;
  }

  if (path.isAbsolute(inputPath) && fs.existsSync(inputPath)) {
    return inputPath;
  }

  const candidates = [
    path.resolve(process.cwd(), inputPath),
    path.resolve(ROOT_DIR, inputPath),
  ];

  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function resolveOutputPath(outputPath) {
  if (!outputPath) {
    return path.join(OUTPUT_DIR, `output_${uuidv4()}.pcap`);
  }

  if (path.isAbsolute(outputPath)) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    return outputPath;
  }

  const resolved = path.resolve(process.cwd(), outputPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  return resolved;
}

function parsePythonResult(stdoutText) {
  const text = (stdoutText || "").trim();
  if (!text) {
    throw new Error("Python DPI script returned empty output");
  }

  const lines = text.split(/\r?\n/).filter(Boolean);
  const lastLine = lines[lines.length - 1];
  const parsed = JSON.parse(lastLine);

  if (parsed.stats) {
    return {
      total: parsed.stats.total_packets ?? 0,
      forwarded: parsed.stats.forwarded_packets ?? 0,
      dropped: parsed.stats.dropped_packets ?? 0,
      drop_rate: (parsed.stats.drop_rate ?? 0) * 100,
      top_apps: parsed.stats.app_counts || {},
      block_reasons: parsed.stats.block_reasons || {},
      input_file: parsed.input_file,
      output_file: parsed.output_file,
      raw_stats: parsed.stats,
    };
  }

  return {
    total: parsed.total ?? parsed.total_packets ?? 0,
    forwarded: parsed.forwarded ?? parsed.forwarded_packets ?? 0,
    dropped: parsed.dropped ?? parsed.dropped_packets ?? 0,
    drop_rate: parsed.drop_rate ?? 0,
    top_apps: parsed.top_apps ?? parsed.app_counts ?? {},
    block_reasons: parsed.block_reasons || {},
    input_file: parsed.input_file,
    output_file: parsed.output_file,
    raw_stats: parsed,
  };
}

function resolvePythonBin() {
  if (process.env.PYTHON_BIN) {
    return process.env.PYTHON_BIN;
  }

  const candidates = [
    path.resolve(process.cwd(), "../python_engine/.venv/Scripts/python.exe"),
    path.resolve(process.cwd(), "../python_engine/.venv/bin/python"),
  ];

  const found = candidates.find((candidate) => fs.existsSync(candidate));
  return found || "python";
}

function runPythonDPI(inputPath, outputPath, rules) {
  return new Promise((resolve, reject) => {
    const pythonBin = resolvePythonBin();
    const scriptPath = path.resolve(process.cwd(), process.env.PYTHON_SCRIPT_PATH || "../python_engine/cli.py");

    if (!fs.existsSync(scriptPath)) {
      reject(new Error(`Python script not found at ${scriptPath}`));
      return;
    }

    const args = [
      scriptPath,
      "--input",
      inputPath,
      "--output",
      outputPath,
      "--rules",
      JSON.stringify(rules || emptyRules),
      "--json",
    ];

    const python = spawn(pythonBin, args, {
      cwd: process.cwd(),
      env: process.env,
    });

    let stdout = "";
    let stderr = "";

    python.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    python.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    python.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`Python error: ${stderr || `Exited with code ${code}`}`));
        return;
      }

      try {
        resolve(parsePythonResult(stdout));
      } catch (error) {
        reject(error);
      }
    });
  });
}

function consumeLiveStreamLine(line) {
  if (!line) {
    return;
  }

  try {
    const msg = JSON.parse(line);
    if (msg.type === "error") {
      liveStreamState.last_error = msg.error || "Unknown live-stream error";
      return;
    }

    if (msg.type === "started") {
      liveStreamState.interface = msg.interface || liveStreamState.interface;
      liveStreamState.output_file = msg.output_file || liveStreamState.output_file;
    }

    if (msg.stats) {
      liveStreamState.stats = msg.stats;
      if (msg.type === "tick") {
        liveStreamState.ticks.push({
          ts: new Date().toISOString(),
          total_packets: msg.stats.total_packets || 0,
          dropped_packets: msg.stats.dropped_packets || 0,
          forwarded_packets: msg.stats.forwarded_packets || 0,
          drop_rate: msg.stats.drop_rate || 0,
        });
        if (liveStreamState.ticks.length > 120) {
          liveStreamState.ticks.shift();
        }
      }
    }

    if (msg.type === "stopped") {
      liveStreamState.running = false;
      liveStreamState.stopped_at = new Date().toISOString();
    }
  } catch (_error) {
    // Ignore non-JSON lines from Python worker.
  }
}

function startLiveStreamWorker({ interfaceName, outputPath, rules, intervalSeconds }) {
  const pythonBin = resolvePythonBin();
  const scriptPath = path.resolve(process.cwd(), process.env.PYTHON_STREAM_SCRIPT_PATH || "../python_engine/live_stream.py");

  if (!fs.existsSync(scriptPath)) {
    throw new Error(`Live stream script not found at ${scriptPath}`);
  }

  const args = [
    scriptPath,
    "--interface",
    interfaceName,
    "--output",
    outputPath,
    "--rules",
    JSON.stringify(rules || emptyRules),
    "--interval",
    String(intervalSeconds || 2),
    "--json",
  ];

  const proc = spawn(pythonBin, args, {
    cwd: process.cwd(),
    env: process.env,
  });

  liveStreamState.running = true;
  liveStreamState.started_at = new Date().toISOString();
  liveStreamState.stopped_at = null;
  liveStreamState.pid = proc.pid || null;
  liveStreamState.interface = interfaceName;
  liveStreamState.output_file = outputPath;
  liveStreamState.last_error = null;
  liveStreamState.process = proc;
  liveStreamState.stdoutBuffer = "";
  liveStreamState.ticks = [];
  liveStreamState.stats = {
    uptime_seconds: 0,
    total_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0,
    tcp_packets: 0,
    udp_packets: 0,
    drop_rate: 0,
    app_counts: {},
    block_reasons: {},
  };

  proc.stdout.on("data", (data) => {
    liveStreamState.stdoutBuffer += data.toString();
    const lines = liveStreamState.stdoutBuffer.split(/\r?\n/);
    liveStreamState.stdoutBuffer = lines.pop() || "";
    lines.forEach((line) => consumeLiveStreamLine(line.trim()));
  });

  proc.stderr.on("data", (data) => {
    const text = data.toString().trim();
    if (text) {
      liveStreamState.last_error = text;
    }
  });

  proc.on("close", () => {
    liveStreamState.running = false;
    liveStreamState.stopped_at = new Date().toISOString();
    liveStreamState.process = null;
    liveStreamState.pid = null;
  });
}

function checkLiveCaptureCapability() {
  return new Promise((resolve) => {
    const pythonBin = resolvePythonBin();
    const scriptPath = path.resolve(
      process.cwd(),
      process.env.PYTHON_CAPTURE_CHECK_SCRIPT_PATH || "../python_engine/check_capture.py"
    );

    if (!fs.existsSync(scriptPath)) {
      resolve({
        ok: false,
        reason: `Capture check script not found at ${scriptPath}`,
        suggestion: "Ensure python_engine/check_capture.py exists in deployment",
        interfaces: [],
      });
      return;
    }

    const proc = spawn(pythonBin, [scriptPath], {
      cwd: process.cwd(),
      env: process.env,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (d) => {
      stdout += d.toString();
    });

    proc.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    proc.on("close", () => {
      const raw = (stdout || "").trim();
      if (!raw) {
        resolve({
          ok: false,
          reason: stderr || "Empty capture capability response",
          suggestion: "Verify Python runtime and scapy installation",
          interfaces: [],
        });
        return;
      }

      try {
        const parsed = JSON.parse(raw.split(/\r?\n/).pop());
        resolve(parsed);
      } catch (_error) {
        resolve({
          ok: false,
          reason: "Invalid capture capability response",
          suggestion: "Check python_engine/check_capture.py output format",
          interfaces: [],
        });
      }
    });
  });
}

function stopLiveStreamWorker() {
  if (!liveStreamState.process || !liveStreamState.running) {
    return false;
  }

  try {
    liveStreamState.process.kill("SIGTERM");
  } catch (error) {
    liveStreamState.last_error = String(error.message || error);
  }

  return true;
}

router.post("/upload", authMiddleware, requireAdmin, singlePcapUpload("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  return res.json({
    message: "File uploaded successfully",
    filepath: req.file.path,
    filename: req.file.originalname,
    size: req.file.size,
  });
});

router.post("/analyze", authMiddleware, singlePcapUpload("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const inputPath = req.file.path;
  const outputFilename = `analysis_${uuidv4()}.pcap`;
  const outputPath = path.join(OUTPUT_DIR, outputFilename);

  try {
    const result = await runPythonDPI(inputPath, outputPath, emptyRules);

    await addRun({
      user_id: req.user.username,
      input_file: req.file.originalname,
      output_file: outputFilename,
      total_packets: result.total,
      forwarded: result.forwarded,
      dropped: result.dropped,
      drop_rate: result.drop_rate,
      top_apps: result.top_apps,
      block_reasons: result.block_reasons,
      run_type: "analysis",
    });

    return res.json({
      total: result.total,
      forwarded: result.forwarded,
      dropped: result.dropped,
      drop_rate: result.drop_rate,
      top_apps: result.top_apps,
      block_reasons: result.block_reasons,
      filename: req.file.originalname,
      output_filename: outputFilename,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/run", authMiddleware, requireAdmin, async (req, res) => {
  const { input_path, output_path, rules } = req.body;
  const resolvedInput = resolveExistingInputPath(input_path);

  if (!resolvedInput) {
    return res.status(400).json({ error: "Input file not found" });
  }

  const resolvedOutput = resolveOutputPath(output_path);

  try {
    const result = await runPythonDPI(resolvedInput, resolvedOutput, rules || emptyRules);

    await addRun({
      user_id: req.user.username,
      input_file: resolvedInput,
      output_file: resolvedOutput,
      total_packets: result.total,
      forwarded: result.forwarded,
      dropped: result.dropped,
      drop_rate: result.drop_rate,
      top_apps: result.top_apps,
      block_reasons: result.block_reasons,
      run_type: "full",
    });

    return res.json({
      total: result.total,
      forwarded: result.forwarded,
      dropped: result.dropped,
      drop_rate: result.drop_rate,
      top_apps: result.top_apps,
      block_reasons: result.block_reasons,
      input_file: resolvedInput,
      output_file: resolvedOutput,
      output_filename: path.basename(resolvedOutput),
      download_url: `/api/dpi/download/${path.basename(resolvedOutput)}`,
      stats: result.raw_stats,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.get("/download/:filename", authMiddleware, requireAdmin, (req, res) => {
  const filePath = path.join(OUTPUT_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "File not found" });
  }

  return res.download(filePath, req.params.filename);
});

router.get("/sample-pcap", authMiddleware, requireAdmin, (req, res) => {
  const samplePath = path.resolve(ROOT_DIR, "test_dpi.pcap");
  if (!fs.existsSync(samplePath)) {
    return res.status(404).json({ error: "Sample file not found" });
  }
  return res.download(samplePath, "sample_test_dpi.pcap");
});

router.get("/report/pdf/:runId", authMiddleware, async (req, res) => {
  try {
    const run = await getRunById(req.params.runId);

    if (!run) {
      return res.status(404).json({ error: "Run not found" });
    }

    if (req.user.role !== "admin" && run.user_id !== req.user.username) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const doc = new PDFDocument({ margin: 50 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=DPI_Report_${run.id}.pdf`);
    doc.pipe(res);

    doc.fontSize(24).font("Helvetica-Bold").text("DPI Analysis Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).font("Helvetica").text(`Generated: ${new Date().toLocaleString()}`, { align: "center" });
    doc.text(`User: ${run.user_id || "-"}`, { align: "center" });

    doc.moveDown();
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown();

    doc.fontSize(16).font("Helvetica-Bold").text("Run Summary");
    doc.moveDown(0.5);

    const stats = [
      ["Input File", path.basename(String(run.input_file || "-"))],
      ["Timestamp", run.timestamp ? new Date(run.timestamp).toLocaleString() : "-"],
      ["Run Type", run.run_type || "full"],
      ["Total Packets", run.total_packets ?? 0],
      ["Forwarded", run.forwarded ?? 0],
      ["Dropped", run.dropped ?? 0],
      ["Drop Rate", `${Number(run.drop_rate || 0).toFixed(2)}%`],
    ];

    stats.forEach(([label, value]) => {
      doc.fontSize(12).font("Helvetica-Bold").text(`${label}: `, { continued: true });
      doc.font("Helvetica").text(String(value));
    });

    doc.moveDown();
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown();

    doc.fontSize(16).font("Helvetica-Bold").text("Top Classified Apps");
    doc.moveDown(0.5);

    let apps = run.top_apps;
    if (typeof apps === "string") {
      try {
        apps = JSON.parse(apps);
      } catch (_error) {
        apps = {};
      }
    }

    const appEntries = Object.entries(apps || {});
    if (!appEntries.length) {
      doc.fontSize(12).font("Helvetica").text("No classified app data available.");
    } else {
      appEntries.forEach(([app, count]) => {
        doc.fontSize(12).font("Helvetica").text(`- ${app}: ${count} packets`);
      });
    }

    doc.moveDown(2);
    doc.fontSize(10).fillColor("grey").text("Generated by DPI Control Plane", { align: "center" });

    doc.end();
    return undefined;
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.get("/apps", (req, res) => {
  return res.json({ apps: APPS });
});

router.get("/rules", authMiddleware, requireAdmin, async (req, res) => {
  const username = req.user?.username || "public";
  try {
    const rules = await getRules(username);
    if (!rules) {
      return res.json(emptyRules);
    }

    return res.json({
      blocked_ips: rules.blocked_ips || [],
      blocked_apps: rules.blocked_apps || [],
      blocked_domains: rules.blocked_domains || [],
      blocked_ports: rules.blocked_ports || [],
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.post("/rules", authMiddleware, requireAdmin, async (req, res) => {
  const username = req.user?.username || "public";
  const payload = {
    blocked_ips: req.body.blocked_ips || [],
    blocked_apps: req.body.blocked_apps || [],
    blocked_domains: req.body.blocked_domains || [],
    blocked_ports: req.body.blocked_ports || [],
  };

  try {
    await upsertRules(username, payload);
    return res.json({ ok: true, rules: payload });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.post("/process", authMiddleware, requireAdmin, async (req, res) => {
  const { input_file, output_file } = req.body;
  const username = req.user?.username || "public";

  const inputPath = resolveExistingInputPath(input_file);
  if (!inputPath) {
    return res.status(404).json({ detail: "Input PCAP file not found" });
  }

  const outputPath = resolveOutputPath(output_file || `output_${uuidv4()}.pcap`);

  try {
    const persistedRules = await getRules(username);
    const normalizedRules = persistedRules
      ? {
          blocked_ips: persistedRules.blocked_ips || [],
          blocked_apps: persistedRules.blocked_apps || [],
          blocked_domains: persistedRules.blocked_domains || [],
          blocked_ports: persistedRules.blocked_ports || [],
        }
      : emptyRules;

    const result = await runPythonDPI(inputPath, outputPath, normalizedRules);

    await addRun({
      user_id: username,
      input_file: inputPath,
      output_file: outputPath,
      total_packets: result.total,
      forwarded: result.forwarded,
      dropped: result.dropped,
      drop_rate: result.drop_rate,
      top_apps: result.top_apps,
      block_reasons: result.block_reasons,
      run_type: "full",
    });

    return res.json({
      ok: true,
      input_file: inputPath,
      output_file: outputPath,
      stats: {
        total_packets: result.total,
        forwarded_packets: result.forwarded,
        dropped_packets: result.dropped,
        drop_rate: (result.drop_rate || 0) / 100,
        app_counts: result.top_apps,
        block_reasons: result.block_reasons,
      },
    });
  } catch (error) {
    return res.status(500).json({ detail: error.message });
  }
});

router.post("/stream/start", authMiddleware, requireAdmin, async (req, res) => {
  if (liveStreamState.running) {
    return res.status(409).json({ error: "Live stream already running" });
  }

  const capability = await checkLiveCaptureCapability();
  if (!capability.ok) {
    return res.status(412).json({
      error: "Live capture not available on this host",
      capability,
      fallback: "Use DPI Testing tab for file-based processing until capture dependency is installed",
    });
  }

  const interfaceName = String(req.body.interface || "").trim();
  if (!interfaceName) {
    return res.status(400).json({ error: "Network interface is required" });
  }

  const outputPath = resolveOutputPath(
    req.body.output_path || path.join("node_backend", "outputs", `live_stream_${Date.now()}.pcap`)
  );
  const intervalSeconds = Number(req.body.interval_seconds || 2);
  const username = req.user?.username || "public";

  try {
    const persistedRules = await getRules(username);
    const normalizedRules = persistedRules
      ? {
          blocked_ips: persistedRules.blocked_ips || [],
          blocked_apps: persistedRules.blocked_apps || [],
          blocked_domains: persistedRules.blocked_domains || [],
          blocked_ports: persistedRules.blocked_ports || [],
        }
      : emptyRules;

    const rules = req.body.rules || normalizedRules;
    startLiveStreamWorker({ interfaceName, outputPath, rules, intervalSeconds });

    return res.json({
      ok: true,
      running: liveStreamState.running,
      interface: liveStreamState.interface,
      output_file: liveStreamState.output_file,
      started_at: liveStreamState.started_at,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.get("/stream/capabilities", authMiddleware, requireAdmin, async (req, res) => {
  const capability = await checkLiveCaptureCapability();
  return res.json(capability);
});

router.post("/stream/stop", authMiddleware, requireAdmin, (req, res) => {
  const stopped = stopLiveStreamWorker();
  return res.json({
    ok: true,
    requested: stopped,
    running: liveStreamState.running,
  });
});

router.get("/stream/status", authMiddleware, requireAdmin, (req, res) => {
  return res.json({
    running: liveStreamState.running,
    started_at: liveStreamState.started_at,
    stopped_at: liveStreamState.stopped_at,
    pid: liveStreamState.pid,
    interface: liveStreamState.interface,
    output_file: liveStreamState.output_file,
    last_error: liveStreamState.last_error,
    stats: liveStreamState.stats,
    ticks: liveStreamState.ticks,
  });
});

module.exports = router;
