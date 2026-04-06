// Fixture: Safe spawn() with array args — Node.js/TypeScript
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-78
// Agent: cmdi
// Pattern: child_process.spawn()/execFile() with array args, no shell option

import express from "express";
import { spawn, execFile } from "child_process";
import { promisify } from "util";
import net from "net";
import path from "path";

const execFileAsync = promisify(execFile);
const app = express();
app.use(express.json());

const UPLOAD_DIR = "/var/app/uploads";
const FILENAME_RE = /^[\w\-]+\.[a-z]{1,5}$/;

// SAFE: spawn() with array args, no shell — arguments cannot escape into shell
app.get("/api/ping", async (req, res) => {
  const host = req.query.host as string;

  // Validate IP address
  if (!net.isIP(host)) {
    return res.status(400).json({ error: "invalid IP address" });
  }

  const child = spawn("ping", ["-c", "3", "-W", "5", host]);
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (data: Buffer) => { stdout += data.toString(); });
  child.stderr.on("data", (data: Buffer) => { stderr += data.toString(); });
  child.on("close", (code: number) => {
    res.json({ reachable: code === 0, output: stdout });
  });
});

// SAFE: execFile() with separate args — no shell interpretation
app.get("/api/checksum", async (req, res) => {
  const filename = req.query.filename as string;

  if (!FILENAME_RE.test(filename)) {
    return res.status(400).json({ error: "invalid filename" });
  }

  const fullPath = path.join(UPLOAD_DIR, filename);
  // Path traversal check
  if (!fullPath.startsWith(UPLOAD_DIR + "/")) {
    return res.status(400).json({ error: "path traversal" });
  }

  try {
    // SAFE: execFile does not invoke a shell; -- prevents option injection
    const { stdout } = await execFileAsync("sha256sum", ["--", fullPath]);
    const checksum = stdout.split(/\s+/)[0];
    res.json({ checksum });
  } catch {
    res.status(500).json({ error: "checksum failed" });
  }
});

// SAFE: spawn with validated arguments and no shell option
app.post("/api/convert", async (req, res) => {
  const { filename, format } = req.body;

  if (!FILENAME_RE.test(filename)) {
    return res.status(400).json({ error: "invalid filename" });
  }
  const allowedFormats = new Set(["png", "jpg", "webp", "gif"]);
  if (!allowedFormats.has(format)) {
    return res.status(400).json({ error: "unsupported format" });
  }

  const inputPath = path.join(UPLOAD_DIR, filename);
  if (!inputPath.startsWith(UPLOAD_DIR + "/")) {
    return res.status(400).json({ error: "path traversal" });
  }
  const outputPath = path.join(UPLOAD_DIR, `converted_${path.parse(filename).name}.${format}`);

  // SAFE: spawn with array args, validated inputs, no shell
  const child = spawn("convert", [inputPath, outputPath]);
  child.on("close", (code: number) => {
    if (code === 0) {
      res.json({ status: "converted", output: outputPath });
    } else {
      res.status(500).json({ error: "conversion failed" });
    }
  });
});

app.listen(3000);
