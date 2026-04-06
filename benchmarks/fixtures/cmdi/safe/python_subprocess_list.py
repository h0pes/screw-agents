# Fixture: Safe subprocess with list args — Python
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-78
# Agent: cmdi
# Pattern: subprocess.run() with list arguments, shell=False (default), input validation

import subprocess
import re
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = Path("/var/app/uploads")
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json", ".xml", ".pdf"}


# SAFE: subprocess with list args, shell=False (default), validated filename
@app.route("/api/files/compress", methods=["POST"])
def compress_file():
    filename = request.json.get("filename")
    # Validate filename: alphanumeric, hyphens, underscores, one dot for extension
    if not re.match(r"^[\w\-]+\.[a-z]{1,5}$", filename):
        return jsonify({"error": "invalid filename"}), 400
    filepath = UPLOAD_DIR / filename
    if not filepath.exists() or not filepath.resolve().is_relative_to(UPLOAD_DIR):
        return jsonify({"error": "file not found"}), 404

    archive_path = UPLOAD_DIR / f"{filepath.stem}.tar.gz"
    result = subprocess.run(
        ["tar", "-czf", str(archive_path), "-C", str(UPLOAD_DIR), filename],
        capture_output=True,
        text=True,
    )
    return jsonify({"status": "compressed", "returncode": result.returncode})


# SAFE: subprocess with list args, validated IP address via regex
@app.route("/api/health/ping")
def ping_host():
    host = request.args.get("host", "")
    # Strict IP address validation — no hostnames, no special chars
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return jsonify({"error": "invalid IP address"}), 400
    result = subprocess.run(
        ["ping", "-c", "3", "-W", "5", host],
        capture_output=True,
        text=True,
    )
    return jsonify({"reachable": result.returncode == 0, "output": result.stdout})


# SAFE: subprocess with list args and -- separator to prevent option injection
@app.route("/api/files/checksum")
def file_checksum():
    filename = request.args.get("filename", "")
    if not re.match(r"^[\w\-]+\.[a-z]{1,5}$", filename):
        return jsonify({"error": "invalid filename"}), 400
    filepath = UPLOAD_DIR / filename
    if not filepath.resolve().is_relative_to(UPLOAD_DIR):
        return jsonify({"error": "path traversal"}), 400

    # -- separator ensures filename is never interpreted as an option
    result = subprocess.run(
        ["sha256sum", "--", str(filepath)],
        capture_output=True,
        text=True,
    )
    return jsonify({"checksum": result.stdout.split()[0] if result.returncode == 0 else None})
