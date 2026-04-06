# Fixture: Safe library replacement — Python
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-78
# Agent: cmdi
# Pattern: Using Python standard library (shutil, pathlib, hashlib, urllib) instead of
#          shelling out to system commands (cp, mv, sha256sum, curl, tar)

import hashlib
import shutil
import tarfile
from pathlib import Path
from urllib.parse import urlparse

import httpx
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = Path("/var/app/uploads")


# SAFE: Using shutil.copy2 instead of os.system("cp ...")
@app.route("/api/files/copy", methods=["POST"])
def copy_file():
    filename = request.json.get("filename")
    dest_name = request.json.get("dest", f"backup_{filename}")
    source = (UPLOAD_DIR / filename).resolve()
    dest = (UPLOAD_DIR / dest_name).resolve()

    # Path traversal check
    if not source.is_relative_to(UPLOAD_DIR) or not dest.is_relative_to(UPLOAD_DIR):
        return jsonify({"error": "path traversal"}), 400
    if not source.exists():
        return jsonify({"error": "file not found"}), 404

    shutil.copy2(source, dest)
    return jsonify({"status": "copied", "dest": str(dest)})


# SAFE: Using hashlib instead of subprocess.run(["sha256sum", ...])
@app.route("/api/files/checksum")
def file_checksum():
    filename = request.args.get("filename")
    filepath = (UPLOAD_DIR / filename).resolve()

    if not filepath.is_relative_to(UPLOAD_DIR) or not filepath.exists():
        return jsonify({"error": "invalid file"}), 400

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return jsonify({"checksum": sha256.hexdigest()})


# SAFE: Using tarfile module instead of os.system("tar ...")
@app.route("/api/files/compress", methods=["POST"])
def compress_file():
    filename = request.json.get("filename")
    filepath = (UPLOAD_DIR / filename).resolve()

    if not filepath.is_relative_to(UPLOAD_DIR) or not filepath.exists():
        return jsonify({"error": "invalid file"}), 400

    archive_path = UPLOAD_DIR / f"{filepath.stem}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(filepath, arcname=filename)

    return jsonify({"status": "compressed", "archive": str(archive_path)})


# SAFE: Using httpx instead of subprocess.run(["curl", ...])
@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    url = request.json.get("url")

    # Validate URL scheme
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "only http/https allowed"}), 400

    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True)
        return jsonify({
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "content_type": resp.headers.get("content-type"),
        })
    except httpx.RequestError as e:
        return jsonify({"error": str(e)}), 502


# SAFE: Using pathlib / shutil instead of os.system("rm ...") or os.system("mv ...")
@app.route("/api/files/move", methods=["POST"])
def move_file():
    filename = request.json.get("filename")
    dest_dir = request.json.get("dest_dir", "archive")
    source = (UPLOAD_DIR / filename).resolve()
    target_dir = (UPLOAD_DIR / dest_dir).resolve()

    if not source.is_relative_to(UPLOAD_DIR) or not target_dir.is_relative_to(UPLOAD_DIR):
        return jsonify({"error": "path traversal"}), 400

    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / source.name
    shutil.move(str(source), str(dest))
    return jsonify({"status": "moved", "dest": str(dest)})
