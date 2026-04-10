// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: Safe Command::new with .arg() chain — Rust
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-78
// Agent: cmdi
// Pattern: std::process::Command with separate .arg() calls, no shell, input validation

use axum::{extract::Query, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct PingParams {
    host: String,
}

#[derive(Serialize)]
struct CommandResult {
    success: bool,
    output: String,
}

static UPLOAD_DIR: &str = "/var/app/uploads";

// SAFE: Command::new("ping") with separate .arg() calls — no shell involved
// Each argument is a separate OS-level argv entry; semicolons/pipes are literal
async fn ping_handler(Query(params): Query<PingParams>) -> Json<CommandResult> {
    // Validate as IPv4 address
    if params.host.parse::<Ipv4Addr>().is_err() {
        return Json(CommandResult {
            success: false,
            output: "invalid IP address".to_string(),
        });
    }

    let output = Command::new("ping")
        .arg("-c").arg("3")
        .arg("-W").arg("5")
        .arg(&params.host)
        .output()
        .expect("failed to execute ping");

    Json(CommandResult {
        success: output.status.success(),
        output: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}

#[derive(Deserialize)]
struct ChecksumParams {
    filename: String,
}

// SAFE: Command with validated filename and -- separator
async fn checksum_handler(Query(params): Query<ChecksumParams>) -> Json<CommandResult> {
    let re = regex::Regex::new(r"^[\w\-]+\.[a-z]{1,5}$").unwrap();
    if !re.is_match(&params.filename) {
        return Json(CommandResult {
            success: false,
            output: "invalid filename".to_string(),
        });
    }

    let full_path = PathBuf::from(UPLOAD_DIR).join(&params.filename);
    // Path traversal check
    if !full_path.starts_with(UPLOAD_DIR) {
        return Json(CommandResult {
            success: false,
            output: "path traversal detected".to_string(),
        });
    }

    // SAFE: separate .arg() calls, -- prevents option injection
    let output = Command::new("sha256sum")
        .arg("--")
        .arg(&full_path)
        .output()
        .expect("failed to execute sha256sum");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let checksum = stdout.split_whitespace().next().unwrap_or("").to_string();

    Json(CommandResult {
        success: output.status.success(),
        output: checksum,
    })
}

#[derive(Deserialize)]
struct CompressRequest {
    filename: String,
}

// SAFE: Command with separate args and validated input
async fn compress_handler(Json(req): Json<CompressRequest>) -> Json<CommandResult> {
    let re = regex::Regex::new(r"^[\w\-]+\.[a-z]{1,5}$").unwrap();
    if !re.is_match(&req.filename) {
        return Json(CommandResult {
            success: false,
            output: "invalid filename".to_string(),
        });
    }

    let full_path = PathBuf::from(UPLOAD_DIR).join(&req.filename);
    if !full_path.starts_with(UPLOAD_DIR) {
        return Json(CommandResult {
            success: false,
            output: "path traversal detected".to_string(),
        });
    }

    let archive = format!("{}.tar.gz", full_path.file_stem().unwrap().to_string_lossy());

    // SAFE: no shell, each argument is a separate argv entry
    let output = Command::new("tar")
        .arg("-czf")
        .arg(Path::new(UPLOAD_DIR).join(&archive))
        .arg("-C")
        .arg(UPLOAD_DIR)
        .arg("--")
        .arg(&req.filename)
        .output()
        .expect("failed to execute tar");

    Json(CommandResult {
        success: output.status.success(),
        output: format!("archive: {}", archive),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/ping", get(ping_handler))
        .route("/api/checksum", get(checksum_handler))
        .route("/api/compress", post(compress_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
