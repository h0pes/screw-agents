// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 4.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 4 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-axum-sh-c-format — Command::new("sh").arg("-c").arg(format!(...))
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-78
// Agent: cmdi
// Pattern: User input interpolated via format!() into shell -c argument

use axum::{extract::Query, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Deserialize)]
struct PingParams {
    host: String,
    count: Option<u32>,
}

#[derive(Serialize)]
struct CommandResult {
    stdout: String,
    stderr: String,
    success: bool,
}

// VULNERABLE: format!() interpolates user-controlled host into shell command
// Attacker sends: ?host=127.0.0.1;+id
async fn ping_handler(Query(params): Query<PingParams>) -> Json<CommandResult> {
    let count = params.count.unwrap_or(4);
    let cmd = format!("ping -c {} {}", count, params.host);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("failed to execute");

    Json(CommandResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
    })
}

#[derive(Deserialize)]
struct CertParams {
    domain: String,
}

// VULNERABLE: user-controlled domain in openssl command via shell
// Attacker sends: ?domain=example.com;+cat+/etc/shadow
async fn check_cert_handler(Query(params): Query<CertParams>) -> Json<CommandResult> {
    let cmd = format!(
        "echo | openssl s_client -servername {} -connect {}:443 2>/dev/null | openssl x509 -noout -dates",
        params.domain, params.domain
    );
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("failed to execute");

    Json(CommandResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
    })
}

#[derive(Deserialize)]
struct GrepParams {
    pattern: String,
    log_file: Option<String>,
}

// VULNERABLE: user-controlled pattern and filename in grep via shell
// Attacker sends: ?pattern=error&log_file=app.log;+rm+-rf+/tmp/*
async fn search_logs_handler(Query(params): Query<GrepParams>) -> Json<CommandResult> {
    let log_file = params.log_file.unwrap_or_else(|| "app.log".to_string());
    let cmd = format!("grep -i '{}' /var/log/{}", params.pattern, log_file);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("failed to execute");

    Json(CommandResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/ping", get(ping_handler))
        .route("/api/cert", get(check_cert_handler))
        .route("/api/logs/search", get(search_logs_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
