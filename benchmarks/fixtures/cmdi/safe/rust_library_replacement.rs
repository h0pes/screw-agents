// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: Safe library replacement — Rust
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-78
// Agent: cmdi
// Pattern: Using Rust standard library and crates instead of shelling out to system commands

use axum::{extract::Query, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    data: serde_json::Value,
}

static UPLOAD_DIR: &str = "/var/app/uploads";

#[derive(Deserialize)]
struct FileParams {
    filename: String,
}

// SAFE: Using tokio::fs instead of shelling out to `cp` or `mv`
// No command injection possible — pure Rust I/O
async fn copy_file(Json(params): Json<FileParams>) -> Json<ApiResponse> {
    let source = PathBuf::from(UPLOAD_DIR).join(&params.filename);
    let dest = PathBuf::from(UPLOAD_DIR).join(format!("backup_{}", params.filename));

    if !source.starts_with(UPLOAD_DIR) {
        return Json(ApiResponse {
            success: false,
            data: serde_json::json!({"error": "path traversal"}),
        });
    }

    match fs::copy(&source, &dest).await {
        Ok(bytes) => Json(ApiResponse {
            success: true,
            data: serde_json::json!({"bytes_copied": bytes}),
        }),
        Err(e) => Json(ApiResponse {
            success: false,
            data: serde_json::json!({"error": e.to_string()}),
        }),
    }
}

// SAFE: Using sha2 crate instead of shelling out to `sha256sum`
// No process spawning at all
async fn checksum_file(Query(params): Query<FileParams>) -> Json<ApiResponse> {
    use sha2::{Sha256, Digest};

    let filepath = PathBuf::from(UPLOAD_DIR).join(&params.filename);
    if !filepath.starts_with(UPLOAD_DIR) {
        return Json(ApiResponse {
            success: false,
            data: serde_json::json!({"error": "path traversal"}),
        });
    }

    match fs::read(&filepath).await {
        Ok(contents) => {
            let mut hasher = Sha256::new();
            hasher.update(&contents);
            let hash = format!("{:x}", hasher.finalize());
            Json(ApiResponse {
                success: true,
                data: serde_json::json!({"checksum": hash}),
            })
        }
        Err(e) => Json(ApiResponse {
            success: false,
            data: serde_json::json!({"error": e.to_string()}),
        }),
    }
}

#[derive(Deserialize)]
struct FetchParams {
    url: String,
}

// SAFE: Using reqwest instead of shelling out to `curl` or `wget`
// No shell interpretation of the URL
async fn fetch_url(Json(params): Json<FetchParams>) -> Json<ApiResponse> {
    // URL validation — only allow http/https
    let url = match url::Url::parse(&params.url) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => u,
        _ => {
            return Json(ApiResponse {
                success: false,
                data: serde_json::json!({"error": "invalid URL, must be http or https"}),
            });
        }
    };

    match reqwest::get(url.as_str()).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Json(ApiResponse {
                success: true,
                data: serde_json::json!({"status": status, "length": body.len()}),
            })
        }
        Err(e) => Json(ApiResponse {
            success: false,
            data: serde_json::json!({"error": e.to_string()}),
        }),
    }
}

// SAFE: Using walkdir/tokio::fs instead of shelling out to `find` or `ls`
async fn list_files(Query(params): Query<FileParams>) -> Json<ApiResponse> {
    let dir = PathBuf::from(UPLOAD_DIR);
    let mut entries = Vec::new();

    if let Ok(mut read_dir) = fs::read_dir(&dir).await {
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                entries.push(serde_json::json!({
                    "name": entry.file_name().to_string_lossy(),
                    "size": metadata.len(),
                    "is_file": metadata.is_file(),
                }));
            }
        }
    }

    Json(ApiResponse {
        success: true,
        data: serde_json::json!({"files": entries}),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/copy", post(copy_file))
        .route("/api/checksum", get(checksum_file))
        .route("/api/fetch", post(fetch_url))
        .route("/api/files", get(list_files));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
