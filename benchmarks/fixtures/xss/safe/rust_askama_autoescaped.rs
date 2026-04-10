// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-askama-autoescaped — Askama template with default auto-escaping
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: Askama auto-escapes all variables in HTML templates by default; no |safe filter used

use askama::Template;
use axum::{
    extract::{Path, Query},
    routing::get,
    Router,
};
use serde::Deserialize;

// SAFE: Askama auto-escapes all variables in .html templates
// The template engine applies HTML entity encoding to all {{ var }} expressions
// unless explicitly bypassed with the |safe filter (which is NOT used here)

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileTemplate {
    username: String,
    bio: String,
    role: String,
}

#[derive(Deserialize)]
struct ProfileParams {
    username: Option<String>,
    bio: Option<String>,
    role: Option<String>,
}

// SAFE: user input fills struct fields, Askama auto-escapes them in the template
// Input "<script>alert(1)</script>" renders as "&lt;script&gt;alert(1)&lt;/script&gt;"
async fn profile_handler(Query(params): Query<ProfileParams>) -> ProfileTemplate {
    ProfileTemplate {
        username: params.username.unwrap_or_else(|| "Guest".to_string()),
        bio: params.bio.unwrap_or_else(|| "No bio provided".to_string()),
        role: params.role.unwrap_or_else(|| "member".to_string()),
    }
}

#[derive(Template)]
#[template(path = "search_results.html")]
struct SearchResultsTemplate {
    query: String,
    results: Vec<SearchResult>,
    page: u32,
}

struct SearchResult {
    title: String,
    snippet: String,
    url: String,
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<u32>,
}

// SAFE: all user input is auto-escaped by Askama's HTML escaper
async fn search_handler(Query(params): Query<SearchParams>) -> SearchResultsTemplate {
    let query = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(1);

    let results: Vec<SearchResult> = (1..=10)
        .map(|i| SearchResult {
            title: format!("Result {}", i),
            snippet: format!("Match for '{}'...", query),
            url: format!("/item/{}", i),
        })
        .collect();

    SearchResultsTemplate {
        query,
        results,
        page,
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    code: u16,
    message: String,
}

// SAFE: error message auto-escaped by Askama
async fn error_handler(Path(code): Path<u16>) -> ErrorTemplate {
    let message = match code {
        404 => "Page not found".to_string(),
        500 => "Internal server error".to_string(),
        _ => format!("Error {}", code),
    };

    ErrorTemplate { code, message }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/profile", get(profile_handler))
        .route("/search", get(search_handler))
        .route("/error/{code}", get(error_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
