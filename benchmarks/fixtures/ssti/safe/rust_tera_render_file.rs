// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-tera-render-file — Tera render() with registered template and user data in context
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-1336
// Agent: ssti
// Pattern: Templates loaded from files at init, user input only flows into Tera Context as data

use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tera::{Context, Tera};

struct AppState {
    tera: Tera,
}

#[derive(Deserialize)]
struct ProfileParams {
    username: Option<String>,
    bio: Option<String>,
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<u32>,
}

#[derive(Serialize)]
struct SearchResult {
    title: String,
    snippet: String,
    url: String,
}

// SAFE: Template loaded from file ("templates/profile.html"), user input is context data
// Tera context variables are auto-escaped; user input cannot alter template structure
async fn profile_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ProfileParams>,
) -> axum::response::Html<String> {
    let username = params.username.unwrap_or_else(|| "Guest".to_string());
    let bio = params.bio.unwrap_or_else(|| "No bio provided".to_string());

    let mut context = Context::new();
    context.insert("username", &username);
    context.insert("bio", &bio);

    // SAFE: "profile.html" is a registered file template, user data is in context
    let rendered = state.tera.render("profile.html", &context)
        .unwrap_or_else(|e| format!("Error: {}", e));

    axum::response::Html(rendered)
}

// SAFE: Search results with file template
async fn search_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> axum::response::Html<String> {
    let query = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(1);

    let results: Vec<SearchResult> = (1..=10)
        .map(|i| SearchResult {
            title: format!("Result {}", i),
            snippet: format!("Match for '{}'...", query),
            url: format!("/item/{}", i),
        })
        .collect();

    let mut context = Context::new();
    context.insert("query", &query);
    context.insert("results", &results);
    context.insert("page", &page);
    context.insert("total_pages", &5u32);

    // SAFE: file-based template, all user input is context data
    let rendered = state.tera.render("search.html", &context)
        .unwrap_or_else(|e| format!("Error: {}", e));

    axum::response::Html(rendered)
}

#[tokio::main]
async fn main() {
    // Templates loaded from files at startup
    let tera = Tera::new("templates/**/*.html").expect("Failed to load templates");

    let state = Arc::new(AppState { tera });

    let app = Router::new()
        .route("/profile", get(profile_handler))
        .route("/search", get(search_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
