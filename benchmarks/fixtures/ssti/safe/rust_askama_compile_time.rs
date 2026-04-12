// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 4.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 4 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-askama-compile-time — Askama derive macro template (structurally immune)
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-1336
// Agent: ssti
// Pattern: Askama templates are compiled at build time from files; no runtime template parsing
//          User input can only flow as data into struct fields, never as template source

use askama::Template;
use axum::{
    extract::Query,
    routing::get,
    Router,
};
use serde::Deserialize;

// SAFE: Askama templates are compiled at build time from the file specified in the attribute
// The template source is baked into the binary; there is no runtime parsing API
// This is structurally immune to SSTI — there is no mechanism to inject template syntax

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

// SAFE: user input fills struct fields, which are auto-escaped in the compiled template
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
    total_pages: u32,
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

// SAFE: compile-time template, user input is struct field data
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
        total_pages: 5,
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    user_id: String,
    active_tab: String,
    post_count: u32,
    comment_count: u32,
}

#[derive(Deserialize)]
struct DashboardParams {
    user_id: Option<String>,
    tab: Option<String>,
}

// SAFE: structurally immune — no runtime template parsing exists in Askama
async fn dashboard_handler(Query(params): Query<DashboardParams>) -> DashboardTemplate {
    DashboardTemplate {
        user_id: params.user_id.unwrap_or_else(|| "anonymous".to_string()),
        active_tab: params.tab.unwrap_or_else(|| "overview".to_string()),
        post_count: 42,
        comment_count: 128,
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/profile", get(profile_handler))
        .route("/search", get(search_handler))
        .route("/dashboard", get(dashboard_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
