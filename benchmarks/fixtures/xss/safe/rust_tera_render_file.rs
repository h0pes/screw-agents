// Fixture: rust-tera-render-file — Tera render() with registered file template and user data in context
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: Templates loaded from files at init, user input flows only into Context as data (auto-escaped)

use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Router,
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

// SAFE: Tera render() with file-based template and auto-escaping (default: on)
// User input is inserted as Context data, not as template source
// Tera auto-escapes all {{ variable }} expressions in HTML templates by default
async fn profile_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ProfileParams>,
) -> Html<String> {
    let mut context = Context::new();
    context.insert("username", &params.username.unwrap_or_else(|| "Guest".to_string()));
    context.insert("bio", &params.bio.unwrap_or_else(|| "No bio".to_string()));

    // SAFE: "profile.html" is a registered file template
    // User data in context is auto-escaped — no | safe filter used in template
    let rendered = state.tera.render("profile.html", &context)
        .unwrap_or_else(|e| format!("Error: {}", e));

    Html(rendered)
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
}

// SAFE: search query is context data, auto-escaped in the template
async fn search_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Html<String> {
    let query = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(1);

    let results: Vec<SearchResult> = (1..=10)
        .map(|i| SearchResult {
            title: format!("Result {}", i),
            snippet: format!("Match for '{}'...", query),
        })
        .collect();

    let mut context = Context::new();
    context.insert("query", &query);
    context.insert("results", &results);
    context.insert("page", &page);

    // SAFE: file template with auto-escaping — user data cannot inject HTML
    let rendered = state.tera.render("search.html", &context)
        .unwrap_or_else(|e| format!("Error: {}", e));

    Html(rendered)
}

// SAFE: Tera one_off with autoescape=true (third parameter)
// Even with inline template strings, auto-escaping protects against XSS
// when user data is in the context (not the template source)
async fn greeting_handler(Query(params): Query<ProfileParams>) -> Html<String> {
    let name = params.username.unwrap_or_else(|| "World".to_string());

    let mut context = Context::new();
    context.insert("name", &name);

    // SAFE: autoescape=true (third parameter) ensures HTML encoding
    let rendered = Tera::one_off("<h1>Hello, {{ name }}!</h1>", &context, true)
        .unwrap_or_else(|e| format!("Error: {}", e));

    Html(rendered)
}

#[tokio::main]
async fn main() {
    // Templates loaded from files at startup — developer-controlled source
    let tera = Tera::new("templates/**/*.html").expect("Failed to load templates");

    let state = Arc::new(AppState { tera });

    let app = Router::new()
        .route("/profile", get(profile_handler))
        .route("/search", get(search_handler))
        .route("/greeting", get(greeting_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
