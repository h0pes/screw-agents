// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-tera-safe-filter — Tera template with | safe filter on user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: Tera's | safe filter disables auto-escaping for user-controlled context variables

use axum::{
    extract::{Query, State},
    response::Html,
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tera::{Context, Tera};

struct AppState {
    tera: Tera,
}

#[derive(Deserialize)]
struct CommentParams {
    author: Option<String>,
    body: Option<String>,
}

// VULNERABLE: Template uses {{ body | safe }} which disables Tera's auto-escaping
// Tera auto-escapes by default, but the | safe filter overrides this for specific variables
// Attacker sends: ?body=<img src=x onerror=alert(document.cookie)>
//
// Template (comment.html):
//   <div class="comment">
//     <strong>{{ author }}</strong>           <!-- auto-escaped: safe -->
//     <div class="body">{{ body | safe }}</div>  <!-- VULNERABLE: | safe disables escaping -->
//   </div>
async fn render_comment(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CommentParams>,
) -> Html<String> {
    let mut context = Context::new();
    context.insert("author", &params.author.unwrap_or_else(|| "Anonymous".to_string()));
    // VULNERABLE: user input inserted into context, rendered with | safe in template
    context.insert("body", &params.body.unwrap_or_else(|| "No comment".to_string()));

    let rendered = state.tera.render("comment.html", &context)
        .unwrap_or_else(|e| format!("Error: {}", e));
    Html(rendered)
}

#[derive(Deserialize)]
struct AnnouncementForm {
    title: String,
    content: String,
}

// VULNERABLE: Admin announcement feature where content is rendered with | safe
// Even if only admins can post, stored XSS can target other admins or
// be exploited via CSRF to inject malicious content
//
// Template (announcement.html):
//   <article>
//     <h2>{{ title }}</h2>
//     <div class="announcement-body">{{ content | safe }}</div>
//   </article>
async fn post_announcement(
    State(state): State<Arc<AppState>>,
    Form(form): Form<AnnouncementForm>,
) -> Html<String> {
    let mut context = Context::new();
    context.insert("title", &form.title);
    // VULNERABLE: content rendered with | safe — allows arbitrary HTML/JS
    context.insert("content", &form.content);

    let rendered = state.tera.render("announcement.html", &context)
        .unwrap_or_else(|e| format!("Error: {}", e));
    Html(rendered)
}

// VULNERABLE: Tera one_off with autoescape disabled (third parameter = false)
// This disables escaping for ALL variables in the template
#[derive(Deserialize)]
struct PreviewParams {
    text: Option<String>,
}

async fn preview_handler(Query(params): Query<PreviewParams>) -> Html<String> {
    let text = params.text.unwrap_or_else(|| "Preview text".to_string());

    let mut context = Context::new();
    context.insert("text", &text);

    // VULNERABLE: autoescape=false (third parameter) disables all escaping
    let rendered = Tera::one_off("<p>{{ text }}</p>", &context, false)
        .unwrap_or_else(|e| format!("Error: {}", e));

    Html(rendered)
}

#[tokio::main]
async fn main() {
    let mut tera = Tera::new("templates/**/*.html").expect("Failed to load templates");

    let state = Arc::new(AppState { tera });

    let app = Router::new()
        .route("/comment", get(render_comment))
        .route("/announcement", post(post_announcement))
        .route("/preview", get(preview_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
