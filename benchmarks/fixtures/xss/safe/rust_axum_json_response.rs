// Fixture: rust-axum-json-response — Axum returning JSON or using template engine (no raw HTML)
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: JSON responses have no XSS risk; template engines provide auto-escaping

use askama::Template;
use axum::{
    extract::{Path, Query},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    page: Option<u32>,
}

#[derive(Serialize)]
struct SearchResponse {
    query: String,
    results: Vec<SearchResultItem>,
    page: u32,
    total_pages: u32,
}

#[derive(Serialize)]
struct SearchResultItem {
    title: String,
    snippet: String,
    url: String,
}

// SAFE: JSON API response — axum::Json sets Content-Type: application/json
// JSON responses are not rendered as HTML by browsers, so XSS is not possible
// User input in JSON values is properly serialized (quotes escaped by serde_json)
async fn search_api(Query(params): Query<SearchParams>) -> Json<SearchResponse> {
    let query = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(1);

    let results: Vec<SearchResultItem> = (1..=10)
        .map(|i| SearchResultItem {
            title: format!("Result {}", i),
            snippet: format!("Match for '{}'...", query),
            url: format!("/item/{}", i),
        })
        .collect();

    Json(SearchResponse {
        query,
        results,
        page,
        total_pages: 5,
    })
}

#[derive(Serialize)]
struct ProfileResponse {
    username: String,
    bio: String,
    joined: String,
}

// SAFE: JSON response for user profile — no HTML rendering
async fn profile_api(Path(username): Path<String>) -> Json<ProfileResponse> {
    Json(ProfileResponse {
        username,
        bio: "A regular user".to_string(),
        joined: "2024-01-15".to_string(),
    })
}

// SAFE: Using Askama template engine for HTML responses
// Askama auto-escapes all template variables in .html templates
#[derive(Template)]
#[template(path = "profile.html")]
struct ProfilePage {
    username: String,
    bio: String,
}

// SAFE: Askama auto-escapes username and bio in the compiled template
async fn profile_page(Path(username): Path<String>) -> ProfilePage {
    ProfilePage {
        username,
        bio: "A regular user".to_string(),
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: u16,
}

// SAFE: Error responses as JSON — no HTML, no XSS
async fn error_handler(Path(code): Path<u16>) -> Json<ErrorResponse> {
    let error = match code {
        404 => "Not found".to_string(),
        500 => "Internal server error".to_string(),
        _ => format!("Error {}", code),
    };

    Json(ErrorResponse { error, code })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/search", get(search_api))
        .route("/api/user/{username}", get(profile_api))
        .route("/user/{username}", get(profile_page))
        .route("/api/error/{code}", get(error_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
