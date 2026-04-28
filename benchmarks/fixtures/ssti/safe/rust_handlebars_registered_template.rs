// --- screw-agents synthetic Rust SSTI fixture (Phase 4 D-01) -------------
// Synthetic benchmark fixture: NOT a real CVE and NOT represented as one.
// Engine: Handlebars-rust
// Expected: TRUE NEGATIVE
// CWE: CWE-1336
// Agent: ssti
// Safe pattern: server-controlled registered template with user input bound only
// as data.
// -----------------------------------------------------------------------
// Fixture: rust-handlebars-registered-template — render() of a registered
// server-owned template.

use axum::{
    extract::Query,
    routing::get,
    Json, Router,
};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
struct ProfileQuery {
    name: Option<String>,
    status: Option<String>,
}

#[derive(Serialize)]
struct RenderResponse {
    html: String,
}

// SAFE: the template source is a server-owned string registered at startup.
// User input is data only; template syntax inside name/status is not reparsed.
async fn profile(Query(query): Query<ProfileQuery>) -> Json<RenderResponse> {
    let mut registry = Handlebars::new();
    registry
        .register_template_string(
            "profile",
            "<section><h1>{{name}}</h1><p>{{status}}</p></section>",
        )
        .expect("static template should compile");

    let data = json!({
        "name": query.name.unwrap_or_else(|| "Guest".to_string()),
        "status": query.status.unwrap_or_else(|| "active".to_string())
    });

    let html = registry
        .render("profile", &data)
        .unwrap_or_else(|err| format!("template error: {err}"));

    Json(RenderResponse { html })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/profile", get(profile));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
