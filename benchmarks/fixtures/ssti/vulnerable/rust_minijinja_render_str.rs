// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// Fixture: rust-minijinja-render-str — minijinja env.render_str() with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input passed as template source to minijinja Environment::render_str()

use actix_web::{web, App, HttpResponse, HttpServer};
use minijinja::{context, Environment};
use serde::Deserialize;

#[derive(Deserialize)]
struct WidgetQuery {
    template: Option<String>,
    title: Option<String>,
}

// VULNERABLE: user-controlled template string rendered via minijinja
// minijinja supports filters, tests, and method calls on context objects
// Attacker sends: ?template={{ config | tojson }} or probes context for sensitive data
async fn render_widget(query: web::Query<WidgetQuery>) -> HttpResponse {
    let env = Environment::new();
    let template_src = query
        .template
        .clone()
        .unwrap_or_else(|| "<p>{{ title }}</p>".to_string());
    let title = query.title.clone().unwrap_or_else(|| "Widget".to_string());

    // VULNERABLE: user-controlled template_src is the template source
    let rendered = env
        .render_str(
            &template_src,
            context! {
                title => title,
                db_password => "hunter2",
                api_secret => "whsec_abc123",
            },
        )
        .unwrap_or_else(|e| format!("Error: {}", e));

    HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

#[derive(Deserialize)]
struct BannerRequest {
    markup: String,
    campaign: Option<String>,
}

// VULNERABLE: promotional banner markup from request body rendered as template
async fn render_banner(body: web::Json<BannerRequest>) -> HttpResponse {
    let env = Environment::new();
    let campaign = body
        .campaign
        .clone()
        .unwrap_or_else(|| "default".to_string());

    // VULNERABLE: body.markup is user-controlled and used as template source
    let rendered = env
        .render_str(
            &body.markup,
            context! {
                campaign => campaign,
                discount_code => "INTERNAL-50OFF",
                admin_email => "admin@company.internal",
            },
        )
        .unwrap_or_else(|e| format!("Error: {}", e));

    HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/api/widget", web::get().to(render_widget))
            .route("/api/banner", web::post().to(render_banner))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
