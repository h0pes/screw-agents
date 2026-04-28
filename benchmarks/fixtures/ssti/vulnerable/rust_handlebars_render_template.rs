// --- screw-agents synthetic Rust SSTI fixture (Phase 4 D-01) -------------
// Synthetic benchmark fixture: NOT a real CVE and NOT represented as one.
// Engine: Handlebars-rust
// Expected: TRUE POSITIVE
// CWE: CWE-1336
// Agent: ssti
// Misuse pattern: attacker-controlled template source passed to render_template()
// CWE rationale: user input controls server-side template syntax evaluated by the
// template engine instead of being bound only as data.
// -----------------------------------------------------------------------
// Fixture: rust-handlebars-render-template — Handlebars::render_template()
// with user input as template source.

use axum::{
    extract::Query,
    routing::{get, post},
    Json, Router,
};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
struct PreviewQuery {
    template: Option<String>,
    customer: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptRequest {
    body_template: String,
    order_id: String,
}

#[derive(Serialize)]
struct RenderResponse {
    html: String,
}

// VULNERABLE: the query parameter is used as the Handlebars template source.
// Attacker sends: ?template=<p>{{internal_note}}</p>
async fn preview(Query(query): Query<PreviewQuery>) -> Json<RenderResponse> {
    let registry = Handlebars::new();
    let template_src = query
        .template
        .unwrap_or_else(|| "<p>Hello {{customer}}</p>".to_string());
    let customer = query.customer.unwrap_or_else(|| "Guest".to_string());
    let data = json!({
        "customer": customer,
        "internal_note": "refund-risk-review",
        "support_token": "support-token-abc123"
    });

    let html = registry
        .render_template(&template_src, &data)
        .unwrap_or_else(|err| format!("template error: {err}"));

    Json(RenderResponse { html })
}

// VULNERABLE: user-controlled receipt body is rendered as a template source.
async fn receipt(Json(req): Json<ReceiptRequest>) -> Json<RenderResponse> {
    let registry = Handlebars::new();
    let data = json!({
        "order_id": req.order_id,
        "warehouse": "eu-west-private",
        "fulfillment_key": "fulfill_live_123"
    });

    let html = registry
        .render_template(&req.body_template, &data)
        .unwrap_or_else(|err| format!("template error: {err}"));

    Json(RenderResponse { html })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/preview", get(preview))
        .route("/receipt", post(receipt));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
