// Fixture: rust-tera-render-str — Tera::one_off() / render_str with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input passed as template source to Tera::one_off() or similar render-from-string

use axum::{
    extract::Query,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};

#[derive(Deserialize)]
struct WidgetParams {
    template: Option<String>,
    title: Option<String>,
}

#[derive(Serialize)]
struct RenderResponse {
    html: String,
}

// VULNERABLE: user-controlled template string passed to Tera::one_off()
// Tera templates can access all context data; information disclosure at minimum
// Attacker sends: ?template={{ secret_key }}
async fn render_widget(Query(params): Query<WidgetParams>) -> Json<RenderResponse> {
    let template_src = params
        .template
        .unwrap_or_else(|| "<p>{{ title }}</p>".to_string());
    let title = params.title.unwrap_or_else(|| "Widget".to_string());

    let mut context = Context::new();
    context.insert("title", &title);
    context.insert("secret_key", &"sk-prod-abc123xyz");
    context.insert("db_url", &"postgres://admin:password@db.internal/prod");

    // VULNERABLE: user-controlled template_src is the template source
    let html = Tera::one_off(&template_src, &context, true).unwrap_or_else(|e| {
        format!("<p>Error: {}</p>", e)
    });

    Json(RenderResponse { html })
}

#[derive(Deserialize)]
struct EmailPreviewRequest {
    body_template: String,
    recipient: String,
    subject: String,
}

// VULNERABLE: email body template from JSON request rendered as Tera template
async fn email_preview(Json(req): Json<EmailPreviewRequest>) -> Json<RenderResponse> {
    let full_template = format!(
        "<html><body><h2>{}</h2><p>Dear {},</p>{}<p>Regards</p></body></html>",
        req.subject, req.recipient, req.body_template
    );

    let mut context = Context::new();
    context.insert("recipient", &req.recipient);
    context.insert("subject", &req.subject);
    context.insert("internal_api_token", &"Bearer eyJhbGciOi...");

    // VULNERABLE: body_template from user is embedded in the template source
    let html = Tera::one_off(&full_template, &context, true)
        .unwrap_or_else(|e| format!("Error: {}", e));

    Json(RenderResponse { html })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/widget", get(render_widget))
        .route("/api/email-preview", post(email_preview));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
