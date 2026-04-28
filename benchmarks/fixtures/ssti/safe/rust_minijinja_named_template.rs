// --- screw-agents synthetic Rust SSTI fixture (Phase 4 D-01) -------------
// Synthetic benchmark fixture: NOT a real CVE and NOT represented as one.
// Engine: MiniJinja
// Expected: TRUE NEGATIVE
// CWE: CWE-1336
// Agent: ssti
// Safe pattern: server-controlled named template with user input bound only as
// render context data.
// -----------------------------------------------------------------------
// Fixture: rust-minijinja-named-template — get_template().render() with
// server-owned template source.

use actix_web::{web, App, HttpResponse, HttpServer};
use minijinja::{context, Environment};
use serde::Deserialize;

#[derive(Deserialize)]
struct NoticeQuery {
    title: Option<String>,
    message: Option<String>,
}

// SAFE: user input never becomes template source; it is only context data.
async fn notice(query: web::Query<NoticeQuery>) -> HttpResponse {
    let mut env = Environment::new();
    env.add_template("notice.html", "<h1>{{ title }}</h1><p>{{ message }}</p>")
        .expect("static template should compile");

    let template = env
        .get_template("notice.html")
        .expect("static template should exist");
    let rendered = template
        .render(context! {
            title => query.title.clone().unwrap_or_else(|| "Notice".to_string()),
            message => query.message.clone().unwrap_or_else(|| "No message".to_string()),
        })
        .unwrap_or_else(|err| format!("template error: {err}"));

    HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().route("/notice", web::get().to(notice)))
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
