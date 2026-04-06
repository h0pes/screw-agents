// Fixture: rust-actix-raw-response — Actix-web HttpResponse::Ok().body(format!(...)) with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: User input interpolated into HTML string via HttpResponse body — no template engine escaping

use actix_web::{web, App, HttpResponse, HttpServer};
use serde::Deserialize;

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    lang: Option<String>,
}

// VULNERABLE: format!() interpolates user input into HTML set as HttpResponse body
// HttpResponse::Ok().content_type("text/html") with format!() is the actix-web XSS antipattern
// Attacker sends: GET /search?q=<script>alert(document.cookie)</script>
async fn search_handler(query: web::Query<SearchQuery>) -> HttpResponse {
    let q = query.q.as_deref().unwrap_or("");
    let lang = query.lang.as_deref().unwrap_or("en");

    // VULNERABLE: user-controlled query string directly in format!() HTML
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            r#"<!DOCTYPE html>
<html lang="{}">
<body>
    <h1>Search</h1>
    <p>Results for: {}</p>
    <form>
        <input type="text" name="q" value="{}">
        <button type="submit">Search</button>
    </form>
</body>
</html>"#,
            lang, q, q
        ))
}

#[derive(Deserialize)]
struct ErrorParams {
    code: Option<u16>,
    message: Option<String>,
}

// VULNERABLE: error message reflected in HTML response without encoding
// Attacker sends: GET /error?message=<img src=x onerror=alert(1)>
async fn error_handler(params: web::Query<ErrorParams>) -> HttpResponse {
    let code = params.code.unwrap_or(404);
    let message = params.message.as_deref().unwrap_or("Page not found");

    // VULNERABLE: user-controlled message in HTML body
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "<html><body><h1>Error {}</h1><p>{}</p></body></html>",
            code, message
        ))
}

// VULNERABLE: path parameter reflected in greeting page
// Attacker sends: GET /greet/<svg/onload=alert(1)>
async fn greet_handler(path: web::Path<String>) -> HttpResponse {
    let name = path.into_inner();

    // VULNERABLE: path segment interpolated directly into HTML
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "<html><body>\
             <h1>Hello, {}!</h1>\
             <p>Welcome to our site, {}.</p>\
             </body></html>",
            name, name
        ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/search", web::get().to(search_handler))
            .route("/error", web::get().to(error_handler))
            .route("/greet/{name}", web::get().to(greet_handler))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
