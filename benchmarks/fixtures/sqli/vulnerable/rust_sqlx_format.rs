// VULNERABLE: sqlx::query() with format!() — the Rust SQL injection footgun
// CWE-89: SQL Injection
// Agent: sqli
// Expected: TRUE POSITIVE

use axum::{extract::Query, response::Json, Extension};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct User {
    id: i32,
    name: String,
    email: String,
}

// VULNERABLE: format!() builds raw SQL from user input
async fn search_users(
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<PgPool>,
) -> Json<Vec<User>> {
    let search = params.get("q").cloned().unwrap_or_default();

    // BUG: format!() interpolates user input directly into SQL string
    let query = format!(
        "SELECT id, name, email FROM users WHERE name LIKE '%{}%'",
        search
    );

    let users = sqlx::query_as::<_, User>(&query)
        .fetch_all(&*pool)
        .await
        .unwrap_or_default();

    Json(users)
}

// VULNERABLE: format!() in diesel::sql_query
fn find_by_email(conn: &mut diesel::PgConnection, email: &str) -> Vec<User> {
    use diesel::RunQueryDsl;

    // BUG: format!() with user-controlled email
    diesel::sql_query(format!(
        "SELECT id, name, email FROM users WHERE email = '{}'",
        email
    ))
    .load::<User>(conn)
    .unwrap_or_default()
}

// VULNERABLE: String building with push_str flowing to sqlx::query
async fn dynamic_search(
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<PgPool>,
) -> Json<Vec<User>> {
    let mut query = String::from("SELECT id, name, email FROM users WHERE 1=1");

    if let Some(name) = params.get("name") {
        // BUG: push_str with user input directly into SQL
        query.push_str(&format!(" AND name = '{}'", name));
    }

    if let Some(email) = params.get("email") {
        // BUG: same pattern with email
        query.push_str(&format!(" AND email = '{}'", email));
    }

    let users = sqlx::query_as::<_, User>(&query)
        .fetch_all(&*pool)
        .await
        .unwrap_or_default();

    Json(users)
}
