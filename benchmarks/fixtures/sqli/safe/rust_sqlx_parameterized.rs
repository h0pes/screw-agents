// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 4.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 4 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
// SAFE: Rust sqlx with parameterized queries and compile-time checked macros
// CWE-89: SQL Injection
// Agent: sqli
// Expected: TRUE NEGATIVE (no findings)

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

// SAFE: sqlx::query!() macro — compile-time checked, always parameterized
async fn get_user_by_id(
    axum::extract::Path(user_id): axum::extract::Path<i32>,
    Extension(pool): Extension<PgPool>,
) -> Json<Option<User>> {
    let user = sqlx::query_as!(
        User,
        r#"SELECT id, name, email FROM users WHERE id = $1"#,
        user_id
    )
    .fetch_optional(&*pool)
    .await
    .unwrap();

    Json(user)
}

// SAFE: sqlx::query() function with .bind() — runtime parameterized
async fn search_users(
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<PgPool>,
) -> Json<Vec<User>> {
    let search = params.get("q").cloned().unwrap_or_default();

    let users = sqlx::query_as::<_, User>(
        "SELECT id, name, email FROM users WHERE name LIKE '%' || $1 || '%'"
    )
    .bind(&search)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    Json(users)
}

// SAFE: sqlx::QueryBuilder for dynamic queries — still parameterized
async fn dynamic_search(
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<PgPool>,
) -> Json<Vec<User>> {
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT id, name, email FROM users WHERE 1=1"
    );

    if let Some(name) = params.get("name") {
        qb.push(" AND name = ");
        qb.push_bind(name); // Parameterized, safe
    }

    if let Some(email) = params.get("email") {
        qb.push(" AND email = ");
        qb.push_bind(email); // Parameterized, safe
    }

    let users = qb
        .build_query_as::<User>()
        .fetch_all(&*pool)
        .await
        .unwrap_or_default();

    Json(users)
}

// SAFE: Diesel query DSL — type-safe, auto-parameterized
fn find_active_users(conn: &mut diesel::PgConnection) -> Vec<User> {
    use diesel::prelude::*;
    // users::table.filter(...) generates parameterized SQL
    // This is safe by construction — no raw SQL involved
    users::table
        .filter(users::active.eq(true))
        .order(users::name.asc())
        .load::<User>(conn)
        .unwrap_or_default()
}

// SAFE: SeaORM entity query — auto-parameterized
async fn find_user_seaorm(
    db: &sea_orm::DatabaseConnection,
    name: &str,
) -> Option<user::Model> {
    use sea_orm::*;
    User::find()
        .filter(user::Column::Name.eq(name))
        .one(db)
        .await
        .unwrap()
}

// SAFE: rusqlite with params! macro
fn find_user_rusqlite(conn: &rusqlite::Connection, name: &str) -> Option<User> {
    conn.query_row(
        "SELECT id, name, email FROM users WHERE name = ?1",
        rusqlite::params![name],
        |row| {
            Ok(User {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
            })
        },
    )
    .ok()
}
