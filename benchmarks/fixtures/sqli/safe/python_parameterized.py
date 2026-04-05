# Fixture: Safe parameterized queries — Python
# Expected: TRUE NEGATIVE (must NOT be flagged)
# Pattern: Correct use of DB-API placeholders, Django ORM, SQLAlchemy bind params

import sqlite3
from flask import Flask, request
from django.contrib.auth.models import User
from sqlalchemy import text
from sqlalchemy.orm import Session

app = Flask(__name__)


# SAFE: DB-API parameterized query with tuple
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return {"user": user}


# SAFE: DB-API parameterized with named placeholders (psycopg2 style)
def search_users_psycopg(conn, query):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username LIKE %(pattern)s",
        {"pattern": f"%{query}%"},
    )
    return cursor.fetchall()


# SAFE: Django ORM filter — auto-parameterized
def search_users_django(request):
    query = request.GET.get("q")
    users = User.objects.filter(username__icontains=query)
    return list(users.values("username", "email"))


# SAFE: Django raw with parameterized placeholders
def raw_search_django(request):
    query = request.GET.get("q")
    users = User.objects.raw(
        "SELECT * FROM auth_user WHERE username LIKE %s",
        ["%" + query + "%"],
    )
    return list(users)


# SAFE: SQLAlchemy text() with bind parameters
def get_user_sqlalchemy(session: Session, user_id: str):
    result = session.execute(
        text("SELECT * FROM users WHERE id = :id"),
        {"id": user_id},
    )
    return result.fetchone()


# SAFE: String concatenation of compile-time constants only
def build_constant_query():
    table = "users"
    columns = "id, name, email"
    query = "SELECT " + columns + " FROM " + table + " WHERE active = 1"
    return query


# SAFE: Allowlisted ORDER BY
def sorted_users(request):
    ALLOWED_SORT = {"name": "user_name", "date": "created_at", "email": "email"}
    sort_col = ALLOWED_SORT.get(request.args.get("sort"), "user_name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # f-string is safe because sort_col is server-controlled (from allowlist)
    cursor.execute(f"SELECT * FROM users ORDER BY {sort_col}")
    return cursor.fetchall()
