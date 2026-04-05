# Fixture: py-dbapi-fstring — DB-API f-string injection
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-89
# Pattern: f-string interpolation in cursor.execute()

import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: f-string interpolation in execute()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    return {"user": user}


@app.route("/search")
def search_users():
    query = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: %-formatting in execute()
    cursor.execute("SELECT * FROM users WHERE username LIKE '%%%s%%'" % query)
    users = cursor.fetchall()
    conn.close()
    return {"users": users}
