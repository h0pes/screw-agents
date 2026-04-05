# Fixture: any-second-order — Second-order SQL injection
# Expected: TRUE POSITIVE (context required)
# CWE: CWE-89
# Pattern: Data stored safely, retrieved and used unsafely in a later query
# Real CVEs: CVE-2024-45378, CVE-2020-35700, CVE-2024-0685

import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


# STEP 1: Safe storage — parameterized INSERT
@app.route("/profile", methods=["POST"])
def create_profile():
    username = request.form["username"]
    bio = request.form["bio"]  # Attacker sets bio to: '; DROP TABLE users; --
    conn = get_db()
    cursor = conn.cursor()
    # This INSERT is safe — parameterized
    cursor.execute(
        "INSERT INTO profiles (username, bio) VALUES (?, ?)",
        (username, bio),
    )
    conn.commit()
    conn.close()
    return {"status": "created"}


# STEP 2: Later, in a DIFFERENT code path — VULNERABLE retrieval + use
@app.route("/report/<username>")
def generate_report(username):
    conn = get_db()
    cursor = conn.cursor()
    # Safe retrieval
    cursor.execute("SELECT bio FROM profiles WHERE username = ?", (username,))
    stored_bio = cursor.fetchone()[0]

    # VULNERABLE: Stored value used in dynamic SQL without parameterization
    # The bio was stored safely but is now treated as trusted data
    cursor.execute(
        f"INSERT INTO reports (content) VALUES ('{stored_bio}')"
    )
    conn.commit()
    conn.close()
    return {"status": "report generated"}


# Another second-order pattern: user-configurable sort preference
@app.route("/settings", methods=["POST"])
def save_sort_preference():
    sort_col = request.form["sort_column"]  # Attacker sets to: name; DROP TABLE users--
    conn = get_db()
    cursor = conn.cursor()
    # Safe storage
    cursor.execute(
        "UPDATE user_settings SET sort_column = ? WHERE user_id = ?",
        (sort_col, request.form["user_id"]),
    )
    conn.commit()
    conn.close()
    return {"status": "saved"}


@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id")
    conn = get_db()
    cursor = conn.cursor()
    # Retrieve stored preference
    cursor.execute(
        "SELECT sort_column FROM user_settings WHERE user_id = ?", (user_id,)
    )
    sort_col = cursor.fetchone()[0]

    # VULNERABLE: Stored sort preference used in ORDER BY without validation
    cursor.execute(f"SELECT * FROM items ORDER BY {sort_col}")
    items = cursor.fetchall()
    conn.close()
    return {"items": items}
