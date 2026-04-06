# Fixture: py-flask-render-template — render_template() with user data in context only
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-1336
# Agent: ssti
# Pattern: Template loaded from file, user input only flows into context variables (data, not source)

from flask import Flask, request, render_template

app = Flask(__name__)


# SAFE: render_template() loads from the templates/ directory
# User input is passed as context data, never as template source
# Jinja2 autoescaping prevents XSS; template structure is developer-controlled
@app.route("/profile")
def profile():
    username = request.args.get("username", "Guest")
    bio = request.args.get("bio", "")
    role = request.args.get("role", "member")

    # SAFE: user input flows into template context as data, not source
    return render_template(
        "profile.html",
        username=username,
        bio=bio,
        role=role,
    )


@app.route("/search")
def search():
    query = request.args.get("q", "")
    page = request.args.get("page", "1", type=int)

    # Simulate search results
    results = [
        {"title": f"Result {i}", "snippet": f"Match for '{query}'..."}
        for i in range(1, 11)
    ]

    # SAFE: query and results are context data, template is from file
    return render_template(
        "search_results.html",
        query=query,
        results=results,
        page=page,
        total_pages=10,
    )


@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id")
    # Simulate fetching user data
    user = {"id": user_id, "name": "Alice", "email": "alice@example.com"}
    notifications = [
        {"message": "New comment on your post", "read": False},
        {"message": "System maintenance scheduled", "read": True},
    ]

    # SAFE: all user-related data passed as context variables
    return render_template(
        "dashboard.html",
        user=user,
        notifications=notifications,
        active_tab="overview",
    )
