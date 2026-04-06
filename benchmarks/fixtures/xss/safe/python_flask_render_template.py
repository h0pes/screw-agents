# Fixture: py-flask-render-template — Flask render_template() with .html extension
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-79
# Agent: xss
# Pattern: render_template() with .html file extension (Jinja2 auto-escaping active)

from flask import Flask, request, render_template
from markupsafe import escape

app = Flask(__name__)


@app.route("/profile")
def profile():
    username = request.args.get("username", "Guest")
    bio = request.args.get("bio", "")

    # SAFE: render_template() loads from templates/ directory
    # Jinja2 auto-escapes all variables in .html templates by default
    # {{ username }} and {{ bio }} are automatically HTML-encoded
    return render_template(
        "profile.html",
        username=username,
        bio=bio,
    )


@app.route("/search")
def search():
    query = request.args.get("q", "")
    page = request.args.get("page", "1", type=int)

    results = [
        {"title": f"Result {i}", "snippet": f"Match for '{query}'..."}
        for i in range(1, 11)
    ]

    # SAFE: file-based template with .html extension — auto-escaping on
    return render_template(
        "search_results.html",
        query=query,
        results=results,
        page=page,
        total_pages=10,
    )


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")

    # SAFE: markupsafe.escape() provides explicit HTML encoding
    # This is safe even for direct string returns, though render_template is preferred
    escaped_name = escape(name)
    return render_template("greeting.html", name=escaped_name)


@app.route("/api/search")
def api_search():
    query = request.args.get("q", "")

    # SAFE: returning JSON, not HTML — no XSS risk in JSON API responses
    # (assuming proper Content-Type: application/json header)
    return {
        "query": query,
        "results": [
            {"title": "Result 1", "url": "/page/1"},
            {"title": "Result 2", "url": "/page/2"},
        ],
    }
