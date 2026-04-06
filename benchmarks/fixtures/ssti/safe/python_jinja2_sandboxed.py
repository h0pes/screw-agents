# Fixture: py-jinja2-sandboxed — Jinja2 SandboxedEnvironment with template from file
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-1336
# Agent: ssti
# Pattern: SandboxedEnvironment with templates loaded from filesystem, user input as context only

from jinja2.sandbox import SandboxedEnvironment
from jinja2 import FileSystemLoader
from flask import Flask, request, jsonify

app = Flask(__name__)

# SAFE: SandboxedEnvironment restricts template capabilities
# Even if a template tries to access unsafe attributes, the sandbox blocks it
sandbox_env = SandboxedEnvironment(
    loader=FileSystemLoader("templates"),
    autoescape=True,
)


@app.route("/render-widget")
def render_widget():
    title = request.args.get("title", "Widget")
    content = request.args.get("content", "Default content")
    theme = request.args.get("theme", "light")

    # SAFE: template loaded from file, user input is context data only
    template = sandbox_env.get_template("widget.html")
    rendered = template.render(title=title, content=content, theme=theme)
    return rendered


@app.route("/api/email-preview", methods=["POST"])
def email_preview():
    data = request.get_json()
    subject = data.get("subject", "No Subject")
    body_text = data.get("body", "Hello")
    recipient = data.get("recipient", "user@example.com")

    # SAFE: template is loaded from a file, not constructed from user input
    # body_text is passed as data that gets HTML-escaped by autoescaping
    template = sandbox_env.get_template("email_preview.html")
    rendered = template.render(
        subject=subject,
        body=body_text,
        recipient=recipient,
    )
    return jsonify({"preview": rendered})


@app.route("/newsletter", methods=["POST"])
def newsletter():
    data = request.get_json()
    articles = data.get("articles", [])
    header_text = data.get("header", "Weekly Newsletter")

    # SAFE: even though articles come from user, they are data not source
    template = sandbox_env.get_template("newsletter.html")
    rendered = template.render(
        header=header_text,
        articles=articles,
        unsubscribe_url="https://example.com/unsubscribe",
    )
    return rendered
