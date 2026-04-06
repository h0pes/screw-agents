# Fixture: py-jinja2-from-string — Jinja2 Environment.from_string() with user input
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-1336
# Agent: ssti
# Pattern: User input passed directly as template source to Environment.from_string()

from jinja2 import Environment, FileSystemLoader
from flask import Flask, request, jsonify

app = Flask(__name__)
jinja_env = Environment(loader=FileSystemLoader("templates"))


@app.route("/render-widget")
def render_widget():
    widget_template = request.args.get("template", "<p>Default</p>")
    title = request.args.get("title", "Widget")
    # VULNERABLE: user-supplied template string is compiled as Jinja2 template
    # Attacker sends: ?template={{config}}
    tmpl = jinja_env.from_string(widget_template)
    return tmpl.render(title=title)


@app.route("/api/email-preview", methods=["POST"])
def email_preview():
    data = request.get_json()
    subject = data.get("subject", "No Subject")
    body_template = data.get("body", "<p>Hello</p>")
    recipient = data.get("recipient", "user@example.com")
    # VULNERABLE: body_template from JSON request body used as template source
    # Attacker sends: {"body": "{{ ''.__class__.__mro__[1].__subclasses__() }}"}
    tmpl = jinja_env.from_string(body_template)
    rendered = tmpl.render(subject=subject, recipient=recipient)
    return jsonify({"preview": rendered})


@app.route("/cms/page", methods=["POST"])
def cms_page():
    data = request.get_json()
    page_content = data.get("content", "")
    page_title = data.get("title", "Untitled")
    # VULNERABLE: CMS content from user is treated as template source
    # This pattern is common in CMS systems that want to support "dynamic" content
    header = "<html><head><title>{{ title }}</title></head><body>"
    footer = "</body></html>"
    full_template = header + page_content + footer
    tmpl = jinja_env.from_string(full_template)
    return tmpl.render(title=page_title)
