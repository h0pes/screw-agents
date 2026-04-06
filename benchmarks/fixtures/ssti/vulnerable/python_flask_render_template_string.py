# Fixture: py-flask-render-template-string — render_template_string() with user input
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-1336
# Agent: ssti
# Pattern: User input concatenated into template source passed to render_template_string()

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/profile")
def profile():
    username = request.args.get("username", "Guest")
    bio = request.args.get("bio", "")
    # VULNERABLE: user-controlled bio is interpolated into template source
    # Attacker sends: ?bio={{config.items()}} or ?bio={{''.__class__.__mro__[1].__subclasses__()}}
    template = f"""
    <html>
    <body>
        <h1>Profile: {username}</h1>
        <div class="bio">{bio}</div>
    </body>
    </html>
    """
    return render_template_string(template)


@app.route("/greeting")
def greeting():
    name = request.args.get("name", "World")
    custom_message = request.args.get("message", "Welcome!")
    # VULNERABLE: user-controlled message becomes part of Jinja2 template source
    # Attacker sends: ?message={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
    return render_template_string(
        "<h1>Hello, " + name + "!</h1><p>" + custom_message + "</p>"
    )


@app.route("/error")
def custom_error():
    error_code = request.args.get("code", "404")
    error_detail = request.args.get("detail", "Page not found")
    # VULNERABLE: error_detail is user-controlled and embedded in template
    template_src = (
        "{% extends 'base.html' %}"
        "{% block content %}"
        "<div class='error'>"
        "<h2>Error " + error_code + "</h2>"
        "<p>" + error_detail + "</p>"
        "</div>"
        "{% endblock %}"
    )
    return render_template_string(template_src)
