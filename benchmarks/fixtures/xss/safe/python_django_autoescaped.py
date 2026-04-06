# Fixture: py-django-autoescaped — Django render() with auto-escaping on, format_html()
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-79
# Agent: xss
# Pattern: Django auto-escaping enabled (default), format_html() for safe HTML construction

from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import format_html, escape


def user_profile(request):
    username = request.GET.get("username", "Guest")
    bio = request.GET.get("bio", "")
    role = request.GET.get("role", "member")

    # SAFE: render() with auto-escaping on (Django's default behavior)
    # Template variables like {{ username }} are automatically HTML-escaped
    # <, >, &, ", ' are all converted to their HTML entity equivalents
    return render(request, "profile.html", {
        "username": username,
        "bio": bio,
        "role": role,
    })


def notification_banner(request):
    message = request.GET.get("message", "Welcome!")
    alert_type = request.GET.get("type", "info")

    # SAFE: format_html() is Django's safe way to build HTML with user input
    # It applies escaping to all arguments while preserving the format string's HTML
    banner = format_html(
        '<div class="alert alert-{}" role="alert">{}</div>',
        alert_type,
        message,
    )

    return render(request, "dashboard.html", {"banner": banner})


def search_results(request):
    query = request.GET.get("q", "")
    page = request.GET.get("page", "1")

    results = [
        {"title": f"Result {i}", "snippet": f"Matched: {query}"}
        for i in range(1, 11)
    ]

    # SAFE: Django auto-escapes {{ query }} in the template
    # No |safe filter, no mark_safe(), no {% autoescape off %}
    return render(request, "search.html", {
        "query": query,
        "results": results,
        "page": page,
    })


def user_comment(request):
    comment_text = request.POST.get("comment", "")

    # SAFE: explicit escape() for programmatic HTML construction
    escaped_comment = escape(comment_text)

    return render(request, "comment_posted.html", {
        "comment": escaped_comment,
    })
