# Fixture: py-django-raw-interp — Django raw() with interpolation
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-89
# Pattern: f-string in Model.objects.raw() and .extra()

from django.http import JsonResponse
from django.contrib.auth.models import User
from django.db.models.expressions import RawSQL


def search_users(request):
    query = request.GET.get("q")
    # VULNERABLE: f-string in raw()
    users = User.objects.raw(
        f"SELECT * FROM auth_user WHERE username LIKE '%{query}%'"
    )
    return JsonResponse({"users": [u.username for u in users]})


def filter_with_extra(request):
    status = request.GET.get("status")
    # VULNERABLE: f-string in extra(where=)
    users = User.objects.extra(where=[f"status = '{status}'"])
    return JsonResponse({"users": list(users.values("username"))})


def annotate_raw(request):
    field = request.GET.get("field")
    # VULNERABLE: f-string in RawSQL
    users = User.objects.annotate(
        custom=RawSQL(f"SELECT {field} FROM auth_user", [])
    )
    return JsonResponse({"users": list(users.values())})
