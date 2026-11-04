import pytest
from django.core.cache import cache

API = "/_allauth/browser/v1"
PASSWORD = "correct horse battery"


def sign_in(client, email, password):
    return client.post(
        f"{API}/auth/login", {"email": email, "password": password}, content_type="application/json"
    )


def is_signed_in(client):
    return client.get(f"{API}/auth/session").status_code == 200


@pytest.fixture(autouse=True)
def _clear_cache():
    """Allauth's attempt limits live in the cache."""
    cache.clear()
