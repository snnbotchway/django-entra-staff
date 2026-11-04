import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal.auth import (
    format_hotp_value,
    hotp_value,
    yield_hotp_counters_from_time,
)
from allauth.mfa.utils import decrypt
from django.core.cache import cache

API = "/_allauth/browser/v1"
PASSWORD = "correct horse battery"


def sign_in(client, email, password):
    return client.post(
        f"{API}/auth/login", {"email": email, "password": password}, content_type="application/json"
    )


def is_signed_in(client):
    return client.get(f"{API}/auth/session").status_code == 200


def totp_code(secret):
    counter = next(yield_hotp_counters_from_time())
    return format_hotp_value(hotp_value(secret, counter))


def totp_secret_of(account):
    authenticator = Authenticator.objects.get(user=account, type=Authenticator.Type.TOTP)
    return decrypt(authenticator.data["secret"])


def recovery_codes_of(account):
    authenticator = Authenticator.objects.get(user=account, type=Authenticator.Type.RECOVERY_CODES)
    return authenticator.wrap().get_unused_codes()


@pytest.fixture(autouse=True)
def _clear_cache():
    """Allauth's attempt limits live in the cache."""
    cache.clear()
