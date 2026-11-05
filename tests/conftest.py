import json
import time
import uuid
from functools import cache as cached
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import requests
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import (
    TOTP,
    format_hotp_value,
    generate_totp_secret,
    hotp_value,
    yield_hotp_counters_from_time,
)
from allauth.mfa.utils import decrypt
from allauth.socialaccount.models import SocialAccount
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.cache import cache

from django_entra_staff.conf import get_settings
from django_entra_staff.signals import microsoft_link_made, temporary_password_set

API = "/_allauth/browser/v1"
MICROSOFT_CALLBACK = "/microsoft/login/callback/"
NEXT_URL = "/next"
PASSWORD = "correct horse battery"

KID = "test-signing-key"


def sign_in(client, email, password):
    return client.post(
        f"{API}/auth/login", {"email": email, "password": password}, content_type="application/json"
    )


def is_signed_in(client):
    return client.get(f"{API}/auth/session").status_code == 200


def link_microsoft(user, uid="uid-1", provider="microsoft"):
    """Give the User the Microsoft link row, whatever way it was made."""
    return SocialAccount.objects.create(user=user, provider=provider, uid=uid)


@pytest.fixture
def second_step_user(user):
    """A User that has set up its Second step (TOTP and recovery codes)."""
    TOTP.activate(user, generate_totp_secret())
    RecoveryCodes.activate(user)
    return user


def totp_code(secret):
    counter = next(yield_hotp_counters_from_time())
    return format_hotp_value(hotp_value(secret, counter))


def totp_secret_of(user):
    authenticator = Authenticator.objects.get(user=user, type=Authenticator.Type.TOTP)
    return decrypt(authenticator.data["secret"])


def recovery_codes_of(user):
    authenticator = Authenticator.objects.get(user=user, type=Authenticator.Type.RECOVERY_CODES)
    return authenticator.wrap().get_unused_codes()


@pytest.fixture(autouse=True)
def _clear_cache():
    """Allauth's attempt limits and id_token replay protection live in the cache."""
    cache.clear()


def error_code(response):
    """The `?error=` code the headless provider flow redirected back with."""
    query = parse_qs(urlparse(response["Location"]).query)
    return query.get("error", [None])[0]


@cached
def _signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks():
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(_signing_key().public_key(), as_dict=True)
    jwk |= {"kid": KID, "alg": "RS256", "use": "sig"}
    return {"keys": [jwk]}


def _id_token(tid, uid, idp=None):
    client_id = settings.SOCIALACCOUNT_PROVIDERS["microsoft"]["APP"]["client_id"]
    now = int(time.time())
    claims = {
        "aud": client_id,
        "exp": now + 300,
        "iat": now,
        "iss": f"https://login.microsoftonline.com/{tid}/v2.0",
        "jti": uuid.uuid4().hex,
        "sub": uid,
        "tid": tid,
    }
    if idp:
        claims["idp"] = idp
    return jwt.encode(claims, _signing_key(), algorithm="RS256", headers={"kid": KID})


def _json_response(status, data):
    body = json.dumps(data)

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __init__(self):
            self.status_code = status
            self.text = body
            self.content = body.encode()

        def json(self):
            return data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(str(self.status_code), response=self)

    return FakeResponse()


class FakeMicrosoft:
    """Microsoft Entra, faked at the network edge.

    Only the three HTTP endpoints the sign-in talks to are faked (token,
    key-set, Graph user info), by patching `requests.Session.request`. The
    id_token is really signed and really verified by the package.
    """

    def __init__(self):
        self.tid = None
        self.uid = None
        self.idp = None
        self.profile = {}

    def sign_in(
        self,
        client,
        *,
        email,
        uid="uid-1",
        tid=None,
        idp=None,
        process="login",
        provider="microsoft",
        given_name="Jane",
        surname="Doe",
    ):
        """`idp` sets the id_token's identity provider claim, as Entra does for a guest.
        `provider` is the id the App's Microsoft app is registered under. A name
        given as None is left out of the profile, as Graph does when it's unset."""
        self.tid = tid or get_settings().tenant_id
        self.uid = uid
        self.idp = idp
        self.profile = {
            "id": uid,
            "mail": email,
            "userPrincipalName": email,
            "mailNickname": email.partition("@")[0],
        }
        if given_name is not None:
            self.profile["givenName"] = given_name
        if surname is not None:
            self.profile["surname"] = surname
        started = client.post(
            f"{API}/auth/provider/redirect",
            {"provider": provider, "callback_url": NEXT_URL, "process": process},
        )
        assert started.status_code == 302, started.status_code
        state = parse_qs(urlparse(started["Location"]).query)["state"][0]
        return client.get(MICROSOFT_CALLBACK, {"code": "test-code", "state": state})

    def route(self, method, url):
        tenant = get_settings().tenant_id
        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        keys_url = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        if method == "POST" and url == token_url:
            token = {
                "access_token": "fake-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": _id_token(self.tid, self.uid, self.idp),
            }
            return _json_response(200, token)
        if method == "GET" and url == keys_url:
            return _json_response(200, _jwks())
        if method == "GET" and url == "https://graph.microsoft.com/v1.0/me":
            return _json_response(200, self.profile)
        raise AssertionError(f"Unexpected request to Microsoft: {method} {url}")


@pytest.fixture
def microsoft():
    fake = FakeMicrosoft()

    def request(_session, method, url, **kwargs):
        return fake.route(method, url)

    with mock.patch.object(requests.Session, "request", request):
        yield fake


@pytest.fixture
def link_made_events():
    """The payloads of every microsoft_link_made sent during the test."""
    events = []

    def receiver(sender, **kwargs):
        events.append(kwargs)

    microsoft_link_made.connect(receiver, weak=False)
    yield events
    microsoft_link_made.disconnect(receiver)


@pytest.fixture
def temporary_password_events():
    """The payloads of every temporary_password_set sent during the test."""
    received = []

    def receiver(sender, **kwargs):
        received.append(kwargs)

    temporary_password_set.connect(receiver, weak=False)
    yield received
    temporary_password_set.disconnect(receiver)
