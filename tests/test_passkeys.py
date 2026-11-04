import pytest
from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model

from tests.conftest import API, PASSWORD, is_signed_in, sign_in
from tests.software_authenticator import SoftwareAuthenticator

pytestmark = pytest.mark.django_db


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def register_passkey(client, name):
    options = client.get(f"{API}/auth/2fa/setup/webauthn").json()["data"]["creation_options"]
    key = SoftwareAuthenticator()
    response = client.post(
        f"{API}/auth/2fa/setup/webauthn",
        {"name": name, "credential": key.create_credential(options)},
        content_type="application/json",
    )
    return key, response


def test_set_up_with_a_passkey_opens_the_account(client, account):
    response = sign_in(client, account.email, PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    key, response = register_passkey(client, "Laptop")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["user"]["email"] == account.email
    assert len(data["recovery_codes"]) > 0
    assert data["methods"][-1]["method"] == "mfa"
    assert data["methods"][-1]["type"] == "webauthn"
    assert is_signed_in(client)
    assert Authenticator.objects.filter(user=account, type=Authenticator.Type.WEBAUTHN).exists()
    assert Authenticator.objects.filter(
        user=account, type=Authenticator.Type.RECOVERY_CODES
    ).exists()


def test_the_passkey_is_the_second_step_at_the_next_sign_in(client, account):
    sign_in(client, account.email, PASSWORD)
    key, _ = register_passkey(client, "Laptop")
    client.logout()

    response = sign_in(client, account.email, PASSWORD)

    assert response.status_code == 401
    flows = response.json()["data"]["flows"]
    assert {
        "id": "mfa_authenticate",
        "is_pending": True,
        "types": ["recovery_codes", "webauthn"],
    } in flows
    assert not is_signed_in(client)

    response = client.get(f"{API}/auth/webauthn/authenticate")

    assert response.status_code == 200
    request_options = response.json()["data"]["request_options"]

    response = client.post(
        f"{API}/auth/webauthn/authenticate",
        {"credential": key.sign(request_options)},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["data"]["user"]["email"] == account.email
    assert is_signed_in(client)


def test_passkey_set_up_refuses_when_a_second_step_already_exists(client, account):
    from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret

    sign_in(client, account.email, PASSWORD)
    TOTP.activate(account, generate_totp_secret())

    assert client.get(f"{API}/auth/2fa/setup/webauthn").status_code == 409
    response = client.post(
        f"{API}/auth/2fa/setup/webauthn",
        {"name": "Laptop", "credential": {}},
        content_type="application/json",
    )

    assert response.status_code == 409
    assert not Authenticator.objects.filter(user=account, type=Authenticator.Type.WEBAUTHN).exists()
    assert not is_signed_in(client)


def test_a_passkey_never_opens_the_account_without_the_password(client, account):
    sign_in(client, account.email, PASSWORD)
    register_passkey(client, "Laptop")
    client.logout()

    assert client.get(f"{API}/auth/webauthn/login").status_code == 404
    assert client.post(f"{API}/auth/webauthn/signup", {}).status_code == 404
    assert not is_signed_in(client)
