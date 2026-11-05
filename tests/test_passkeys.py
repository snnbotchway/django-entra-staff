import pytest
from allauth.mfa.adapter import get_adapter as get_mfa_adapter
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import get_user_model

from tests.conftest import (
    API,
    PASSWORD,
    is_signed_in,
    recovery_codes_of,
    sign_in,
    totp_code,
    totp_secret_of,
)
from tests.software_authenticator import SoftwareAuthenticator

pytestmark = pytest.mark.django_db


@pytest.fixture
def user():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


@pytest.fixture
def totp_user(user):
    TOTP.activate(user, generate_totp_secret())
    RecoveryCodes.activate(user)
    return user


def register_passkey(client, name):
    options = client.get(f"{API}/auth/2fa/setup/webauthn").json()["data"]["creation_options"]
    key = SoftwareAuthenticator()
    response = client.post(
        f"{API}/auth/2fa/setup/webauthn",
        {"name": name, "credential": key.create_credential(options)},
        content_type="application/json",
    )
    return key, response


def authenticate_with_passkey(client, key):
    request_options = client.get(f"{API}/auth/webauthn/authenticate").json()["data"][
        "request_options"
    ]
    return client.post(
        f"{API}/auth/webauthn/authenticate",
        {"credential": key.sign(request_options)},
        content_type="application/json",
    )


def reauthenticate(client, code):
    return client.post(
        f"{API}/auth/2fa/reauthenticate", {"code": code}, content_type="application/json"
    )


def add_passkey_while_signed_in(client, name):
    options = client.get(f"{API}/account/authenticators/webauthn").json()["data"][
        "creation_options"
    ]
    key = SoftwareAuthenticator()
    response = client.post(
        f"{API}/account/authenticators/webauthn",
        {"name": name, "credential": key.create_credential(options)},
        content_type="application/json",
    )
    return key, response


@pytest.fixture
def passkey_user(client, user):
    """A User taken through passkey set-up, with its key and recovery codes."""
    sign_in(client, user.email, PASSWORD)
    key, response = register_passkey(client, "Laptop")
    recovery_codes = response.json()["data"]["recovery_codes"]
    client.logout()
    return user, key, recovery_codes


def test_set_up_with_a_passkey_opens_the_user(client, user):
    response = sign_in(client, user.email, PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    key, response = register_passkey(client, "Laptop")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["user"]["email"] == user.email
    assert len(data["recovery_codes"]) > 0
    assert data["methods"][-1]["method"] == "mfa"
    assert data["methods"][-1]["type"] == "webauthn"
    assert is_signed_in(client)
    assert Authenticator.objects.filter(user=user, type=Authenticator.Type.WEBAUTHN).exists()
    assert Authenticator.objects.filter(user=user, type=Authenticator.Type.RECOVERY_CODES).exists()


def test_the_passkey_is_the_second_step_at_the_next_sign_in(client, user):
    sign_in(client, user.email, PASSWORD)
    key, _ = register_passkey(client, "Laptop")
    client.logout()

    response = sign_in(client, user.email, PASSWORD)

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
    assert response.json()["data"]["user"]["email"] == user.email
    assert is_signed_in(client)


def test_passkey_set_up_refuses_when_a_second_step_already_exists(client, user):
    sign_in(client, user.email, PASSWORD)
    TOTP.activate(user, generate_totp_secret())

    assert client.get(f"{API}/auth/2fa/setup/webauthn").status_code == 409
    response = client.post(
        f"{API}/auth/2fa/setup/webauthn",
        {"name": "Laptop", "credential": {}},
        content_type="application/json",
    )

    assert response.status_code == 409
    assert not Authenticator.objects.filter(user=user, type=Authenticator.Type.WEBAUTHN).exists()
    assert not is_signed_in(client)


def test_a_passkey_never_opens_the_user_without_the_password(client, user):
    sign_in(client, user.email, PASSWORD)
    register_passkey(client, "Laptop")
    client.logout()

    assert client.get(f"{API}/auth/webauthn/login").status_code == 404
    assert client.post(f"{API}/auth/webauthn/signup", {}).status_code == 404
    assert not is_signed_in(client)


def test_a_person_can_register_several_named_passkeys(client, passkey_user):
    user, key, recovery_codes = passkey_user
    sign_in(client, user.email, PASSWORD)
    response = authenticate_with_passkey(client, key)

    assert response.status_code == 200
    assert is_signed_in(client)

    response = reauthenticate(client, recovery_codes[0])

    assert response.status_code == 200

    phone, response = add_passkey_while_signed_in(client, "Phone")

    assert response.status_code == 200
    assert response.json()["data"]["name"] == "Phone"

    client.logout()
    sign_in(client, user.email, PASSWORD)
    response = authenticate_with_passkey(client, phone)

    assert response.status_code == 200
    assert is_signed_in(client)

    client.logout()
    sign_in(client, user.email, PASSWORD)
    response = authenticate_with_passkey(client, key)

    assert response.status_code == 200
    assert is_signed_in(client)


def test_removing_the_last_second_step_is_refused(client, passkey_user):
    user, key, recovery_codes = passkey_user
    sign_in(client, user.email, PASSWORD)
    authenticate_with_passkey(client, key)
    reauthenticate(client, recovery_codes[0])
    authenticator = Authenticator.objects.get(user=user, type=Authenticator.Type.WEBAUTHN)

    response = client.delete(
        f"{API}/account/authenticators/webauthn",
        {"authenticators": [authenticator.pk]},
        content_type="application/json",
    )

    assert response.status_code == 409
    assert response.json()["errors"][0]["code"] == "cannot_delete_authenticator"
    assert Authenticator.objects.filter(user=user, type=Authenticator.Type.WEBAUTHN).exists()


def test_one_of_several_second_steps_can_be_removed(client, passkey_user):
    user, key, recovery_codes = passkey_user
    sign_in(client, user.email, PASSWORD)
    authenticate_with_passkey(client, key)
    reauthenticate(client, recovery_codes[0])
    laptop = Authenticator.objects.get(user=user, type=Authenticator.Type.WEBAUTHN)
    _, response = add_passkey_while_signed_in(client, "Phone")
    phone_pk = response.json()["data"]["id"]

    response = client.delete(
        f"{API}/account/authenticators/webauthn",
        {"authenticators": [laptop.pk]},
        content_type="application/json",
    )

    assert response.status_code == 200

    response = client.delete(
        f"{API}/account/authenticators/webauthn",
        {"authenticators": [phone_pk]},
        content_type="application/json",
    )

    assert response.status_code == 409
    assert Authenticator.objects.filter(user=user, type=Authenticator.Type.WEBAUTHN).count() == 1


def test_removing_the_last_totp_is_refused(client, totp_user):
    sign_in(client, totp_user.email, PASSWORD)
    client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(totp_user))},
        content_type="application/json",
    )
    reauthenticate(client, recovery_codes_of(totp_user)[0])

    response = client.delete(f"{API}/account/authenticators/totp")

    assert response.status_code == 409
    assert Authenticator.objects.filter(user=totp_user, type=Authenticator.Type.TOTP).exists()


def test_the_mfa_adapter_refuses_removing_the_last_second_step(client, totp_user):
    totp = Authenticator.objects.get(user=totp_user, type=Authenticator.Type.TOTP)

    assert not get_mfa_adapter().can_delete_authenticator(totp)

    sign_in(client, totp_user.email, PASSWORD)
    client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(totp_user))},
        content_type="application/json",
    )
    reauthenticate(client, recovery_codes_of(totp_user)[0])
    add_passkey_while_signed_in(client, "Laptop")

    assert get_mfa_adapter().can_delete_authenticator(totp)
