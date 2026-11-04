import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.signals import authenticator_added
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import get_user_model
from django.test import TestCase

from tests.conftest import (
    API,
    PASSWORD,
    is_signed_in,
    sign_in,
    totp_code,
    totp_secret_of,
)

pytestmark = pytest.mark.django_db


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


@pytest.fixture
def second_step_account(account):
    TOTP.activate(account, generate_totp_secret())
    RecoveryCodes.activate(account)
    return account


def recovery_codes_of(account):
    authenticator = Authenticator.objects.get(user=account, type=Authenticator.Type.RECOVERY_CODES)
    return authenticator.wrap().get_unused_codes()


def test_sign_in_is_unfinished_until_a_valid_code(client, second_step_account):
    response = sign_in(client, second_step_account.email, PASSWORD)

    assert response.status_code == 401
    assert {
        "id": "mfa_authenticate",
        "is_pending": True,
        "types": ["recovery_codes", "totp"],
    } in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/authenticate", {"code": "000000"}, content_type="application/json"
    )

    assert response.status_code == 400
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(second_step_account))},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["data"]["user"]["email"] == second_step_account.email
    assert is_signed_in(client)


def test_each_recovery_code_works_once_only(client, second_step_account):
    codes = recovery_codes_of(second_step_account)

    sign_in(client, second_step_account.email, PASSWORD)
    response = client.post(
        f"{API}/auth/2fa/authenticate", {"code": codes[0]}, content_type="application/json"
    )

    assert response.status_code == 200
    assert is_signed_in(client)

    client.logout()
    sign_in(client, second_step_account.email, PASSWORD)
    response = client.post(
        f"{API}/auth/2fa/authenticate", {"code": codes[0]}, content_type="application/json"
    )

    assert response.status_code == 400
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/authenticate", {"code": codes[1]}, content_type="application/json"
    )

    assert response.status_code == 200
    assert is_signed_in(client)


def test_account_without_second_step_is_taken_through_set_up(client, account):
    response = sign_in(client, account.email, PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.get(f"{API}/auth/2fa/setup")

    assert response.status_code == 200
    secret = response.json()["meta"]["secret"]
    assert response.json()["meta"]["totp_url"].startswith("otpauth:")

    response = client.post(
        f"{API}/auth/2fa/setup", {"code": "000000"}, content_type="application/json"
    )

    assert response.status_code == 400
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/setup", {"code": totp_code(secret)}, content_type="application/json"
    )

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["user"]["email"] == account.email
    assert len(data["recovery_codes"]) > 0
    assert is_signed_in(client)
    assert Authenticator.objects.filter(user=account, type=Authenticator.Type.TOTP).exists()
    assert Authenticator.objects.filter(
        user=account, type=Authenticator.Type.RECOVERY_CODES
    ).exists()


def test_the_set_up_second_step_is_required_at_the_next_sign_in(client, account):
    sign_in(client, account.email, PASSWORD)
    secret = client.get(f"{API}/auth/2fa/setup").json()["meta"]["secret"]
    client.post(
        f"{API}/auth/2fa/setup", {"code": totp_code(secret)}, content_type="application/json"
    )
    client.logout()

    response = sign_in(client, account.email, PASSWORD)

    assert response.status_code == 401
    flows = response.json()["data"]["flows"]
    assert {
        "id": "mfa_authenticate",
        "is_pending": True,
        "types": ["recovery_codes", "totp"],
    } in flows
    assert not any(flow.get("id") == "second_step_setup" for flow in flows)

    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(account))},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)


def test_a_half_finished_sign_in_cannot_reach_other_endpoints(client, account):
    sign_in(client, account.email, PASSWORD)

    assert client.get(f"{API}/auth/session").status_code == 401
    assert client.get(f"{API}/account/authenticators").status_code == 401
    response = client.post(
        f"{API}/auth/2fa/authenticate", {"code": "000000"}, content_type="application/json"
    )

    assert response.status_code == 401
    assert not is_signed_in(client)


def test_set_up_refuses_when_the_second_step_already_exists(client, account):
    sign_in(client, account.email, PASSWORD)
    TOTP.activate(account, generate_totp_secret())

    assert client.get(f"{API}/auth/2fa/setup").status_code == 409
    response = client.post(
        f"{API}/auth/2fa/setup", {"code": "000000"}, content_type="application/json"
    )

    assert response.status_code == 409
    assert Authenticator.objects.filter(user=account, type=Authenticator.Type.TOTP).count() == 1
    assert not is_signed_in(client)


@pytest.fixture
def authenticators_added():
    received = []

    def receiver(sender, authenticator, **kwargs):
        received.append(authenticator.type)

    authenticator_added.connect(receiver)
    yield received
    authenticator_added.disconnect(receiver)


def test_set_up_announces_the_new_authenticators(client, account, authenticators_added):
    sign_in(client, account.email, PASSWORD)
    secret = client.get(f"{API}/auth/2fa/setup").json()["meta"]["secret"]

    with TestCase.captureOnCommitCallbacks(execute=True):
        response = client.post(
            f"{API}/auth/2fa/setup", {"code": totp_code(secret)}, content_type="application/json"
        )

    assert response.status_code == 200
    assert authenticators_added == ["totp", "recovery_codes"]
