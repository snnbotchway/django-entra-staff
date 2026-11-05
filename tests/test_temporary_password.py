"""The Temporary password: the service that sets it and the forced replacement at sign-in."""

import pytest
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import get_user_model

from django_entra_staff import services
from django_entra_staff.errors import ErrorCode, StaffError
from tests.conftest import (
    API,
    PASSWORD,
    is_signed_in,
    sign_in,
    totp_code,
    totp_secret_of,
)

pytestmark = pytest.mark.django_db

TEMP_PASSWORD = "temporary-pass-1"
NEW_PASSWORD = "quiet meadow ladder seven"


@pytest.fixture
def temp_password_account():
    account = get_user_model().objects.create_user("jane.doe@example.org")
    services.set_temporary_password(account, TEMP_PASSWORD)
    return account


@pytest.fixture
def second_step(temp_password_account):
    TOTP.activate(temp_password_account, generate_totp_secret())
    RecoveryCodes.activate(temp_password_account)
    return temp_password_account


def test_set_temporary_password_sets_the_password_and_the_flag_together(
    temporary_password_events,
):
    account = get_user_model().objects.create_user("jane.doe@example.org")
    it = get_user_model().objects.create_superuser("it@example.org", PASSWORD)

    services.set_temporary_password(account, TEMP_PASSWORD, acting_account=it)

    account.refresh_from_db()
    assert account.check_password(TEMP_PASSWORD)
    assert account.must_replace_password
    assert [(event["account"], event["acting_account"]) for event in temporary_password_events] == [
        (account, it)
    ]


def test_set_temporary_password_refuses_an_account_with_a_microsoft_link(
    microsoft, client, temporary_password_events
):
    account = get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)
    microsoft.sign_in(client, email=account.email)
    account.refresh_from_db()

    with pytest.raises(StaffError) as refused:
        services.set_temporary_password(account, TEMP_PASSWORD)

    assert refused.value.code == ErrorCode.MICROSOFT_LINKED
    account.refresh_from_db()
    assert not account.has_usable_password()
    assert not account.must_replace_password
    assert temporary_password_events == []


@pytest.mark.usefixtures("second_step")
def test_a_temporary_password_is_replaced_after_the_second_step(client, temp_password_account):
    response = sign_in(client, temp_password_account.email, TEMP_PASSWORD)

    assert response.status_code == 401
    assert {
        "id": "mfa_authenticate",
        "is_pending": True,
        "types": ["recovery_codes", "totp"],
    } in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(temp_password_account))},
        content_type="application/json",
    )

    assert response.status_code == 401
    assert {"id": "replace_password", "is_pending": True} in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["data"]["user"]["email"] == temp_password_account.email
    assert is_signed_in(client)
    temp_password_account.refresh_from_db()
    assert not temp_password_account.must_replace_password
    assert temp_password_account.check_password(NEW_PASSWORD)


def test_second_step_set_up_comes_before_replacing_the_temporary_password(
    client, temp_password_account
):
    response = sign_in(client, temp_password_account.email, TEMP_PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]

    secret = client.get(f"{API}/auth/2fa/setup").json()["meta"]["secret"]
    response = client.post(
        f"{API}/auth/2fa/setup", {"code": totp_code(secret)}, content_type="application/json"
    )

    assert response.status_code == 401
    data = response.json()["data"]
    assert len(data["recovery_codes"]) > 0
    assert {"id": "replace_password", "is_pending": True} in data["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)


@pytest.mark.usefixtures("second_step")
def test_the_new_password_must_pass_the_app_s_password_rules(client, temp_password_account):
    sign_in(client, temp_password_account.email, TEMP_PASSWORD)
    client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(temp_password_account))},
        content_type="application/json",
    )

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": "short"},
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["param"] == "new_password"
    assert not is_signed_in(client)
    temp_password_account.refresh_from_db()
    assert temp_password_account.must_replace_password

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)


def test_a_microsoft_sign_in_is_never_asked_to_replace_a_password(
    client, microsoft, temp_password_account
):
    response = microsoft.sign_in(client, email=temp_password_account.email)

    assert response.status_code == 302
    temp_password_account.refresh_from_db()
    assert not temp_password_account.has_usable_password()
    assert temp_password_account.must_replace_password
    assert is_signed_in(client)
