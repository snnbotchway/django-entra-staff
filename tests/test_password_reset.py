from urllib.parse import urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core import mail

from django_entra_staff import services
from tests.conftest import (
    API,
    PASSWORD,
    is_signed_in,
    link_microsoft,
    sign_in,
    totp_code,
    totp_secret_of,
)

pytestmark = pytest.mark.django_db

NEW_PASSWORD = "new correct horse battery"


def request_reset(client, email):
    return client.post(
        f"{API}/auth/password/request", {"email": email}, content_type="application/json"
    )


def reset_key_from_mail():
    url = next(line for line in mail.outbox[0].body.splitlines() if line.startswith("http"))
    return urlparse(url).path.rpartition("/")[2]


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def test_a_reset_email_is_sent_to_an_account_with_a_password(client, account):
    response = request_reset(client, account.email)

    assert response.status_code == 200
    assert [message.to for message in mail.outbox] == [[account.email]]


def test_no_reset_email_for_an_account_without_a_password(client):
    get_user_model().objects.create_user("jane.doe@example.org")

    response = request_reset(client, "jane.doe@example.org")

    assert response.status_code == 200
    assert not mail.outbox


def test_no_reset_email_for_a_linked_account_even_with_a_password(client, account):
    link_microsoft(account)

    response = request_reset(client, account.email)

    assert response.status_code == 200
    assert not mail.outbox


def test_the_reset_request_answers_the_same_way_whatever_the_email(client):
    get_user_model().objects.create_user("has.password@example.org", PASSWORD)
    linked = get_user_model().objects.create_user("linked@example.org", PASSWORD)
    link_microsoft(linked, uid="uid-2")

    responses = [
        request_reset(client, email)
        for email in ("has.password@example.org", "linked@example.org", "nobody@example.org")
    ]

    assert all(response.json() == {"status": 200} for response in responses)


def test_after_a_reset_the_next_sign_in_still_needs_the_second_step(client, second_step_account):
    request_reset(client, second_step_account.email)
    response = client.post(
        f"{API}/auth/password/reset",
        {"key": reset_key_from_mail(), "password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 401
    assert not is_signed_in(client)

    response = sign_in(client, second_step_account.email, NEW_PASSWORD)

    assert response.status_code == 401
    assert {
        "id": "mfa_authenticate",
        "is_pending": True,
        "types": ["recovery_codes", "totp"],
    } in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(second_step_account))},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)


def test_a_reset_key_issued_before_linking_dies_when_the_account_is_linked(
    client, microsoft, account
):
    request_reset(client, account.email)
    key = reset_key_from_mail()

    microsoft.sign_in(client, email=account.email)
    account.refresh_from_db()
    assert not account.has_usable_password()

    response = client.post(
        f"{API}/auth/password/reset",
        {"key": key, "password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "invalid_password_reset"
    account.refresh_from_db()
    assert not account.has_usable_password()


def test_resetting_a_temporary_password_does_not_ask_for_a_replacement_again(
    client, second_step_account
):
    services.set_temporary_password(second_step_account, "temporary-pass-1")
    request_reset(client, second_step_account.email)
    client.post(
        f"{API}/auth/password/reset",
        {"key": reset_key_from_mail(), "password": NEW_PASSWORD},
        content_type="application/json",
    )

    sign_in(client, second_step_account.email, NEW_PASSWORD)
    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(second_step_account))},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)
    second_step_account.refresh_from_db()
    assert not second_step_account.must_replace_password
