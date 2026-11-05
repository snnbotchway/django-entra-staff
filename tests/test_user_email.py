import pytest
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, override_settings

from tests.conftest import API, PASSWORD, error_code, sign_in

pytestmark = pytest.mark.django_db

COLLEAGUE = "colleague@example.org"


@pytest.fixture
def user():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def post_email(client, email):
    return client.post(f"{API}/account/email", {"email": email}, content_type="application/json")


def patch_primary(client, email):
    return client.patch(
        f"{API}/account/email", {"email": email, "primary": True}, content_type="application/json"
    )


def test_a_linked_user_cannot_add_an_email(microsoft, client, user):
    microsoft.sign_in(client, email=user.email)

    response = post_email(client, COLLEAGUE)

    assert response.status_code == 403
    assert response.json()["errors"][0]["code"] == "email_change_not_supported"
    assert not EmailAddress.objects.exists()
    assert mail.outbox == []


def test_a_linked_user_cannot_make_another_email_its_primary(microsoft, client, user):
    microsoft.sign_in(client, email=user.email)
    EmailAddress.objects.create(user=user, email=COLLEAGUE)

    response = patch_primary(client, COLLEAGUE)

    assert response.status_code == 403
    assert response.json()["errors"][0]["code"] == "email_change_not_supported"
    user.refresh_from_db()
    assert user.email == "jane.doe@example.org"


def test_an_user_with_a_password_can_still_add_an_email(client, user):
    client.force_login(user)

    response = post_email(client, "jane@example.com")

    assert response.status_code == 200
    assert EmailAddress.objects.filter(user=user, email="jane@example.com").exists()
    assert [message.to for message in mail.outbox] == [["jane@example.com"]]


def test_an_unverified_address_cannot_become_primary_and_capture_a_colleagues_sign_in(
    microsoft, client, user
):
    client.force_login(user)
    post_email(client, COLLEAGUE)

    response = patch_primary(client, COLLEAGUE)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "unverified_primary_email"
    user.refresh_from_db()
    assert user.email == "jane.doe@example.org"

    colleague = microsoft.sign_in(Client(), email=COLLEAGUE)

    assert error_code(colleague) == "invite_only"
    assert not SocialAccount.objects.exists()


def test_a_verified_address_can_become_primary(client, user):
    client.force_login(user)
    EmailAddress.objects.create(user=user, email="jane@example.com", verified=True)

    response = patch_primary(client, "jane@example.com")

    assert response.status_code == 200
    user.refresh_from_db()
    assert user.email == "jane@example.com"


@override_settings(
    ACCOUNT_EMAIL_VERIFICATION="mandatory",
    ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED=True,
    ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_CHANGE=True,
)
def test_a_person_waiting_to_verify_their_email_cannot_change_it_to_a_colleagues(
    microsoft, client, user
):
    pending = sign_in(client, user.email, PASSWORD)
    assert [flow["id"] for flow in pending.json()["data"]["flows"] if flow.get("is_pending")] == [
        "verify_email"
    ]

    response = post_email(client, COLLEAGUE)

    assert response.status_code == 403
    user.refresh_from_db()
    assert user.email == "jane.doe@example.org"
    colleague = microsoft.sign_in(Client(), email=COLLEAGUE)
    assert error_code(colleague) == "invite_only"
    assert not SocialAccount.objects.exists()
