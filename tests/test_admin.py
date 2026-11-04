"""The Django admin: the Account support page, its sign-in and its actions."""

import re
from urllib.parse import parse_qs, urlparse

import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

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

TEMP_PASSWORD = "temporary-pass-1"


@pytest.fixture
def it():
    return get_user_model().objects.create_superuser("it@example.org", PASSWORD)


@pytest.fixture
def it_client(client, it):
    client.force_login(it)
    return client


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def row_of(response, email):
    """The changelist row for the Account with this email, as HTML."""
    match = re.search(
        rf"<tr[^>]*>(?:(?!</tr>).)*{re.escape(email)}(?:(?!</tr>).)*</tr>",
        response.content.decode(),
        re.DOTALL,
    )
    assert match, f"No changelist row for {email}"
    return match[0]


def test_the_changelist_shows_what_it_needs_to_support_people(it_client):
    invited = services.invite_account("invited@example.org", ["viewer", "editor"])
    temporary = services.invite_account("temporary@example.org", ["viewer"])
    services.set_temporary_password(temporary, TEMP_PASSWORD)
    linked = services.invite_account("linked@example.org", ["viewer"])
    link_microsoft(linked, uid="uid-1")
    blocked = services.invite_account("blocked@example.org", ["viewer"])
    services.block_account(blocked)
    guarding = get_user_model().objects.create_user("guarding@example.org", PASSWORD)
    TOTP.activate(guarding, generate_totp_secret())
    RecoveryCodes.activate(guarding)

    response = it_client.get(reverse("admin:testapp_account_changelist"))

    row = row_of(response, invited.email)
    assert "editor, viewer" in row
    assert "Not linked" in row
    assert "No password" in row
    assert "Not set up" in row
    assert "Active" in row

    row = row_of(response, temporary.email)
    assert "Temporary password" in row

    row = row_of(response, linked.email)
    assert "Linked" in row
    assert "No password" in row

    row = row_of(response, blocked.email)
    assert "Blocked" in row

    row = row_of(response, guarding.email)
    assert "Password set" in row
    assert "Set up" in row


def test_the_admin_login_page_is_not_a_plain_password_form(client):
    response = client.get("/admin/login/")

    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert location.path == "/sign-in/"
    assert parse_qs(location.query)["next"] == ["/admin/login/"]


def test_an_admin_signs_in_with_password_and_second_step(client):
    it = get_user_model().objects.create_superuser("it@example.org", PASSWORD)
    TOTP.activate(it, generate_totp_secret())
    RecoveryCodes.activate(it)

    response = sign_in(client, it.email, PASSWORD)

    assert response.status_code == 401
    assert not is_signed_in(client)
    assert client.get(reverse("admin:index")).status_code == 302

    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(it))},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)
    assert client.get(reverse("admin:index")).status_code == 200
    assert client.get(reverse("admin:testapp_account_changelist")).status_code == 200


def test_a_microsoft_sign_in_opens_the_admin(client, microsoft):
    it = get_user_model().objects.create_superuser("it@example.org", PASSWORD)

    response = microsoft.sign_in(client, email=it.email)

    assert response.status_code == 302
    assert is_signed_in(client)
    assert client.get(reverse("admin:index")).status_code == 200


def test_an_access_group_never_grants_django_admin_access(client):
    person = get_user_model().objects.create_user("boss@example.org", PASSWORD)
    services.set_access_groups(person, ["manager"])
    TOTP.activate(person, generate_totp_secret())
    RecoveryCodes.activate(person)
    sign_in(client, person.email, PASSWORD)
    client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(person))},
        content_type="application/json",
    )
    assert is_signed_in(client)

    response = client.get(reverse("admin:index"))

    assert response.status_code == 302
    response = client.get(response["Location"])
    assert response.status_code == 403


def test_the_admin_sets_a_temporary_password_through_the_service(
    it_client, it, temporary_password_events
):
    person = services.invite_account("jane.doe@example.org", ["viewer"])
    changelist = reverse("admin:testapp_account_changelist")

    response = it_client.post(
        changelist, {"action": "set_temporary_password", "_selected_action": str(person.pk)}
    )

    assert response.status_code == 200
    assert b'name="password"' in response.content
    assert not person.has_usable_password()

    response = it_client.post(
        changelist,
        {
            "action": "set_temporary_password",
            "post": "yes",
            "_selected_action": str(person.pk),
            "password": TEMP_PASSWORD,
        },
        follow=True,
    )

    assert response.status_code == 200
    assert "Temporary password set for 1 account." in response.content.decode()
    person.refresh_from_db()
    assert person.check_password(TEMP_PASSWORD)
    assert person.must_replace_password
    assert [(event["account"], event["acting_account"]) for event in temporary_password_events] == [
        (person, it)
    ]


def test_setting_a_temporary_password_refuses_a_linked_account(it_client):
    person = services.invite_account("jane.doe@example.org", ["viewer"])
    linked = services.invite_account("linked@example.org", ["viewer"])
    link_microsoft(linked, uid="uid-2")
    changelist = reverse("admin:testapp_account_changelist")

    response = it_client.post(
        changelist,
        {
            "action": "set_temporary_password",
            "post": "yes",
            "_selected_action": [str(person.pk), str(linked.pk)],
            "password": TEMP_PASSWORD,
        },
        follow=True,
    )

    assert response.status_code == 200
    content = response.content.decode()
    assert "Temporary password set for 1 account." in content
    assert "Not set for 1 account with a Microsoft link" in content
    person.refresh_from_db()
    assert person.check_password(TEMP_PASSWORD)
    linked.refresh_from_db()
    assert not linked.has_usable_password()


def test_the_admin_clears_authenticators_so_the_next_sign_in_sets_up_again(
    it_client, second_step_account
):
    changelist = reverse("admin:testapp_account_changelist")

    response = it_client.post(
        changelist,
        {"action": "clear_authenticators", "_selected_action": str(second_step_account.pk)},
        follow=True,
    )

    assert response.status_code == 200
    assert "Cleared authenticators and passkeys for 1 account." in response.content.decode()
    assert not Authenticator.objects.filter(user=second_step_account).exists()

    response = sign_in(Client(), second_step_account.email, PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]


def test_the_admin_removes_the_microsoft_link_and_the_next_sign_in_links_again(
    it_client, microsoft, link_made_events
):
    person = services.invite_account("jane.doe@example.org", ["viewer"])
    browser = Client()
    microsoft.sign_in(browser, email=person.email)
    assert SocialAccount.objects.filter(user=person, provider="microsoft").exists()
    changelist = reverse("admin:testapp_account_changelist")

    response = it_client.post(
        changelist,
        {"action": "remove_microsoft_link", "_selected_action": str(person.pk)},
        follow=True,
    )

    assert response.status_code == 200
    assert "Removed the Microsoft link from 1 account." in response.content.decode()
    assert not SocialAccount.objects.filter(user=person).exists()
    person.refresh_from_db()
    assert not person.has_usable_password()

    response = microsoft.sign_in(browser, email=person.email)

    assert response.status_code == 302
    assert is_signed_in(browser)
    assert SocialAccount.objects.filter(user=person, provider="microsoft").exists()
    assert len(link_made_events) == 2
