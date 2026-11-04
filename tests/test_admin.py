"""The Django admin: the Account support page, its sign-in and its actions."""

import re
from urllib.parse import parse_qs, urlparse

import pytest
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import get_user_model
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
