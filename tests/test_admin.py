"""The Django admin: the Account support page, its sign-in and its actions."""

import re

import pytest
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import get_user_model
from django.urls import reverse

from django_entra_staff import services
from tests.conftest import PASSWORD, link_microsoft

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
