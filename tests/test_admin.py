"""The Django admin: the Account support page, its sign-in and its actions."""

import re
from html import unescape
from urllib.parse import parse_qs, urlparse

import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, override_settings
from django.urls import reverse

from django_entra_staff import services, signals
from tests.conftest import (
    API,
    PASSWORD,
    is_signed_in,
    link_microsoft,
    sign_in,
    totp_code,
    totp_secret_of,
)
from tests.testapp import variants

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


@pytest.fixture
def sent():
    """(signal name, account, acting account) for each clear or link removal sent."""
    received = []
    watched = {
        "authenticators_cleared": signals.authenticators_cleared,
        "microsoft_link_removed": signals.microsoft_link_removed,
    }
    receivers = {}
    for name, signal in watched.items():

        def receiver(sender, name=name, **kwargs):
            received.append((name, kwargs["account"], kwargs["acting_account"]))

        receivers[name] = receiver
        signal.connect(receiver, weak=False)
    yield received
    for name, signal in watched.items():
        signal.disconnect(receivers[name])


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
    it_client, it, second_step_account, sent
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
    assert sent == [("authenticators_cleared", second_step_account, it)]

    response = sign_in(Client(), second_step_account.email, PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]


def test_the_admin_removes_the_microsoft_link_and_the_next_sign_in_links_again(
    it_client, it, microsoft, link_made_events, sent
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
    assert sent == [("microsoft_link_removed", person, it)]
    person.refresh_from_db()
    assert not person.has_usable_password()

    response = microsoft.sign_in(browser, email=person.email)

    assert response.status_code == 302
    assert is_signed_in(browser)
    assert SocialAccount.objects.filter(user=person, provider="microsoft").exists()
    assert len(link_made_events) == 2


def change_url(account):
    return reverse("admin:testapp_account_change", args=[account.pk])


def post_change(client, account, **fields):
    """Submit the change form the way a browser does: unchecked boxes are left out."""
    return client.post(change_url(account), fields, follow=True)


def held(account):
    return set(account.groups.values_list("name", flat=True))


def test_it_sets_access_groups_on_the_change_form_through_the_service(it_client, it):
    person = services.invite_account("jane.doe@example.org", ["viewer"])
    events = []

    def receiver(sender, **kwargs):
        events.append((kwargs["account"], kwargs["acting_account"], kwargs["groups"]))

    signals.access_groups_changed.connect(receiver, weak=False)
    try:
        response = post_change(it_client, person, access_groups=["editor", "manager"])
    finally:
        signals.access_groups_changed.disconnect(receiver)

    assert response.status_code == 200
    assert held(person) == {"editor", "manager"}
    assert events == [(person, it, frozenset({"editor", "manager"}))]


def test_the_change_form_offers_only_declared_access_groups(it_client):
    person = services.invite_account("jane.doe@example.org", ["viewer"])
    person.groups.add(Group.objects.create(name="payroll"))

    response = it_client.get(change_url(person))

    offered = response.context["adminform"].form.fields["access_groups"].choices
    assert [value for value, _label in offered] == ["viewer", "editor", "manager"]

    response = post_change(it_client, person, access_groups=["editor"])

    assert held(person) == {"editor", "payroll"}
    assert response.status_code == 200


@override_settings(ENTRA_STAFF=variants.INVITE_ONLY_EXCLUSIVE)
def test_exclusive_access_groups_are_picked_one_at_a_time(it_client):
    person = services.invite_account("jane.doe@example.org", ["viewer"])

    response = it_client.get(change_url(person))

    assert 'type="radio"' in response.content.decode()
    post_change(it_client, person, access_groups="editor")
    assert held(person) == {"editor"}

    response = post_change(it_client, person, access_groups="")

    assert response.status_code == 200
    assert "Choose exactly one Access group." in response.content.decode()
    assert held(person) == {"editor"}


def test_a_refused_change_shows_a_message_and_saves_nothing(it_client):
    only_admin = services.invite_account("boss@example.org", ["manager"])

    response = post_change(it_client, only_admin, access_groups=["viewer"], is_staff="on")

    assert response.status_code == 200
    assert "The last App admin can't lose the App admin group." in unescape(
        response.content.decode()
    )
    assert held(only_admin) == {"manager"}
    only_admin.refresh_from_db()
    assert not only_admin.is_staff


@pytest.fixture
def block_events():
    received = []

    def receiver(sender, signal, **kwargs):
        received.append((kwargs["account"], kwargs["acting_account"], signal))

    signals.account_blocked.connect(receiver, weak=False)
    signals.account_unblocked.connect(receiver, weak=False)
    yield received
    signals.account_blocked.disconnect(receiver)
    signals.account_unblocked.disconnect(receiver)


def test_it_blocks_and_unblocks_on_the_change_form(it_client, it, block_events):
    person = services.invite_account("jane.doe@example.org", ["viewer"])

    post_change(it_client, person, access_groups=["viewer"], blocked="on")

    person.refresh_from_db()
    assert not person.is_active
    assert block_events == [(person, it, signals.account_blocked)]

    post_change(it_client, person, access_groups=["viewer"])

    person.refresh_from_db()
    assert person.is_active
    assert block_events[1:] == [(person, it, signals.account_unblocked)]


def test_it_blocks_and_unblocks_accounts_from_the_changelist(it_client, it, block_events):
    one = services.invite_account("one@example.org", ["viewer"])
    two = services.invite_account("two@example.org", ["viewer"])
    services.block_account(two)
    block_events.clear()
    changelist = reverse("admin:testapp_account_changelist")
    selected = [str(one.pk), str(two.pk)]

    response = it_client.post(
        changelist, {"action": "block_accounts", "_selected_action": selected}, follow=True
    )

    assert "Blocked 1 account." in response.content.decode()
    assert not get_user_model().objects.filter(pk__in=selected, is_active=True).exists()
    assert block_events == [(one, it, signals.account_blocked)]

    response = it_client.post(
        changelist, {"action": "unblock_accounts", "_selected_action": selected}, follow=True
    )

    assert "Unblocked 2 accounts." in response.content.decode()
    assert get_user_model().objects.filter(pk__in=selected, is_active=True).count() == 2
