import pytest
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model

from django_entra_staff.signals import microsoft_link_made
from tests.conftest import PASSWORD, error_code, is_signed_in

pytestmark = pytest.mark.django_db

OTHER_TENANT = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def account():
    return get_user_model().objects.create_user("Jane.Doe@example.org", PASSWORD)


def test_a_token_from_another_tenant_is_refused(microsoft, client):
    response = microsoft.sign_in(client, email="jane.doe@example.org", tid=OTHER_TENANT)

    assert error_code(response) == "unknown"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()


def test_first_sign_in_links_the_account_by_email_and_removes_the_password(
    microsoft, client, account, link_made_events
):
    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert response.status_code == 302
    assert error_code(response) is None
    assert is_signed_in(client)
    link = SocialAccount.objects.get(provider="microsoft", uid="uid-1")
    assert link.user == account
    account.refresh_from_db()
    assert not account.has_usable_password()
    assert [(event["account"], event["acting_account"]) for event in link_made_events] == [
        (account, None)
    ]


def test_second_sign_in_uses_the_link_and_ignores_the_email(
    microsoft, client, account, link_made_events
):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")

    response = microsoft.sign_in(client, email="renamed@example.org", uid="uid-1")

    assert response.status_code == 302
    assert error_code(response) is None
    assert is_signed_in(client)
    account.refresh_from_db()
    assert account.email == "Jane.Doe@example.org"
    assert get_user_model().objects.count() == 1
    assert SocialAccount.objects.filter(provider="microsoft").count() == 1
    assert len(link_made_events) == 1


def test_an_account_already_linked_to_another_microsoft_person_is_refused(
    microsoft, client, account
):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")
    client.logout()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-2")

    assert error_code(response) == "account_already_linked"
    assert not is_signed_in(client)
    link = SocialAccount.objects.get(provider="microsoft")
    assert link.uid == "uid-1"
    assert link.user == account


def test_invite_only_refuses_a_person_with_no_account(microsoft, client):
    response = microsoft.sign_in(client, email="new.person@example.org")

    assert error_code(response) == "invite_only"
    assert not is_signed_in(client)
    assert not get_user_model().objects.exists()
    assert not SocialAccount.objects.exists()


def test_a_blocked_account_with_a_link_is_refused(microsoft, client, account):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")
    client.logout()
    account.is_active = False
    account.save()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")

    assert error_code(response) == "account_blocked"
    assert not is_signed_in(client)


def test_a_blocked_account_without_a_link_is_refused(microsoft, client, account):
    account.is_active = False
    account.save()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")

    assert error_code(response) == "account_blocked"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()
    account.refresh_from_db()
    assert account.has_usable_password()


def test_the_link_and_the_password_removal_are_one_transaction(microsoft, client, account):
    def failing_receiver(sender, **kwargs):
        raise RuntimeError("receiver failed")

    microsoft_link_made.connect(failing_receiver, weak=False)
    try:
        with pytest.raises(RuntimeError):
            microsoft.sign_in(client, email="jane.doe@example.org")
    finally:
        microsoft_link_made.disconnect(failing_receiver)

    assert not SocialAccount.objects.exists()
    account.refresh_from_db()
    assert account.has_usable_password()


def test_connecting_a_microsoft_account_is_refused(microsoft, client, account):
    client.force_login(account)

    response = microsoft.sign_in(client, email="jane.doe@example.org", process="connect")

    assert error_code(response) == "connect_not_supported"
    assert not SocialAccount.objects.exists()
    account.refresh_from_db()
    assert account.has_usable_password()


def test_microsoft_sign_in_is_never_asked_for_the_second_step(microsoft, client, account):
    TOTP.activate(account, generate_totp_secret())

    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert error_code(response) is None
    assert is_signed_in(client)
