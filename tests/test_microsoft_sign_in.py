import pytest
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import override_settings

from django_entra_staff import services
from django_entra_staff.conf import get_settings
from django_entra_staff.errors import ErrorCode, StaffError
from django_entra_staff.signals import microsoft_link_made
from tests.conftest import API, PASSWORD, error_code, is_signed_in

pytestmark = pytest.mark.django_db

OTHER_TENANT = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def user():
    return get_user_model().objects.create_user("Jane.Doe@example.org", PASSWORD)


def test_a_token_from_another_tenant_is_refused(microsoft, client):
    response = microsoft.sign_in(client, email="jane.doe@example.org", tid=OTHER_TENANT)

    assert error_code(response) == "unknown"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()


@pytest.mark.parametrize(
    "idp",
    [f"https://sts.windows.net/{OTHER_TENANT}/", "live.com"],
    ids=["guest-from-another-tenant", "personal-microsoft-user-guest"],
)
def test_a_guest_of_the_tenant_is_refused(microsoft, client, user, idp):
    response = microsoft.sign_in(client, email="jane.doe@example.org", idp=idp)

    assert error_code(response) == "unknown"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()


def test_a_member_whose_token_names_the_tenant_as_identity_provider_signs_in(
    microsoft, client, user
):
    tenant = get_settings().tenant_id
    idp = f"https://login.microsoftonline.com/{tenant}/v2.0"

    response = microsoft.sign_in(client, email="jane.doe@example.org", idp=idp)

    assert error_code(response) is None
    assert is_signed_in(client)


def test_first_sign_in_links_the_user_by_email_and_removes_the_password(
    microsoft, client, user, link_made_events
):
    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert response.status_code == 302
    assert error_code(response) is None
    assert is_signed_in(client)
    link = SocialAccount.objects.get(provider="microsoft", uid="uid-1")
    assert link.user == user
    user.refresh_from_db()
    assert not user.has_usable_password()
    assert [(event["user"], event["acting_user"]) for event in link_made_events] == [(user, None)]


def test_second_sign_in_uses_the_link_and_ignores_the_email(
    microsoft, client, user, link_made_events
):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")

    response = microsoft.sign_in(client, email="renamed@example.org", uid="uid-1")

    assert response.status_code == 302
    assert error_code(response) is None
    assert is_signed_in(client)
    user.refresh_from_db()
    assert user.email == "Jane.Doe@example.org"
    assert get_user_model().objects.count() == 1
    assert SocialAccount.objects.filter(provider="microsoft").count() == 1
    assert len(link_made_events) == 1


def test_an_user_already_linked_to_another_microsoft_person_is_refused(microsoft, client, user):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")
    client.logout()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-2")

    assert error_code(response) == "user_already_linked"
    assert not is_signed_in(client)
    link = SocialAccount.objects.get(provider="microsoft")
    assert link.uid == "uid-1"
    assert link.user == user


def test_invite_only_refuses_a_person_with_no_user(microsoft, client):
    response = microsoft.sign_in(client, email="new.person@example.org")

    assert error_code(response) == "invite_only"
    assert not is_signed_in(client)
    assert not get_user_model().objects.exists()
    assert not SocialAccount.objects.exists()


def test_a_blocked_user_with_a_link_is_refused(microsoft, client, user):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")
    client.logout()
    user.is_active = False
    user.save()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")

    assert error_code(response) == "user_blocked"
    assert not is_signed_in(client)


def test_a_blocked_user_without_a_link_is_refused(microsoft, client, user):
    user.is_active = False
    user.save()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")

    assert error_code(response) == "user_blocked"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()
    user.refresh_from_db()
    assert user.has_usable_password()


def test_the_link_and_the_password_removal_are_one_transaction(microsoft, client, user):
    def failing_receiver(sender, **kwargs):
        raise RuntimeError("receiver failed")

    microsoft_link_made.connect(failing_receiver, weak=False)
    try:
        with pytest.raises(RuntimeError):
            microsoft.sign_in(client, email="jane.doe@example.org")
    finally:
        microsoft_link_made.disconnect(failing_receiver)

    assert not SocialAccount.objects.exists()
    user.refresh_from_db()
    assert user.has_usable_password()


def test_connecting_a_microsoft_user_is_refused(microsoft, client, user):
    client.force_login(user)

    response = microsoft.sign_in(client, email="jane.doe@example.org", process="connect")

    assert error_code(response) == "connect_not_supported"
    assert not SocialAccount.objects.exists()
    user.refresh_from_db()
    assert user.has_usable_password()


def test_microsoft_sign_in_is_never_asked_for_the_second_step(microsoft, client, user):
    TOTP.activate(user, generate_totp_secret())

    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert error_code(response) is None
    assert is_signed_in(client)


def test_a_linked_user_cannot_give_itself_a_password(microsoft, client, user):
    microsoft.sign_in(client, email="jane.doe@example.org")

    response = client.post(
        f"{API}/account/password/change",
        {"new_password": "a brand new password"},
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "use_microsoft_signin"
    user.refresh_from_db()
    assert not user.has_usable_password()


def test_a_linked_user_cannot_remove_its_microsoft_link(microsoft, client, user):
    microsoft.sign_in(client, email="jane.doe@example.org")
    # The state a bypass would leave behind: a password next to the link.
    user.refresh_from_db()
    user.set_password(PASSWORD)
    user.save()
    client.force_login(user)

    response = client.delete(
        f"{API}/account/providers",
        {"provider": "microsoft", "account": "uid-1"},
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "disconnect_not_supported"
    assert SocialAccount.objects.filter(user=user, provider="microsoft").exists()


@pytest.fixture
def lowercase_user():
    """allauth's email match compares the lowercased address exactly, so only an
    User stored in lowercase is found by it."""
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


@pytest.fixture
def email_authentication_forced_on():
    """allauth's email authentication on, as an App could set it past the system
    check: the Microsoft email counts as verified, so allauth matches the
    User by email before the package's adapter is asked."""
    providers = {
        "microsoft": {**settings.SOCIALACCOUNT_PROVIDERS["microsoft"], "VERIFIED_EMAIL": True}
    }
    with override_settings(
        SOCIALACCOUNT_EMAIL_AUTHENTICATION=True, SOCIALACCOUNT_PROVIDERS=providers
    ):
        yield


@pytest.mark.usefixtures("email_authentication_forced_on")
def test_allauths_email_match_still_links_the_user_and_removes_the_password(
    microsoft, client, lowercase_user, link_made_events
):
    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert error_code(response) is None
    assert is_signed_in(client)
    link = SocialAccount.objects.get(provider="microsoft", uid="uid-1")
    assert link.user == lowercase_user
    lowercase_user.refresh_from_db()
    assert not lowercase_user.has_usable_password()
    assert len(link_made_events) == 1


@pytest.mark.usefixtures("email_authentication_forced_on")
def test_allauths_email_match_does_not_sign_in_to_an_user_linked_to_another_person(
    microsoft, client, lowercase_user
):
    microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-1")
    client.logout()

    response = microsoft.sign_in(client, email="jane.doe@example.org", uid="uid-2")

    assert error_code(response) == "user_already_linked"
    assert not is_signed_in(client)
    assert SocialAccount.objects.get(provider="microsoft").uid == "uid-1"


@pytest.mark.usefixtures("email_authentication_forced_on")
def test_allauths_email_match_does_not_sign_in_to_a_blocked_user(microsoft, client, lowercase_user):
    lowercase_user.is_active = False
    lowercase_user.save()

    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert error_code(response) == "user_blocked"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()
    lowercase_user.refresh_from_db()
    assert lowercase_user.has_usable_password()


@pytest.mark.usefixtures("email_authentication_forced_on")
@override_settings(SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT=True)
def test_allauths_email_match_with_auto_connect_makes_one_link(
    microsoft, client, lowercase_user, link_made_events
):
    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert error_code(response) is None
    assert is_signed_in(client)
    assert SocialAccount.objects.filter(user=lowercase_user, provider="microsoft").count() == 1
    lowercase_user.refresh_from_db()
    assert not lowercase_user.has_usable_password()
    assert len(link_made_events) == 1


def test_a_link_made_under_another_provider_id_still_counts_as_the_microsoft_link(
    microsoft, client, user
):
    providers = {
        "microsoft": {
            "APP": {**settings.SOCIALACCOUNT_PROVIDERS["microsoft"]["APP"], "provider_id": "entra"}
        }
    }
    with override_settings(SOCIALACCOUNT_PROVIDERS=providers):
        microsoft.sign_in(client, email=user.email, provider="entra")
        client.logout()
        assert SocialAccount.objects.get(user=user).provider == "entra"

        with pytest.raises(StaffError) as refused:
            services.set_temporary_password(user, "temporary-pass-1")
        other_person = microsoft.sign_in(client, email=user.email, uid="uid-2", provider="entra")

    assert refused.value.code == ErrorCode.MICROSOFT_LINKED
    user.refresh_from_db()
    assert not user.has_usable_password()
    assert error_code(other_person) == "user_already_linked"
    assert SocialAccount.objects.filter(user=user).count() == 1
