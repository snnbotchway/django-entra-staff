from unittest import mock

import pytest
from django.conf import settings
from django.core.management import call_command
from django.test import override_settings

from django_entra_staff.checks import check_settings
from tests.testapp import variants
from tests.testapp.variants import INVITE_ONLY_ADDING


def check_ids(**overrides):
    """Run the package's check alone, so a bad setting cannot crash another app's check."""
    with override_settings(**overrides):
        return {message.id for message in check_settings(None)}


@pytest.mark.django_db
def test_the_test_app_passes_all_system_checks():
    call_command("check")


def staff(**changes):
    return {**INVITE_ONLY_ADDING, **changes}


@pytest.mark.parametrize("variant", variants.ALL)
def test_every_test_app_variant_is_consistent(variant):
    assert check_ids(ENTRA_STAFF=variant) == set()


def test_microsoft_sign_in_needs_the_tenant_id():
    without_tenant = {k: v for k, v in INVITE_ONLY_ADDING.items() if k != "TENANT_ID"}

    assert check_ids(ENTRA_STAFF=without_tenant) == {"entra_staff.E013"}


@pytest.mark.parametrize(
    ("bad", "expected"),
    [
        ("not a dict", "entra_staff.E001"),
        (staff(COLOUR="red"), "entra_staff.E002"),
        (staff(TENANT_ID=""), "entra_staff.E003"),
        (staff(SIGN_UP_RULE="anyone"), "entra_staff.E004"),
        (staff(GROUP_MODE="sticky"), "entra_staff.E005"),
        (staff(ACCESS_GROUPS=[]), "entra_staff.E006"),
        (staff(ACCESS_GROUPS=["viewer", "viewer"]), "entra_staff.E006"),
        (staff(APP_ADMIN_GROUP="boss"), "entra_staff.E007"),
        (staff(APP_ADMIN_GROUP=None), "entra_staff.E007"),
        (staff(LOWEST_ACCESS_GROUP="guest"), "entra_staff.E008"),
        (staff(SIGN_UP_RULE="open_to_staff", LOWEST_ACCESS_GROUP=None), "entra_staff.E009"),
    ],
)
def test_inconsistent_settings_dict_is_refused(bad, expected):
    assert expected in check_ids(ENTRA_STAFF=bad)


def test_missing_settings_dict_is_refused():
    with override_settings():
        del settings.ENTRA_STAFF
        assert "entra_staff.E001" in {message.id for message in check_settings(None)}


def test_user_model_must_be_an_account():
    assert "entra_staff.E010" in check_ids(AUTH_USER_MODEL="auth.User")


@pytest.mark.parametrize("adapter", ["allauth.account.adapter.DefaultAccountAdapter", None])
def test_account_adapter_must_be_the_packages(adapter):
    assert "entra_staff.E011" in check_ids(ACCOUNT_ADAPTER=adapter)


def test_allauths_microsoft_provider_app_must_not_be_installed():
    installed = [*settings.INSTALLED_APPS, "allauth.socialaccount.providers.microsoft"]
    # Patching the setting directly: override_settings would re-run the app
    # registry, and both provider apps carry the label "microsoft".
    with mock.patch.object(settings, "INSTALLED_APPS", installed):
        assert "entra_staff.E012" in check_ids()


@pytest.mark.parametrize(
    "adapter", ["allauth.socialaccount.adapter.DefaultSocialAccountAdapter", None]
)
def test_social_account_adapter_must_be_the_packages(adapter):
    assert "entra_staff.E015" in check_ids(SOCIALACCOUNT_ADAPTER=adapter)


def test_the_microsoft_callback_must_be_the_packages():
    assert "entra_staff.E014" in check_ids(ROOT_URLCONF="tests.testapp.urls_allauth_microsoft")


def test_webauthn_type_must_be_on_so_a_passkey_can_be_the_second_step():
    types = ["recovery_codes", "totp"]

    assert "entra_staff.E016" in check_ids(MFA_SUPPORTED_TYPES=types)


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        ("MFA_PASSKEY_LOGIN_ENABLED", "entra_staff.E017"),
        ("MFA_PASSKEY_SIGNUP_ENABLED", "entra_staff.E018"),
    ],
)
def test_passwordless_passkey_settings_must_stay_off(setting, expected):
    types = ["recovery_codes", "totp", "webauthn"]

    assert expected in check_ids(**{setting: True, "MFA_SUPPORTED_TYPES": types})
