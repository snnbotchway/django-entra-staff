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


def test_the_test_app_passes_all_system_checks():
    call_command("check")


def staff(**changes):
    return {**INVITE_ONLY_ADDING, **changes}


@pytest.mark.parametrize("variant", variants.ALL)
def test_every_test_app_variant_is_consistent(variant):
    assert check_ids(ENTRA_STAFF=variant) == set()


def test_tenant_is_optional_so_password_sign_in_works_without_microsoft():
    without_tenant = {k: v for k, v in INVITE_ONLY_ADDING.items() if k != "TENANT_ID"}

    assert check_ids(ENTRA_STAFF=without_tenant) == set()


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
