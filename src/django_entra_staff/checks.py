from allauth.mfa import app_settings as mfa_settings
from allauth.mfa.models import Authenticator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.checks import Error, register
from django.http import Http404
from django.urls import NoReverseMatch, resolve, reverse
from django.utils.module_loading import import_string

from .conf import SETTING_NAME, CheckId, get_settings, validate
from .models import AbstractAccount
from .providers.microsoft.views import oauth2_callback

PACKAGE_ADAPTER = "django_entra_staff.adapters.AccountAdapter"
PACKAGE_SOCIAL_ADAPTER = "django_entra_staff.adapters.SocialAccountAdapter"
PACKAGE_MICROSOFT_APP = "django_entra_staff.providers.microsoft"
ALLAUTH_MICROSOFT_APP = "allauth.socialaccount.providers.microsoft"


def _subclass_of(setting, base):
    path = getattr(settings, setting, None)
    return path and issubclass(import_string(path), import_string(base))


def _microsoft_is_set_up() -> bool:
    return PACKAGE_MICROSOFT_APP in settings.INSTALLED_APPS


def _microsoft_callback_is_the_packages() -> bool:
    try:
        match = resolve(reverse("microsoft_callback"))
    except (NoReverseMatch, Http404):
        return False
    return match.func is oauth2_callback


@register()
def check_settings(app_configs, **kwargs):
    raw = getattr(settings, SETTING_NAME, None)
    problems = validate(raw)
    errors = [Error(problem.message, id=problem.id.value) for problem in problems]

    if not issubclass(get_user_model(), AbstractAccount):
        errors.append(
            Error(
                "AUTH_USER_MODEL must subclass django_entra_staff.models.AbstractAccount.",
                id=CheckId.USER_MODEL_NOT_AN_ACCOUNT.value,
            )
        )

    if not _subclass_of("ACCOUNT_ADAPTER", PACKAGE_ADAPTER):
        errors.append(
            Error(
                f"ACCOUNT_ADAPTER must be {PACKAGE_ADAPTER} or a subclass of it.",
                id=CheckId.ACCOUNT_ADAPTER_NOT_THE_PACKAGES.value,
            )
        )

    if ALLAUTH_MICROSOFT_APP in settings.INSTALLED_APPS:
        errors.append(
            Error(
                f"Microsoft sign-in needs {PACKAGE_MICROSOFT_APP} in INSTALLED_APPS,"
                f" not {ALLAUTH_MICROSOFT_APP}: allauth's adapter never verifies the"
                " id_token's tenant.",
                id=CheckId.MICROSOFT_PROVIDER_NOT_THE_PACKAGES.value,
            )
        )

    if _microsoft_is_set_up() and not problems:
        if not get_settings().tenant_id:
            errors.append(
                Error(
                    "Microsoft sign-in needs ENTRA_STAFF['TENANT_ID'].",
                    id=CheckId.MICROSOFT_NEEDS_TENANT_ID.value,
                )
            )
        if not _microsoft_callback_is_the_packages():
            errors.append(
                Error(
                    f"The microsoft_callback URL must come from {PACKAGE_MICROSOFT_APP}.urls.",
                    id=CheckId.MICROSOFT_CALLBACK_NOT_THE_PACKAGES.value,
                )
            )
        if not _subclass_of("SOCIALACCOUNT_ADAPTER", PACKAGE_SOCIAL_ADAPTER):
            errors.append(
                Error(
                    f"SOCIALACCOUNT_ADAPTER must be {PACKAGE_SOCIAL_ADAPTER} or a subclass of it.",
                    id=CheckId.SOCIAL_ACCOUNT_ADAPTER_NOT_THE_PACKAGES.value,
                )
            )

    if Authenticator.Type.WEBAUTHN not in mfa_settings.SUPPORTED_TYPES:
        errors.append(
            Error(
                "MFA_SUPPORTED_TYPES must include 'webauthn' so a passkey can be the Second step.",
                id=CheckId.WEBAUTHN_TYPE_NOT_ON.value,
            )
        )
    if mfa_settings.PASSKEY_LOGIN_ENABLED:
        errors.append(
            Error(
                "MFA_PASSKEY_LOGIN_ENABLED must stay off: a passkey is only ever the Second step.",
                id=CheckId.PASSKEY_LOGIN_ON.value,
            )
        )
    if mfa_settings.PASSKEY_SIGNUP_ENABLED:
        errors.append(
            Error(
                "MFA_PASSKEY_SIGNUP_ENABLED must stay off: nobody creates an Account"
                " with a passkey.",
                id=CheckId.PASSKEY_SIGNUP_ON.value,
            )
        )
    return errors
