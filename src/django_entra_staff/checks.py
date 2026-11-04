from allauth.mfa import app_settings as mfa_settings
from allauth.mfa.models import Authenticator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.checks import Error, register
from django.utils.module_loading import import_string

from .conf import SETTING_NAME, CheckId, validate
from .models import AbstractAccount

PACKAGE_ADAPTER = "django_entra_staff.adapters.AccountAdapter"


@register()
def check_settings(app_configs, **kwargs):
    errors = [
        Error(problem.message, id=problem.id.value)
        for problem in validate(getattr(settings, SETTING_NAME, None))
    ]

    if not issubclass(get_user_model(), AbstractAccount):
        errors.append(
            Error(
                "AUTH_USER_MODEL must subclass django_entra_staff.models.AbstractAccount.",
                id=CheckId.USER_MODEL_NOT_AN_ACCOUNT.value,
            )
        )

    adapter = getattr(settings, "ACCOUNT_ADAPTER", None)
    if not (adapter and issubclass(import_string(adapter), import_string(PACKAGE_ADAPTER))):
        errors.append(
            Error(
                f"ACCOUNT_ADAPTER must be {PACKAGE_ADAPTER} or a subclass of it.",
                id=CheckId.ACCOUNT_ADAPTER_NOT_THE_PACKAGES.value,
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
