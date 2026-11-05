import importlib

from allauth import app_settings as allauth_settings
from allauth.account import app_settings as account_settings
from allauth.headless import app_settings as headless_settings
from allauth.mfa import app_settings as mfa_settings
from allauth.mfa.models import Authenticator
from allauth.socialaccount import app_settings as socialaccount_settings
from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.checks import Error, register
from django.http import Http404
from django.urls import NoReverseMatch, resolve, reverse
from django.utils.module_loading import import_string

from .adapters import AccountAdapter, MFAAdapter, SocialAccountAdapter, dotted_path
from .conf import (
    MICROSOFT_NEEDS_TENANT_ID_MESSAGE,
    MICROSOFT_PROVIDER_ID,
    SETTING_NAME,
    CheckId,
    get_settings,
    validate,
)
from .models import AbstractUser
from .providers.microsoft.views import oauth2_callback
from .views import GuardedManageEmailView, GuardedManageTOTPView, GuardedManageWebAuthnView

PACKAGE_ADAPTER = dotted_path(AccountAdapter)
PACKAGE_SOCIAL_ADAPTER = dotted_path(SocialAccountAdapter)
PACKAGE_MFA_ADAPTER = dotted_path(MFAAdapter)
ALLAUTH_BACKEND = "allauth.account.auth_backends.AuthenticationBackend"
PACKAGE_MICROSOFT_APP = "django_entra_staff.providers.microsoft"
ALLAUTH_MICROSOFT_APP = "allauth.socialaccount.providers.microsoft"

# The allauth endpoints the package guards, as (url name, the package's view,
# the MFA type that mounts it or None). The package's URLs shadow allauth's, so
# resolving the allauth path must land on the package's view.
GUARDED_ENDPOINTS = (
    ("account:manage_email", GuardedManageEmailView, None),
    ("mfa:manage_totp", GuardedManageTOTPView, Authenticator.Type.TOTP),
    ("mfa:manage_webauthn", GuardedManageWebAuthnView, Authenticator.Type.WEBAUTHN),
)


def _subclass_of(setting, base):
    path = getattr(settings, setting, None)
    return path and issubclass(import_string(path), import_string(base))


def _is_allauths_backend(path) -> bool:
    try:
        return issubclass(import_string(path), import_string(ALLAUTH_BACKEND))
    except ImportError:
        return False


def _microsoft_is_set_up() -> bool:
    return PACKAGE_MICROSOFT_APP in settings.INSTALLED_APPS


def _other_provider_apps() -> list[str]:
    """Installed apps that bring a sign-in provider other than Microsoft.

    allauth registers a provider from the `provider` module of any installed
    app, not only its own, so every app is looked at the way allauth's registry
    does. allauth's own Microsoft app shares the Microsoft id; E012 refuses it.
    """
    found = []
    for app_config in apps.get_app_configs():
        module_name = f"{app_config.name}.provider"
        try:
            module = importlib.import_module(module_name)
        except ImportError as error:
            if error.name != module_name:
                raise
            continue
        provider_ids = {cls.id for cls in getattr(module, "provider_classes", [])}
        if provider_ids - {MICROSOFT_PROVIDER_ID}:
            found.append(app_config.name)
    return found


def _microsoft_callback_is_the_packages() -> bool:
    try:
        match = resolve(reverse("microsoft_callback"))
    except (NoReverseMatch, Http404):
        return False
    return match.func is oauth2_callback


def _email_authentication_is_on() -> bool:
    """Whether allauth would match a Microsoft person to a User by email on
    its own, globally or for one provider (its settings or its app's)."""
    if (
        socialaccount_settings.EMAIL_AUTHENTICATION
        or socialaccount_settings.EMAIL_AUTHENTICATION_AUTO_CONNECT
    ):
        return True
    providers = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {})
    return any(
        provider.get("EMAIL_AUTHENTICATION")
        or provider.get("APP", {}).get("settings", {}).get("email_authentication")
        for provider in providers.values()
    )


def _microsoft_app_has_another_provider_id() -> bool:
    """Whether an app set up in `SOCIALACCOUNT_PROVIDERS` for Microsoft names its
    own `provider_id`. A Microsoft app saved in the database cannot be seen here."""
    config = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {}).get(MICROSOFT_PROVIDER_ID, {})
    apps = config.get("APPS") or [config.get("APP", {})]
    return any(
        app.get("provider_id", MICROSOFT_PROVIDER_ID) != MICROSOFT_PROVIDER_ID for app in apps
    )


def _unguarded_endpoints() -> list[str]:
    """The URL names whose allauth path resolves to something other than the
    package's guarded view. An endpoint that is not mounted has nothing to
    bypass."""
    unguarded = []
    for client in headless_settings.CLIENTS:
        for name, view_class, mfa_type in GUARDED_ENDPOINTS:
            if mfa_type is not None and mfa_type not in mfa_settings.SUPPORTED_TYPES:
                continue
            urlname = f"headless:{client}:{name}"
            try:
                match = resolve(reverse(urlname))
            except (NoReverseMatch, Http404):
                continue
            if not issubclass(getattr(match.func, "view_class", object), view_class):
                unguarded.append(urlname)
    return unguarded


@register()
def check_settings(app_configs, **kwargs):
    raw = getattr(settings, SETTING_NAME, None)
    problems = validate(raw)
    errors = [Error(problem.message, id=problem.id.value) for problem in problems]

    if not issubclass(get_user_model(), AbstractUser):
        errors.append(
            Error(
                "AUTH_USER_MODEL must subclass django_entra_staff.models.AbstractUser.",
                id=CheckId.USER_MODEL_NOT_THE_PACKAGES.value,
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

    for app in _other_provider_apps():
        errors.append(
            Error(
                f"{app} must not be installed: every social account counts as the"
                " Microsoft link, so another provider's sign-in would pass as one.",
                id=CheckId.OTHER_PROVIDER_INSTALLED.value,
            )
        )

    if _microsoft_app_has_another_provider_id():
        errors.append(
            Error(
                f"The Microsoft app in SOCIALACCOUNT_PROVIDERS must keep the provider id"
                f" {MICROSOFT_PROVIDER_ID!r}: leave out its 'provider_id'.",
                id=CheckId.MICROSOFT_PROVIDER_ID_CHANGED.value,
            )
        )

    if _microsoft_is_set_up() and not problems:
        if not get_settings().tenant_id:
            errors.append(
                Error(
                    MICROSOFT_NEEDS_TENANT_ID_MESSAGE,
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
                "MFA_PASSKEY_SIGNUP_ENABLED must stay off: nobody creates a User with a passkey.",
                id=CheckId.PASSKEY_SIGNUP_ON.value,
            )
        )
    errors.extend(_allauth_path_errors())
    errors.extend(_allauth_setting_errors())
    return errors


def _allauth_path_errors():
    """Settings that open a way in, or a way to add a password, around the
    package's adapters and endpoints."""
    errors = []
    if not allauth_settings.HEADLESS_ONLY:
        errors.append(
            Error(
                "HEADLESS_ONLY must be True: allauth's own pages skip the package's"
                " sign-in and Second step guards.",
                id=CheckId.ALLAUTH_PAGES_ON.value,
            )
        )
    if not _subclass_of("MFA_ADAPTER", PACKAGE_MFA_ADAPTER):
        errors.append(
            Error(
                f"MFA_ADAPTER must be {PACKAGE_MFA_ADAPTER} or a subclass of it.",
                id=CheckId.MFA_ADAPTER_NOT_THE_PACKAGES.value,
            )
        )
    if account_settings.LOGIN_BY_CODE_ENABLED:
        errors.append(
            Error(
                "ACCOUNT_LOGIN_BY_CODE_ENABLED must stay off: an emailed code would sign"
                " in without the password, the Second step or the Microsoft link check.",
                id=CheckId.LOGIN_BY_CODE_ON.value,
            )
        )
    if account_settings.PASSWORD_RESET_BY_CODE_ENABLED:
        errors.append(
            Error(
                "ACCOUNT_PASSWORD_RESET_BY_CODE_ENABLED must stay off: the emailed-code"
                " reset skips the package's Password reset refusals.",
                id=CheckId.PASSWORD_RESET_BY_CODE_ON.value,
            )
        )
    for backend in settings.AUTHENTICATION_BACKENDS:
        if not _is_allauths_backend(backend):
            errors.append(
                Error(
                    f"AUTHENTICATION_BACKENDS must hold only {ALLAUTH_BACKEND} or a subclass of"
                    f" it, not {backend}: any other backend can check a password with no"
                    " Microsoft link check.",
                    id=CheckId.AUTHENTICATION_BACKEND_NOT_ALLAUTHS.value,
                )
            )
    return errors


def _allauth_setting_errors():
    """Settings that weaken the sign-in rules inside allauth's own flows."""
    errors = []
    if _email_authentication_is_on():
        errors.append(
            Error(
                "SOCIALACCOUNT_EMAIL_AUTHENTICATION,"
                " SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT and a provider's"
                " EMAIL_AUTHENTICATION must stay off: allauth would sign a Microsoft person"
                " in to the User with their email, before the package links it.",
                id=CheckId.EMAIL_AUTHENTICATION_ON.value,
            )
        )
    if mfa_settings.TRUST_ENABLED:
        errors.append(
            Error(
                "MFA_TRUST_ENABLED must stay off: a trusted browser would skip the Second step.",
                id=CheckId.MFA_TRUST_ON.value,
            )
        )
    if not account_settings.PREVENT_ENUMERATION:
        errors.append(
            Error(
                "ACCOUNT_PREVENT_ENUMERATION must stay on: sign-in, Password reset and the"
                " email endpoints must not tell whether an email has a User.",
                id=CheckId.PREVENT_ENUMERATION_OFF.value,
            )
        )
    if account_settings.EMAIL_VERIFICATION_MAX_CHANGE_COUNT:
        errors.append(
            Error(
                "ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_CHANGE must stay off: a person waiting"
                " to verify their email at sign-in could change it, unverified, to a"
                " colleague's, whose first Microsoft sign-in would then land in their User.",
                id=CheckId.EMAIL_CHANGE_WHILE_VERIFYING_ON.value,
            )
        )
    for urlname in _unguarded_endpoints():
        errors.append(
            Error(
                f"{urlname} must resolve to the package's view: mount"
                " django_entra_staff.urls before allauth's headless URLs, not allauth's alone.",
                id=CheckId.GUARDED_ENDPOINT_NOT_THE_PACKAGES.value,
            )
        )
    return errors
