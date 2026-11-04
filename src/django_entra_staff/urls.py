from allauth.headless import app_settings as headless_settings
from allauth.headless.constants import Client
from allauth.mfa import app_settings as mfa_settings
from allauth.mfa.models import Authenticator
from django.urls import include, path

from .views import (
    GuardedManageEmailView,
    GuardedManageTOTPView,
    GuardedManageWebAuthnView,
    ReplacePasswordView,
    SecondStepSetupView,
    SecondStepWebAuthnSetupView,
)


def _client_patterns(client, setup_urlname, replace_urlname):
    """The package's own endpoints for one headless client. They shadow the
    allauth endpoints they must police, so they come before allauth's include."""
    prefix = "browser/v1" if client == Client.BROWSER else "app/v1"
    patterns = [
        path(
            f"{prefix}/auth/2fa/setup",
            SecondStepSetupView.as_api_view(client=client),
            name=setup_urlname,
        ),
        path(
            f"{prefix}/auth/password/replace",
            ReplacePasswordView.as_api_view(client=client),
            name=replace_urlname,
        ),
        path(f"{prefix}/account/email", GuardedManageEmailView.as_api_view(client=client)),
    ]
    if Authenticator.Type.WEBAUTHN in mfa_settings.SUPPORTED_TYPES:
        patterns.extend(
            [
                path(
                    f"{prefix}/auth/2fa/setup/webauthn",
                    SecondStepWebAuthnSetupView.as_api_view(client=client),
                    name=f"{setup_urlname}_webauthn",
                ),
                path(
                    f"{prefix}/account/authenticators/webauthn",
                    GuardedManageWebAuthnView.as_api_view(client=client),
                ),
            ]
        )
    if Authenticator.Type.TOTP in mfa_settings.SUPPORTED_TYPES:
        patterns.append(
            path(
                f"{prefix}/account/authenticators/totp",
                GuardedManageTOTPView.as_api_view(client=client),
            )
        )
    return patterns


urlpatterns = []
if Client.BROWSER in headless_settings.CLIENTS:
    urlpatterns.extend(_client_patterns(Client.BROWSER, "second_step_setup", "replace_password"))
if Client.APP in headless_settings.CLIENTS:
    urlpatterns.extend(
        _client_patterns(Client.APP, "second_step_setup_app", "replace_password_app")
    )
urlpatterns.append(path("", include("allauth.headless.urls")))
