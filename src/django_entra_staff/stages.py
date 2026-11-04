"""The package's login stages.

Stages run for every sign-in, Microsoft sign-ins included, so each stage
decides for itself whether it applies to one: `is_social_login` tells a
stage that the sign-in already proved itself outside the App.
"""

from allauth.mfa.stages import AuthenticateStage as AllauthAuthenticateStage

MFA_AUTHENTICATE_STAGE = "allauth.mfa.stages.AuthenticateStage"


def is_social_login(login) -> bool:
    return bool(login.signal_kwargs and login.signal_kwargs.get("sociallogin"))


class SecondStepStage(AllauthAuthenticateStage):
    """allauth's MFA stage, skipped for Microsoft sign-ins: Microsoft already
    ran its own MFA and Conditional Access, so the App never asks twice."""

    def _should_handle(self, request) -> bool:
        if is_social_login(self.login):
            return False
        return super()._should_handle(request)
