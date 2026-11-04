from allauth.account.internal.flows.login import get_authentication_records
from allauth.account.stages import LoginStage
from allauth.core.internal.httpkit import headed_redirect_response
from allauth.mfa.models import Authenticator
from allauth.mfa.stages import AuthenticateStage as AllauthAuthenticateStage
from allauth.mfa.utils import is_mfa_enabled

SECOND_STEP_TYPES = [Authenticator.Type.TOTP, Authenticator.Type.WEBAUTHN]


class SecondStepAuthenticateStage(AllauthAuthenticateStage):
    """The Second step is a Password sign-in rule: Microsoft sign-in is never
    asked for it, because Entra already runs its own checks."""

    def _should_handle(self, request):
        if _used_social_sign_in(request, self.login.user):
            return False
        return super()._should_handle(request)


class SecondStepSetupStage(LoginStage):
    """An Account without a Second step is taken through authenticator set-up
    before the sign-in opens it. Microsoft sign-in never reaches this stage."""

    key = "second_step_setup"
    urlname = "second_step_setup"

    def handle(self):
        if self.login.user is None or _used_social_sign_in(self.request, self.login.user):
            return None, True
        if is_mfa_enabled(self.login.user, SECOND_STEP_TYPES):
            return None, True
        return headed_redirect_response(self.urlname), True


def _used_social_sign_in(request, user):
    return any(
        record.get("method") == "socialaccount"
        for record in get_authentication_records(request, user)
    )
