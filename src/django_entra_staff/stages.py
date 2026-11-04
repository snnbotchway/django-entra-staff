from allauth.account.internal.flows.login import get_authentication_records
from allauth.account.stages import LoginStage
from allauth.core.internal.httpkit import headed_redirect_response
from allauth.mfa.models import Authenticator
from allauth.mfa.utils import is_mfa_enabled


class SecondStepSetupStage(LoginStage):
    """An Account without a Second step is taken through authenticator set-up
    before the sign-in opens it. Microsoft sign-in never reaches this stage."""

    key = "second_step_setup"
    urlname = "second_step_setup"

    def handle(self):
        if self.login.user is None or _used_social_sign_in(self.request, self.login.user):
            return None, True
        if is_mfa_enabled(self.login.user, [Authenticator.Type.TOTP, Authenticator.Type.WEBAUTHN]):
            return None, True
        return headed_redirect_response(self.urlname), True


def _used_social_sign_in(request, user):
    return any(
        record.get("method") == "socialaccount"
        for record in get_authentication_records(request, user)
    )
