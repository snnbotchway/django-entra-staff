from allauth.account.internal.flows.login import get_authentication_records
from allauth.account.stages import LoginStage
from allauth.core.internal.httpkit import headed_redirect_response
from allauth.mfa.models import Authenticator
from allauth.mfa.stages import AuthenticateStage as AllauthAuthenticateStage
from allauth.mfa.utils import is_mfa_enabled

SECOND_STEP_TYPES = [Authenticator.Type.TOTP, Authenticator.Type.WEBAUTHN]

# The `method` allauth records for a sign-in through a provider; allauth has no
# constant of its own for it.
SOCIAL_SIGN_IN_METHOD = "socialaccount"


class SecondStepAuthenticateStage(AllauthAuthenticateStage):
    """The Second step is a Password sign-in rule: Microsoft sign-in is never
    asked for it, because Entra already runs its own checks."""

    def _should_handle(self, request):
        if _used_social_sign_in(request, self.login.user):
            return False
        return super()._should_handle(request)


class PasswordSignInStage(LoginStage):
    """A forced step of Password sign-in. Microsoft sign-in never reaches it."""

    def handle(self):
        user = self.login.user
        if user is None or _used_social_sign_in(self.request, user) or not self.is_needed(user):
            return None, True
        return headed_redirect_response(self.urlname), True

    def is_needed(self, user) -> bool:
        raise NotImplementedError


class SecondStepSetupStage(PasswordSignInStage):
    """An Account without a Second step is taken through authenticator set-up
    before the sign-in opens it."""

    key = "second_step_setup"
    urlname = "second_step_setup"

    def is_needed(self, user):
        return not is_mfa_enabled(user, SECOND_STEP_TYPES)


class ReplacePasswordStage(PasswordSignInStage):
    """An Account with a Temporary password must choose a new one before the
    sign-in opens it."""

    key = "replace_password"
    urlname = "replace_password"

    def is_needed(self, user):
        return user.must_replace_password


def _used_social_sign_in(request, user):
    return any(
        record.get("method") == SOCIAL_SIGN_IN_METHOD
        for record in get_authentication_records(request, user)
    )
