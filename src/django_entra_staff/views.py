from http import HTTPStatus

from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.internal.flows.login import get_authentication_records
from allauth.account.stages import LoginStageController
from allauth.headless.adapter import get_adapter as get_headless_adapter
from allauth.headless.base.response import (
    APIResponse,
    BaseAuthenticationResponse,
    ConflictResponse,
)
from allauth.headless.base.views import AuthenticationStageAPIView
from allauth.headless.mfa.inputs import ActivateTOTPInput
from allauth.mfa import signals
from allauth.mfa.adapter import get_adapter as get_mfa_adapter
from allauth.mfa.base.internal.flows import post_authentication
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, clear_totp_secret, get_totp_secret
from allauth.mfa.utils import is_mfa_enabled
from django.db import transaction

from .stages import SecondStepSetupStage


class SecondStepSetupView(AuthenticationStageAPIView):
    stage_class = SecondStepSetupStage
    input_class = {"POST": ActivateTOTPInput}

    def handle(self, request, *args, **kwargs):
        self.stage = LoginStageController.enter(request, self.stage_class.key)
        if self.stage and is_mfa_enabled(self.stage.login.user, [Authenticator.Type.TOTP]):
            return ConflictResponse(request)
        return super().handle(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        user = self.stage.login.user
        secret = get_totp_secret(regenerate=True)
        totp_url = get_mfa_adapter().build_totp_url(user, secret)
        return APIResponse(request, meta={"secret": secret, "totp_url": totp_url})

    def post(self, request, *args, **kwargs):
        recovery_codes = activate_second_step(request, self.stage.login.user, self.input.secret)
        self.stage.exit()
        return SecondStepSetupResponse(request, recovery_codes)

    def get_input_kwargs(self):
        return {"user": self.stage.login.user}


def activate_second_step(request, user, secret):
    with transaction.atomic():
        totp_auth = TOTP.activate(user, secret).instance
        had_recovery_codes = Authenticator.objects.filter(
            user=user, type=Authenticator.Type.RECOVERY_CODES
        ).exists()
        recovery_codes = RecoveryCodes.activate(user)
        clear_totp_secret(request)

        def on_commit():
            added = [totp_auth]
            if not had_recovery_codes:
                added.append(recovery_codes.instance)
            for authenticator in added:
                signals.authenticator_added.send(
                    sender=Authenticator,
                    request=request,
                    user=user,
                    authenticator=authenticator,
                )

        transaction.on_commit(on_commit)
    get_account_adapter(request).send_notification_mail("mfa/email/totp_activated", user)
    post_authentication(request, totp_auth)
    return recovery_codes.get_unused_codes()


class SecondStepSetupResponse(BaseAuthenticationResponse):
    """The sign-in outcome plus the one-time recovery codes the person must keep."""

    def __init__(self, request, recovery_codes):
        user = request.user
        data = {"recovery_codes": recovery_codes}
        status = HTTPStatus.OK
        if user.is_authenticated:
            data["user"] = get_headless_adapter().serialize_user(user)
            data["methods"] = get_authentication_records(request, user)
        else:
            status = HTTPStatus.UNAUTHORIZED
            data["flows"] = self._get_flows(request, user)
        APIResponse.__init__(
            self,
            request,
            data=data,
            meta={"is_authenticated": user.is_authenticated},
            status=status,
        )
