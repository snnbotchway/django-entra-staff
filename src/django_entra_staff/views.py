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
from allauth.headless.internal.restkit.response import ErrorResponse
from allauth.headless.mfa.inputs import ActivateTOTPInput, AddWebAuthnInput
from allauth.headless.mfa.views import ManageTOTPView, ManageWebAuthnView
from allauth.mfa import signals
from allauth.mfa.adapter import get_adapter as get_mfa_adapter
from allauth.mfa.base.internal.flows import post_authentication
from allauth.mfa.internal.flows.add import validate_can_add_authenticator
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, clear_totp_secret, get_totp_secret
from allauth.mfa.utils import is_mfa_enabled
from allauth.mfa.webauthn.internal.auth import WebAuthn, begin_registration
from django.core.exceptions import ValidationError
from django.db import transaction

from .stages import SecondStepSetupStage

SECOND_STEP_TYPES = [Authenticator.Type.TOTP, Authenticator.Type.WEBAUTHN]


class SecondStepSetupView(AuthenticationStageAPIView):
    stage_class = SecondStepSetupStage
    input_class = {"POST": ActivateTOTPInput}

    def handle(self, request, *args, **kwargs):
        self.stage = LoginStageController.enter(request, self.stage_class.key)
        if self.stage and is_mfa_enabled(self.stage.login.user, SECOND_STEP_TYPES):
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


class SecondStepWebAuthnSetupView(AuthenticationStageAPIView):
    stage_class = SecondStepSetupStage
    input_class = {"POST": AddWebAuthnInput}

    def handle(self, request, *args, **kwargs):
        self.stage = LoginStageController.enter(request, self.stage_class.key)
        if self.stage and is_mfa_enabled(self.stage.login.user, SECOND_STEP_TYPES):
            return ConflictResponse(request)
        return super().handle(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        creation_options = begin_registration(self.stage.login.user, passwordless=False)
        return APIResponse(request, data={"creation_options": creation_options})

    def post(self, request, *args, **kwargs):
        try:
            validate_can_add_authenticator(self.stage.login.user)
        except ValidationError as error:
            return ErrorResponse(request, status=HTTPStatus.CONFLICT, exception=error)
        recovery_codes = activate_passkey_second_step(
            request,
            self.stage.login.user,
            name=self.input.cleaned_data["name"],
            credential=self.input.cleaned_data["credential"],
        )
        self.stage.exit()
        return SecondStepSetupResponse(request, recovery_codes)

    def get_input_kwargs(self):
        return {"user": self.stage.login.user}


def activate_second_step(request, user, secret):
    with transaction.atomic():
        totp_auth = TOTP.activate(user, secret).instance
        clear_totp_secret(request)
        recovery_codes = _activate_recovery_codes(request, user, [totp_auth])
    get_account_adapter(request).send_notification_mail("mfa/email/totp_activated", user)
    post_authentication(request, totp_auth)
    return recovery_codes.get_unused_codes()


def activate_passkey_second_step(request, user, name, credential):
    with transaction.atomic():
        webauthn_auth = WebAuthn.add(user, name, credential).instance
        recovery_codes = _activate_recovery_codes(request, user, [webauthn_auth])
    get_account_adapter(request).send_notification_mail("mfa/email/webauthn_added", user)
    post_authentication(request, webauthn_auth)
    return recovery_codes.get_unused_codes()


def _activate_recovery_codes(request, user, added):
    """Recovery codes come with the first Second step, whichever kind it is."""
    with transaction.atomic():
        had_recovery_codes = Authenticator.objects.filter(
            user=user, type=Authenticator.Type.RECOVERY_CODES
        ).exists()
        recovery_codes = RecoveryCodes.activate(user)

        def on_commit():
            announced = [*added]
            if not had_recovery_codes:
                announced.append(recovery_codes.instance)
            for authenticator in announced:
                signals.authenticator_added.send(
                    sender=Authenticator,
                    request=request,
                    user=user,
                    authenticator=authenticator,
                )

        transaction.on_commit(on_commit)
    return recovery_codes


def _removes_last_second_step(user, authenticators):
    remaining = (
        Authenticator.objects.filter(user=user)
        .exclude(type=Authenticator.Type.RECOVERY_CODES)
        .exclude(pk__in=[authenticator.pk for authenticator in authenticators])
    )
    return not remaining.exists()


def _cannot_delete_response(request):
    error = get_mfa_adapter().validation_error("cannot_delete_authenticator")
    return ErrorResponse(request, status=HTTPStatus.CONFLICT, exception=error)


class GuardedManageWebAuthnView(ManageWebAuthnView):
    """allauth's passkey management, refusing to remove the last Second step."""

    def delete(self, request, *args, **kwargs):
        if _removes_last_second_step(request.user, self.input.cleaned_data["authenticators"]):
            return _cannot_delete_response(request)
        return super().delete(request, *args, **kwargs)


class GuardedManageTOTPView(ManageTOTPView):
    """allauth's authenticator management, refusing to remove the last Second step."""

    def delete(self, request, *args, **kwargs):
        authenticator = self._get_authenticator()
        if authenticator and _removes_last_second_step(request.user, [authenticator]):
            return _cannot_delete_response(request)
        return super().delete(request, *args, **kwargs)


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
