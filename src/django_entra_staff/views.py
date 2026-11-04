from http import HTTPStatus

from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.internal.flows.login import get_authentication_records
from allauth.account.stages import LoginStageController
from allauth.headless.account.views import ManageEmailView
from allauth.headless.adapter import get_adapter as get_headless_adapter
from allauth.headless.base.response import (
    APIResponse,
    BaseAuthenticationResponse,
    ConflictResponse,
)
from allauth.headless.base.views import AuthenticationStageAPIView
from allauth.headless.internal.restkit.inputs import CharField, Input
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

from .adapters import removes_last_second_step
from .errors import SignInErrorCode
from .services import has_microsoft_link
from .stages import SECOND_STEP_TYPES, ReplacePasswordStage, SecondStepSetupStage


class _SecondStepSetupBaseView(AuthenticationStageAPIView):
    """Set-up of the first Second step, refused once the Account has one."""

    stage_class = SecondStepSetupStage

    def handle(self, request, *args, **kwargs):
        self.stage = LoginStageController.enter(request, self.stage_class.key)
        if self.stage and is_mfa_enabled(self.stage.login.user, SECOND_STEP_TYPES):
            return ConflictResponse(request)
        return super().handle(request, *args, **kwargs)

    def get_input_kwargs(self):
        return {"user": self.stage.login.user}


class SecondStepSetupView(_SecondStepSetupBaseView):
    input_class = {"POST": ActivateTOTPInput}

    def get(self, request, *args, **kwargs):
        user = self.stage.login.user
        secret = get_totp_secret(regenerate=True)
        totp_url = get_mfa_adapter().build_totp_url(user, secret)
        return APIResponse(request, meta={"secret": secret, "totp_url": totp_url})

    def post(self, request, *args, **kwargs):
        recovery_codes = _activate_totp_second_step(
            request, self.stage.login.user, self.input.secret
        )
        self.stage.exit()
        return SecondStepSetupResponse(request, recovery_codes)


class SecondStepWebAuthnSetupView(_SecondStepSetupBaseView):
    input_class = {"POST": AddWebAuthnInput}

    def get(self, request, *args, **kwargs):
        creation_options = begin_registration(self.stage.login.user, passwordless=False)
        return APIResponse(request, data={"creation_options": creation_options})

    def post(self, request, *args, **kwargs):
        try:
            validate_can_add_authenticator(self.stage.login.user)
        except ValidationError as error:
            return ErrorResponse(request, status=HTTPStatus.CONFLICT, exception=error)
        recovery_codes = _activate_passkey_second_step(
            request,
            self.stage.login.user,
            name=self.input.cleaned_data["name"],
            credential=self.input.cleaned_data["credential"],
        )
        self.stage.exit()
        return SecondStepSetupResponse(request, recovery_codes)


def _activate_totp_second_step(request, user, secret):
    def add():
        totp_auth = TOTP.activate(user, secret).instance
        clear_totp_secret(request)
        return totp_auth

    return _activate_first_second_step(request, user, add, "mfa/email/totp_activated")


def _activate_passkey_second_step(request, user, name, credential):
    def add():
        return WebAuthn.add(user, name, credential).instance

    return _activate_first_second_step(request, user, add, "mfa/email/webauthn_added")


def _activate_first_second_step(request, user, add, notification_template):
    """Add the first Second step with its recovery codes, tell the person, and
    record the sign-in as authenticated by it. Returns the recovery codes."""
    with transaction.atomic():
        authenticator = add()
        recovery_codes = _activate_recovery_codes(request, user, [authenticator])
    get_account_adapter(request).send_notification_mail(notification_template, user)
    post_authentication(request, authenticator)
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


def _cannot_delete_response(request):
    error = get_mfa_adapter().validation_error("cannot_delete_authenticator")
    return ErrorResponse(request, status=HTTPStatus.CONFLICT, exception=error)


class GuardedManageWebAuthnView(ManageWebAuthnView):
    """allauth's passkey management, refusing to remove the last Second step."""

    def delete(self, request, *args, **kwargs):
        if removes_last_second_step(request.user, self.input.cleaned_data["authenticators"]):
            return _cannot_delete_response(request)
        return super().delete(request, *args, **kwargs)


class GuardedManageTOTPView(ManageTOTPView):
    """allauth's authenticator management, refusing to remove the last Second step."""

    def delete(self, request, *args, **kwargs):
        authenticator = self._get_authenticator()
        if authenticator and not get_mfa_adapter().can_delete_authenticator(authenticator):
            return _cannot_delete_response(request)
        return super().delete(request, *args, **kwargs)


class GuardedManageEmailView(ManageEmailView):
    """allauth's email management, refusing to add an address or make one primary
    for an Account with a Microsoft link, and making an unverified address
    primary for any Account.

    The Account's email is what a first Microsoft sign-in matches. Making
    another address primary rewrites it, and allauth does that for an unverified
    address when the Account has no verified one. A linked person could then take
    a colleague's address, and so could a person with a password: the colleague's
    first Microsoft sign-in would land in their Account. A person still waiting
    to verify their email at sign-in cannot change it either: allauth would
    rewrite the Account's email unverified. Listing, deleting a non-primary
    address and resending a verification stay allowed.
    """

    def post(self, request, *args, **kwargs):
        return (
            self._refuse_if_verifying_sign_in()
            or self._refuse_if_linked()
            or super().post(request, *args, **kwargs)
        )

    def patch(self, request, *args, **kwargs):
        return (
            self._refuse_if_linked()
            or self._refuse_if_unverified(self.input.cleaned_data["email"])
            or super().patch(request, *args, **kwargs)
        )

    def _refuse_if_unverified(self, address):
        if address.verified:
            return None
        error = get_account_adapter().validation_error("unverified_primary_email")
        return ErrorResponse(self.request, status=HTTPStatus.BAD_REQUEST, exception=error)

    def _refuse_if_verifying_sign_in(self):
        if self.verification_stage_process is None:
            return None
        return self._email_change_not_supported()

    def _refuse_if_linked(self):
        if not has_microsoft_link(self.user):
            return None
        return self._email_change_not_supported()

    def _email_change_not_supported(self):
        error = get_account_adapter().validation_error(SignInErrorCode.EMAIL_CHANGE_NOT_SUPPORTED)
        return ErrorResponse(self.request, status=HTTPStatus.FORBIDDEN, exception=error)


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


class ReplacePasswordInput(Input):
    new_password = CharField()

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_new_password(self):
        return get_account_adapter().clean_password(
            self.cleaned_data["new_password"], user=self.user
        )


class ReplacePasswordView(AuthenticationStageAPIView):
    stage_class = ReplacePasswordStage
    input_class = {"POST": ReplacePasswordInput}

    def post(self, request, *args, **kwargs):
        user = self.stage.login.user
        user.set_password(self.input.cleaned_data["new_password"])
        user.must_replace_password = False
        user.save(update_fields=["password", "must_replace_password"])
        return self.respond_next_stage()

    def get_input_kwargs(self):
        return {"user": self.stage.login.user}
