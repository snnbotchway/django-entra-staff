from allauth.account.adapter import DefaultAccountAdapter
from allauth.mfa.adapter import DefaultMFAAdapter
from allauth.mfa.models import Authenticator
from allauth.mfa.stages import AuthenticateStage as AllauthAuthenticateStage
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.providers.base import AuthProcess
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from .conf import SignUpRule, get_settings
from .errors import SignInErrorCode as Code
from .services import has_microsoft_link, set_access_groups
from .signals import account_signed_up_open_to_staff, microsoft_link_made
from .stages import ReplacePasswordStage, SecondStepAuthenticateStage, SecondStepSetupStage


def dotted_path(cls) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


class AccountAdapter(DefaultAccountAdapter):
    error_messages = {
        **DefaultAccountAdapter.error_messages,
        Code.USE_MICROSOFT_SIGNIN: _("Use Microsoft sign-in for this account."),
        Code.EMAIL_CHANGE_NOT_SUPPORTED: _("The email address of this account cannot be changed."),
    }

    def is_open_for_signup(self, request):
        """Nobody creates their own Account with a password."""
        return False

    def authenticate(self, request, **credentials):
        user = super().authenticate(request, **credentials)
        if user is not None and has_microsoft_link(user):
            # The password was right, so the refusal can say why; a wrong
            # password keeps allauth's ordinary error, so linked Accounts do
            # not stand out.
            raise self.validation_error(Code.USE_MICROSOFT_SIGNIN)
        return user

    def clean_password(self, password, user=None):
        """Every way of adding a password (set, change, reset from a key) checks
        it here, so a linked Account never gets one back (ADR 0002)."""
        if user is not None and user.pk is not None and has_microsoft_link(user):
            raise self.validation_error(Code.USE_MICROSOFT_SIGNIN)
        return super().clean_password(password, user=user)

    def set_password(self, user, password):
        """Choosing a new password through a Password reset or a password change
        replaces a Temporary password, so the person is not asked again."""
        user.must_replace_password = False
        super().set_password(user, password)

    def send_password_reset_mail(self, user, email, context):
        if user.has_usable_password() and not has_microsoft_link(user):
            super().send_password_reset_mail(user, email, context)

    def get_login_stages(self):
        stages = super().get_login_stages()
        index = stages.index(dotted_path(AllauthAuthenticateStage))
        stages[index : index + 1] = [
            dotted_path(SecondStepAuthenticateStage),
            dotted_path(SecondStepSetupStage),
            dotted_path(ReplacePasswordStage),
        ]
        return stages


def removes_last_second_step(account, authenticators) -> bool:
    """Whether removing `authenticators` would leave the Account with only
    recovery codes, so a Password sign-in would have no Second step."""
    remaining = (
        Authenticator.objects.filter(user=account)
        .exclude(type=Authenticator.Type.RECOVERY_CODES)
        .exclude(pk__in=[authenticator.pk for authenticator in authenticators])
    )
    return not remaining.exists()


class MFAAdapter(DefaultMFAAdapter):
    def can_delete_authenticator(self, authenticator):
        if removes_last_second_step(authenticator.user, [authenticator]):
            return False
        return super().can_delete_authenticator(authenticator)


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    error_messages = {
        **DefaultSocialAccountAdapter.error_messages,
        Code.INVITE_ONLY: _("There is no account for this email address. Ask for access."),
        Code.NO_WORK_EMAIL: _(
            "Your Microsoft account has no email address. Ask IT to add one, then try again."
        ),
        Code.ACCOUNT_BLOCKED: _("This account is blocked. Ask for access."),
        Code.ACCOUNT_ALREADY_LINKED: _(
            "This email address is already linked to another Microsoft account."
        ),
        Code.CONNECT_NOT_SUPPORTED: _("A Microsoft account cannot be connected this way."),
        Code.DISCONNECT_NOT_SUPPORTED: _(
            "Your Microsoft account cannot be removed here. Ask IT to remove it."
        ),
    }

    def validate_disconnect(self, account, accounts):
        """Only IT removes a Microsoft link, through `services.remove_microsoft_link`:
        a person who removed their own could keep a password-only Account after
        leaving (ADR 0002). Every social account is the Microsoft link."""
        raise self.validation_error(Code.DISCONNECT_NOT_SUPPORTED)

    def pre_social_login(self, request, sociallogin):
        if sociallogin.state.get("process") == AuthProcess.CONNECT:
            # The Microsoft link is made at the first sign-in, by matching the
            # work email; connecting one by hand would skip that rule and the
            # password removal that comes with it.
            raise self.validation_error(Code.CONNECT_NOT_SUPPORTED)
        if sociallogin.is_existing and sociallogin.account.pk is not None:
            # The Microsoft link already exists: allauth signs this Account in.
            if not sociallogin.user.is_active:
                raise self.validation_error(Code.ACCOUNT_BLOCKED)
            return
        if sociallogin.is_existing:
            # An existing Account with no saved link: allauth's own email match
            # found it (the system check refuses the settings that turn that on).
            # It is still the first sign-in, so the package matches and links.
            account = sociallogin.user
        else:
            account = self._account_for(sociallogin)
        if account is None:
            # Nobody to link: the Sign-up rule answers.
            if get_settings().sign_up_rule is SignUpRule.OPEN_TO_STAFF:
                self._sign_up(request, sociallogin)
            return
        if has_microsoft_link(account):
            # The email match only happens when no Microsoft link exists yet, so
            # any link on the matched Account belongs to a different person.
            raise self.validation_error(Code.ACCOUNT_ALREADY_LINKED)
        if not account.is_active:
            raise self.validation_error(Code.ACCOUNT_BLOCKED)
        with transaction.atomic():
            sociallogin.connect(request, account)
            account.set_unusable_password()
            account.save(update_fields=["password"])
            microsoft_link_made.send(sender=type(account), account=account, acting_account=None)

    def _account_for(self, sociallogin):
        """The one Account whose email matches the Microsoft person's work
        email, ignoring case. Emails are unique regardless of letter case, so
        at most one Account matches."""
        email = sociallogin.user.email
        if not email:
            return None
        return get_user_model().objects.filter(email__iexact=email).first()

    def _sign_up(self, request, sociallogin):
        """Open to staff: the first Microsoft sign-in makes an Account with the
        lowest access group and links it."""
        email = sociallogin.user.email
        if not email:
            # An Account is identified by its email; without one there is
            # nobody to make an Account for.
            raise self.validation_error(Code.NO_WORK_EMAIL)
        with transaction.atomic():
            account = get_user_model().objects.create_user(email)
            sociallogin.connect(request, account)
            set_access_groups(account, get_settings().lowest_access_group)
            account_signed_up_open_to_staff.send(
                sender=type(account), account=account, acting_account=None
            )
            microsoft_link_made.send(sender=type(account), account=account, acting_account=None)

    def is_open_for_signup(self, request, sociallogin):
        """The Sign-up rule: Invite only refuses here; Open to staff makes the
        Account at the first Microsoft sign-in, so the sign-up is open."""
        if get_settings().sign_up_rule is SignUpRule.INVITE_ONLY:
            raise self.validation_error(Code.INVITE_ONLY)
        return True
