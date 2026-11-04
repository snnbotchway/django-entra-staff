from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.base import AuthProcess
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from .conf import SignUpRule, get_settings
from .signals import microsoft_link_made


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        """Nobody creates their own Account with a password."""
        return False

    def get_login_stages(self):
        stages = super().get_login_stages()
        index = stages.index("allauth.mfa.stages.AuthenticateStage")
        stages[index] = "django_entra_staff.stages.SecondStepAuthenticateStage"
        stages.insert(index + 1, "django_entra_staff.stages.SecondStepSetupStage")
        return stages


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    error_messages = {
        **DefaultSocialAccountAdapter.error_messages,
        "invite_only": _("There is no account for this email address. Ask for access."),
        "account_blocked": _("This account is blocked. Ask for access."),
        "account_already_linked": _(
            "This email address is already linked to another Microsoft account."
        ),
        "connect_not_supported": _("A Microsoft account cannot be connected this way."),
    }

    def pre_social_login(self, request, sociallogin):
        if sociallogin.state.get("process") == AuthProcess.CONNECT:
            # The Microsoft link is made at the first sign-in, by matching the
            # work email; connecting one by hand would skip that rule and the
            # password removal that comes with it.
            raise self.validation_error("connect_not_supported")
        if sociallogin.is_existing:
            # The Microsoft link already exists: allauth signs this Account in.
            if not sociallogin.user.is_active:
                raise self.validation_error("account_blocked")
            return
        account = self._account_for(sociallogin)
        if account is None:
            # Nobody to link: the Sign-up rule answers in is_open_for_signup.
            return
        if SocialAccount.objects.filter(provider="microsoft", user=account).exists():
            # The email match only happens when no Microsoft link exists yet, so
            # any link on the matched Account belongs to a different person.
            raise self.validation_error("account_already_linked")
        if not account.is_active:
            raise self.validation_error("account_blocked")
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

    def is_open_for_signup(self, request, sociallogin):
        if get_settings().sign_up_rule is SignUpRule.INVITE_ONLY:
            raise self.validation_error("invite_only")
        return super().is_open_for_signup(request, sociallogin)
