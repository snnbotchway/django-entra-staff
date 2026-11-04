"""The Django admin for Accounts: a support page for developers and IT.

The page shows what IT needs to support a person; its actions go through the
service functions, so the admin cannot bypass the package's rules. The App
registers it for its concrete Account model.
"""

from allauth.mfa.utils import is_mfa_enabled
from django import forms
from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .adapters import MICROSOFT_PROVIDER_ID
from .conf import get_settings
from .stages import SECOND_STEP_TYPES


class TemporaryPasswordForm(forms.Form):
    password = forms.CharField(label=_("Temporary password"), widget=forms.PasswordInput)


class AccountAdmin(admin.ModelAdmin):
    set_temporary_password_template = "django_entra_staff/set_temporary_password.html"

    list_display = (
        "email",
        "access_groups",
        "microsoft_link",
        "password_status",
        "second_step_status",
        "blocked",
        "last_sign_in",
    )
    ordering = ("email",)
    search_fields = ("email",)
    fields = (
        "email",
        "is_staff",
        "is_superuser",
        "access_groups",
        "microsoft_link",
        "password_status",
        "second_step_status",
        "blocked",
        "last_sign_in",
        "date_joined",
        "groups",
    )
    readonly_fields = (
        "email",
        "access_groups",
        "microsoft_link",
        "password_status",
        "second_step_status",
        "blocked",
        "last_sign_in",
        "date_joined",
        "groups",
    )

    def has_add_permission(self, request):
        """Accounts are made through `invite_account` or Open to staff, not here."""
        return False

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("groups", "socialaccount_set")

    @admin.display(description=_("Access groups"))
    def access_groups(self, account):
        declared = set(get_settings().access_groups)
        return ", ".join(
            sorted(group.name for group in account.groups.all() if group.name in declared)
        )

    @admin.display(description=_("Microsoft link"))
    def microsoft_link(self, account):
        linked = any(
            social_account.provider == MICROSOFT_PROVIDER_ID
            for social_account in account.socialaccount_set.all()
        )
        return _("Linked") if linked else _("Not linked")

    @admin.display(description=_("Password status"))
    def password_status(self, account):
        if not account.has_usable_password():
            return _("No password")
        if account.must_replace_password:
            return _("Temporary password")
        return _("Password set")

    @admin.display(description=_("Second step status"))
    def second_step_status(self, account):
        return _("Set up") if is_mfa_enabled(account, SECOND_STEP_TYPES) else _("Not set up")

    @admin.display(description=_("Blocked state"))
    def blocked(self, account):
        return _("Blocked") if not account.is_active else _("Active")

    @admin.display(description=_("Last sign-in"), ordering="last_login")
    def last_sign_in(self, account):
        return account.last_login
