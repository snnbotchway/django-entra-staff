"""The Django admin for Accounts: a support page for developers and IT.

The page shows what IT needs to support a person; its actions go through the
service functions, so the admin cannot bypass the package's rules. The App
registers it for its concrete Account model.
"""

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.helpers import ACTION_CHECKBOX_NAME
from django.contrib.admin.utils import model_ngettext
from django.template.response import TemplateResponse
from django.utils.translation import gettext_lazy as _

from . import services
from .conf import MICROSOFT_PROVIDER_ID, get_settings
from .errors import ErrorCode, StaffError
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
    actions = ("set_temporary_password", "clear_authenticators", "remove_microsoft_link")
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
        return (
            super()
            .get_queryset(request)
            .prefetch_related("groups", "socialaccount_set", "authenticator_set")
        )

    @admin.display(description=_("Access groups"))
    def access_groups(self, account):
        declared = set(get_settings().access_groups)
        return ", ".join(
            sorted(group.name for group in account.groups.all() if group.name in declared)
        )

    @admin.display(description=_("Microsoft link"))
    def microsoft_link(self, account):
        # `services.has_microsoft_link` would cost a query per row; this reads
        # the prefetched links instead.
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
        held = {authenticator.type for authenticator in account.authenticator_set.all()}
        return _("Set up") if held.intersection(SECOND_STEP_TYPES) else _("Not set up")

    @admin.display(description=_("Blocked state"))
    def blocked(self, account):
        return _("Blocked") if not account.is_active else _("Active")

    @admin.display(description=_("Last sign-in"), ordering="last_login")
    def last_sign_in(self, account):
        return account.last_login

    @admin.action(description=_("Set a Temporary password"))
    def set_temporary_password(self, request, queryset):
        if not request.POST.get("post"):
            return self._temporary_password_page(request, queryset, TemporaryPasswordForm())
        form = TemporaryPasswordForm(request.POST)
        if not form.is_valid():
            return self._temporary_password_page(request, queryset, form)
        password = form.cleaned_data["password"]
        done, linked = 0, 0
        for account in queryset:
            try:
                services.set_temporary_password(account, password, acting_account=request.user)
                done += 1
            except StaffError as error:
                if error.code is not ErrorCode.MICROSOFT_LINKED:
                    raise
                linked += 1
        if done:
            self.message_user(
                request,
                self._counted(_("Temporary password set for %(count)d %(items)s."), done),
                messages.SUCCESS,
            )
        if linked:
            self.message_user(
                request,
                self._counted(
                    _(
                        "Not set for %(count)d %(items)s with a Microsoft link: they sign in"
                        " with Microsoft sign-in."
                    ),
                    linked,
                ),
                messages.WARNING,
            )

    def _temporary_password_page(self, request, queryset, form):
        context = {
            **self.admin_site.each_context(request),
            "title": _("Set a Temporary password"),
            "subtitle": None,
            "form": form,
            "queryset": queryset,
            "opts": self.model._meta,
            "action_checkbox_name": ACTION_CHECKBOX_NAME,
            "media": self.media,
        }
        request.current_app = self.admin_site.name
        return TemplateResponse(request, self.set_temporary_password_template, context)

    @admin.action(description=_("Clear authenticators and passkeys"))
    def clear_authenticators(self, request, queryset):
        count = len(queryset)
        for account in queryset:
            services.clear_authenticators(account, acting_account=request.user)
        self.message_user(
            request,
            self._counted(_("Cleared authenticators and passkeys for %(count)d %(items)s."), count),
            messages.SUCCESS,
        )

    @admin.action(description=_("Remove the Microsoft link"))
    def remove_microsoft_link(self, request, queryset):
        count = 0
        for account in queryset:
            if services.remove_microsoft_link(account, acting_account=request.user):
                count += 1
        self.message_user(
            request,
            self._counted(_("Removed the Microsoft link from %(count)d %(items)s."), count),
            messages.SUCCESS,
        )

    def _counted(self, message, count):
        return message % {"count": count, "items": model_ngettext(self.opts, count)}
