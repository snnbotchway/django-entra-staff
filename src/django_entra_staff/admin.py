"""The Django admin for Accounts: a support page for developers and IT.

The page shows what IT needs to support a person; its actions go through the
service functions, so the admin cannot bypass the package's rules. The App
registers it for its concrete Account model.
"""

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.helpers import ACTION_CHECKBOX_NAME
from django.contrib.admin.utils import model_ngettext
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.utils.translation import gettext_lazy as _

from . import services
from .conf import MICROSOFT_PROVIDER_ID, GroupMode, get_settings
from .errors import ErrorCode, StaffError
from .stages import SECOND_STEP_TYPES


class TemporaryPasswordForm(forms.Form):
    password = forms.CharField(label=_("Temporary password"), widget=forms.PasswordInput)


REFUSALS = {
    ErrorCode.UNDECLARED_ACCESS_GROUP: _("That Access group isn't available."),
    ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP: _("Choose exactly one Access group."),
    ErrorCode.LAST_APP_ADMIN: _(
        "The last App admin can't lose the App admin group. Make someone else an App admin first."
    ),
    ErrorCode.ACCOUNT_EXISTS: _("An Account with this email already exists."),
}


class Refused(Exception):
    """A service refused a change made on a form. Raised inside the admin's transaction so
    that nothing the form changed is kept."""

    def __init__(self, error: StaffError):
        super().__init__(error.message)
        self.message = REFUSALS.get(error.code, _("That change isn't allowed."))


def held_access_groups(account) -> list[str]:
    declared = get_settings().access_groups
    held = set(account.groups.filter(name__in=declared).values_list("name", flat=True))
    return [name for name in declared if name in held]


def access_groups_field(**kwargs) -> forms.Field:
    """Several Access groups to tick, or exactly one to pick, as the App declares."""
    choices = [(name, name) for name in get_settings().access_groups]
    if get_settings().group_mode == GroupMode.EXCLUSIVE:
        return forms.ChoiceField(
            label=_("Access group"), choices=choices, widget=forms.RadioSelect, **kwargs
        )
    return forms.MultipleChoiceField(
        label=_("Access groups"), choices=choices, widget=forms.CheckboxSelectMultiple, **kwargs
    )


def chosen_groups(form) -> list[str]:
    chosen = form.cleaned_data["access_groups"]
    if isinstance(chosen, str):
        return [chosen] if chosen else []
    return list(chosen)


class AccountChangeForm(forms.ModelForm):
    """Django admin access, Access groups and blocked: the Account fields IT edits by hand."""

    access_groups = forms.Field(required=False)  # replaced per request: the App's settings decide
    blocked = forms.BooleanField(label=_("Blocked"), required=False)

    class Meta:
        fields = ("is_staff", "is_superuser")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["access_groups"] = access_groups_field(required=False)
        held = held_access_groups(self.instance)
        exclusive = get_settings().group_mode == GroupMode.EXCLUSIVE
        self.initial["access_groups"] = (held[0] if held else "") if exclusive else held
        self.initial["blocked"] = not self.instance.is_active


class InviteForm(forms.ModelForm):
    """An email and Access groups. There is never a password to set: the person signs in with
    Microsoft sign-in, which links by this email."""

    access_groups = forms.Field(required=False)  # replaced per request: the App's settings decide

    class Meta:
        fields = ("email",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        exclusive = get_settings().group_mode == GroupMode.EXCLUSIVE
        self.fields["access_groups"] = access_groups_field(
            required=exclusive,
            error_messages={"required": REFUSALS[ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP]},
        )

    def clean_email(self):
        email = self.cleaned_data["email"]
        if type(self.instance).objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(REFUSALS[ErrorCode.ACCOUNT_EXISTS], code="account_exists")
        return email


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
    actions = (
        "block_accounts",
        "unblock_accounts",
        "set_temporary_password",
        "clear_authenticators",
        "remove_microsoft_link",
    )
    fields = (
        "email",
        "is_staff",
        "is_superuser",
        "access_groups",
        "blocked",
        "microsoft_link",
        "password_status",
        "second_step_status",
        "last_sign_in",
        "date_joined",
        "groups",
    )
    readonly_fields = (
        "email",
        "microsoft_link",
        "password_status",
        "second_step_status",
        "last_sign_in",
        "date_joined",
        "groups",
    )

    def get_form(self, request, obj=None, **kwargs):
        form = InviteForm if obj is None else AccountChangeForm
        return super().get_form(request, obj, form=form, **kwargs)

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return [(None, {"fields": ("email", "access_groups")})]
        return super().get_fieldsets(request, obj)

    def get_readonly_fields(self, request, obj=None):
        return () if obj is None else super().get_readonly_fields(request, obj)

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        try:
            return super().changeform_view(request, object_id, form_url, extra_context)
        except Refused as refusal:
            self.message_user(request, refusal.message, messages.ERROR)
            return HttpResponseRedirect(request.get_full_path())

    def save_model(self, request, obj, form, change):
        if not change:
            self._invite(request, obj, form)
            return
        flags = {"is_staff", "is_superuser"}.intersection(form.changed_data)
        if flags:
            obj.save(update_fields=sorted(flags))
        try:
            if "access_groups" in form.changed_data:
                services.set_access_groups(obj, chosen_groups(form), acting_account=request.user)
            if "blocked" in form.changed_data:
                change_blocked = (
                    services.block_account
                    if form.cleaned_data["blocked"]
                    else services.unblock_account
                )
                change_blocked(obj, acting_account=request.user)
        except StaffError as error:
            raise Refused(error) from error

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .prefetch_related("groups", "socialaccount_set", "authenticator_set")
        )

    def _invite(self, request, obj, form):
        try:
            account = services.invite_account(
                form.cleaned_data["email"], chosen_groups(form), acting_account=request.user
            )
        except StaffError as error:
            raise Refused(error) from error
        # The admin carries on with the object it was given: point it at the saved Account.
        obj.pk, obj.email = account.pk, account.email
        obj._state.adding, obj._state.db = False, account._state.db

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

    @admin.action(description=_("Block the selected accounts"))
    def block_accounts(self, request, queryset):
        count = 0
        for account in queryset.filter(is_active=True):
            services.block_account(account, acting_account=request.user)
            count += 1
        self.message_user(
            request, self._counted(_("Blocked %(count)d %(items)s."), count), messages.SUCCESS
        )

    @admin.action(description=_("Unblock the selected accounts"))
    def unblock_accounts(self, request, queryset):
        count = 0
        for account in queryset.filter(is_active=False):
            services.unblock_account(account, acting_account=request.user)
            count += 1
        self.message_user(
            request, self._counted(_("Unblocked %(count)d %(items)s."), count), messages.SUCCESS
        )

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
