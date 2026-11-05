"""The Django admin for Accounts: Django's user admin, fitted to the package's rules.

It keeps the familiar shape of `UserAdmin` but never shows or sets a password
(ADR 0002): the add page invites by email, and Access groups, blocking and the
actions go through the service functions, so the admin cannot bypass the
package's rules and every signal is sent. The App registers it for its
concrete Account model.
"""

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.helpers import ACTION_CHECKBOX_NAME
from django.contrib.admin.utils import model_ngettext
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied
from django.template.response import TemplateResponse
from django.utils.translation import gettext_lazy as _

from . import services
from .conf import GroupMode, get_settings
from .errors import ErrorCode, StaffError
from .stages import SECOND_STEP_TYPES


class TemporaryPasswordForm(forms.Form):
    password = forms.CharField(label=_("Temporary password"), widget=forms.PasswordInput)

    def clean_password(self):
        password = self.cleaned_data["password"]
        validate_password(password)
        return password


ONE_ACCESS_GROUP = _("Choose exactly one Access group.")


class AccessGroupsForm(forms.ModelForm):
    """The `groups` field, offering only the declared Access groups. The admin saves
    them through the service functions, so Django groups the App didn't declare stay."""

    def clean_groups(self):
        groups = self.cleaned_data["groups"]
        if get_settings().group_mode == GroupMode.EXCLUSIVE and len(groups) != 1:
            raise forms.ValidationError(ONE_ACCESS_GROUP, code=ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP)
        return groups


class AccountChangeForm(AccessGroupsForm):
    class Meta:
        help_texts = {
            "is_active": _("Untick to block them from signing in."),
            "is_superuser": _("Has every Django admin permission without being given each one."),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "groups" in self.fields:
            offered = self.fields["groups"].queryset
            self.initial["groups"] = list(
                self.instance.groups.filter(pk__in=offered).values_list("pk", flat=True)
            )


class InviteForm(AccessGroupsForm):
    """An email and Access groups. There is never a password to set: the person signs in with
    Microsoft sign-in, which links by this email, or IT gives them a Temporary password."""

    class Meta:
        help_texts = {
            "email": _(
                "The email they sign in with. For Microsoft sign-in, use the email Microsoft"
                " has for them."
            ),
        }

    def clean_email(self):
        email = self.cleaned_data["email"]
        if type(self.instance).objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                _("An Account with this email already exists."), code=ErrorCode.ACCOUNT_EXISTS
            )
        return email


def _names(groups) -> list[str]:
    return [group.name for group in groups]


class AccountAdmin(UserAdmin):
    add_form_template = None
    set_temporary_password_template = "django_entra_staff/set_temporary_password.html"

    form = AccountChangeForm
    add_form = InviteForm
    fieldsets = (
        (None, {"fields": ("email",)}),
        (
            _("Permissions"),
            {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")},
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
        (_("Sign-in"), {"fields": ("microsoft_link", "password_status", "second_step_status")}),
    )
    add_fieldsets = ((None, {"classes": ("wide",), "fields": ("email", "groups")}),)
    readonly_fields = (
        "email",
        "last_login",
        "date_joined",
        "microsoft_link",
        "password_status",
        "second_step_status",
    )
    list_display = (
        "email",
        "access_groups",
        "microsoft_link",
        "password_status",
        "second_step_status",
        "is_active",
        "last_sign_in",
    )
    search_fields = ("email",)
    ordering = ("email",)
    actions = (
        "block_accounts",
        "unblock_accounts",
        "set_temporary_password",
        "clear_authenticators",
        "remove_microsoft_link",
    )

    def get_readonly_fields(self, request, obj=None):
        return () if obj is None else super().get_readonly_fields(request, obj)

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "groups":
            kwargs["queryset"] = Group.objects.filter(name__in=get_settings().access_groups)
            kwargs["label"] = _("Access groups")
            kwargs["help_text"] = ""
        return super().formfield_for_manytomany(db_field, request, **kwargs)

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        formfield = super().formfield_for_dbfield(db_field, request, **kwargs)
        if db_field.name == "groups":
            # A group added here would not be a declared Access group, so it could not be chosen.
            formfield.widget.can_add_related = False
        return formfield

    def user_change_password(self, request, id, form_url=""):
        raise PermissionDenied

    def save_form(self, request, form, change):
        if change:
            return super().save_form(request, form, change)
        return services.invite_account(
            form.cleaned_data["email"],
            _names(form.cleaned_data["groups"]),
            acting_account=request.user,
        )

    def save_model(self, request, obj, form, change):
        if not change:
            return  # `save_form` invited and saved the Account
        if "is_active" not in form.changed_data:
            obj.save()
            return
        # Save the other edits with Active as it was, so the block or unblock
        # service sees a real change: it saves the new state and sends the signal.
        active = obj.is_active
        obj.is_active = not active
        obj.save()
        change_active = services.unblock_account if active else services.block_account
        change_active(obj, acting_account=request.user)

    def save_related(self, request, form, formsets, change):
        if not change:
            return
        groups = form.cleaned_data.pop("groups", None)
        super().save_related(request, form, formsets, change)
        if groups is not None:
            services.set_access_groups(form.instance, _names(groups), acting_account=request.user)

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
        linked = bool(account.socialaccount_set.all())
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

    @admin.display(description=_("Last sign-in"), ordering="last_login")
    def last_sign_in(self, account):
        return account.last_login or self.get_empty_value_display()

    @admin.action(description=_("Block the selected Accounts"))
    def block_accounts(self, request, queryset):
        self._set_blocked(
            request,
            queryset.filter(is_active=True),
            services.block_account,
            _("Blocked %(count)d %(items)s."),
            _("All the selected Accounts were already blocked."),
        )

    @admin.action(description=_("Unblock the selected Accounts"))
    def unblock_accounts(self, request, queryset):
        self._set_blocked(
            request,
            queryset.filter(is_active=False),
            services.unblock_account,
            _("Unblocked %(count)d %(items)s."),
            _("None of the selected Accounts were blocked."),
        )

    def _set_blocked(self, request, accounts, change, done_message, nothing_message):
        count = 0
        for account in accounts:
            change(account, acting_account=request.user)
            count += 1
        self._report(request, count, done_message, nothing_message)

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
            "accounts": [(account, bool(account.socialaccount_set.all())) for account in queryset],
            "opts": self.model._meta,
            "action_checkbox_name": ACTION_CHECKBOX_NAME,
            "media": self.media,
        }
        request.current_app = self.admin_site.name
        return TemplateResponse(request, self.set_temporary_password_template, context)

    @admin.action(description=_("Clear the Second step"))
    def clear_authenticators(self, request, queryset):
        count = sum(
            services.clear_authenticators(account, acting_account=request.user)
            for account in queryset
        )
        self._report(
            request,
            count,
            _("Cleared the Second step for %(count)d %(items)s."),
            _("None of the selected Accounts had a Second step to clear."),
        )

    @admin.action(description=_("Remove the Microsoft link"))
    def remove_microsoft_link(self, request, queryset):
        count = sum(
            services.remove_microsoft_link(account, acting_account=request.user)
            for account in queryset
        )
        self._report(
            request,
            count,
            _("Removed the Microsoft link from %(count)d %(items)s."),
            _("None of the selected Accounts had a Microsoft link."),
        )

    def _report(self, request, count, done_message, nothing_message):
        """Say how many Accounts an action changed, or warn that it changed none."""
        if count:
            self.message_user(request, self._counted(done_message, count), messages.SUCCESS)
        else:
            self.message_user(request, nothing_message, messages.WARNING)

    def _counted(self, message, count):
        return message % {"count": count, "items": model_ngettext(self.opts, count)}
