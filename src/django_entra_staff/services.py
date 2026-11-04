"""The public Python API for changing Accounts. Screens, commands and tests all use these.

Each function enforces the package's rules, raises `StaffError` with a stable `ErrorCode` when
it refuses, and sends its signal (see `signals`) once the change is saved. Only
`set_temporary_password` takes a password — the Temporary password IT hands out; no function
returns password data, and none of them touches Django admin access.

`acting_account` is the Account making the change; it is only carried to the signals.
"""

from collections.abc import Iterable

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction

from . import signals
from .conf import GroupMode, get_settings
from .errors import ErrorCode, StaffError

GroupNames = str | Iterable[str]


def _names(groups: GroupNames) -> frozenset[str]:
    return frozenset([groups] if isinstance(groups, str) else groups)


def _require_declared(names: Iterable[str]) -> None:
    undeclared = sorted(set(names) - set(get_settings().access_groups))
    if undeclared:
        raise StaffError(
            ErrorCode.UNDECLARED_ACCESS_GROUP,
            f"Access groups not declared in ENTRA_STAFF: {', '.join(undeclared)}.",
        )


def _held_groups(account) -> frozenset[str]:
    declared = get_settings().access_groups
    return frozenset(account.groups.filter(name__in=declared).values_list("name", flat=True))


def _check_shape(names: frozenset[str]) -> None:
    _require_declared(names)
    if get_settings().group_mode == GroupMode.EXCLUSIVE and len(names) != 1:
        raise StaffError(
            ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP,
            "Access groups are exclusive: an Account holds exactly one.",
        )


def _check_an_app_admin_remains(account, names: frozenset[str]) -> None:
    admin_group = get_settings().app_admin_group
    if admin_group in names or not account.is_active:
        return
    # Lock the group row so two concurrent removals cannot each see the other admin still there.
    list(Group.objects.select_for_update().filter(name=admin_group))
    holders = get_user_model().objects.filter(is_active=True, groups__name=admin_group)
    if holders.filter(pk=account.pk).exists() and not holders.exclude(pk=account.pk).exists():
        raise StaffError(
            ErrorCode.LAST_APP_ADMIN,
            "The last App admin cannot lose the App admin group.",
        )


def _replace_groups(account, names: frozenset[str], acting_account) -> None:
    previous = _held_groups(account)
    if names == previous:
        return
    _check_an_app_admin_remains(account, names)
    account.groups.remove(*account.groups.filter(name__in=previous))
    account.groups.add(*(Group.objects.get_or_create(name=name)[0] for name in names))
    signals.access_groups_changed.send(
        sender=type(account),
        account=account,
        acting_account=acting_account,
        previous_groups=previous,
        groups=names,
    )


@transaction.atomic
def invite_account(email: str, access_groups: GroupNames, *, acting_account=None):
    """Make an Account for `email` with `access_groups` and no password, and return it.

    The person then signs in with Microsoft sign-in, which links by this email.
    """
    names = _names(access_groups)
    _check_shape(names)
    model = get_user_model()
    if model.objects.filter(email__iexact=email).exists():
        raise StaffError(ErrorCode.ACCOUNT_EXISTS, "An Account with this email already exists.")
    account = model.objects.create_user(email)
    _replace_groups(account, names, acting_account)
    return account


@transaction.atomic
def set_access_groups(account, access_groups: GroupNames, *, acting_account=None) -> None:
    """Make `access_groups` the Account's Access groups, replacing the ones it held.

    Django groups the App declares no Access group for are left alone.
    """
    names = _names(access_groups)
    _check_shape(names)
    _replace_groups(account, names, acting_account)


def _set_active(account, active: bool, signal, acting_account) -> None:
    with transaction.atomic():
        if account.is_active == active:
            return
        account.is_active = active
        account.save(update_fields=["is_active"])
        signal.send(sender=type(account), account=account, acting_account=acting_account)


def block_account(account, *, acting_account=None) -> None:
    """Stop the Account signing in. Blocking a blocked Account does nothing."""
    _set_active(account, False, signals.account_blocked, acting_account)


def unblock_account(account, *, acting_account=None) -> None:
    """Let a blocked Account sign in again. Unblocking an active Account does nothing."""
    _set_active(account, True, signals.account_unblocked, acting_account)


@transaction.atomic
def set_temporary_password(account, password: str, *, acting_account=None) -> None:
    """Give the Account a Temporary password the person must replace at their next
    Password sign-in."""
    if SocialAccount.objects.filter(provider="microsoft", user=account).exists():
        raise StaffError(
            ErrorCode.MICROSOFT_LINKED,
            "An Account with a Microsoft link cannot get a Temporary password.",
        )
    account.set_password(password)
    account.must_replace_password = True
    account.save(update_fields=["password", "must_replace_password"])
    signals.temporary_password_set.send(
        sender=type(account), account=account, acting_account=acting_account
    )


def has_access_group(account, access_group: str) -> bool:
    """Whether `account` holds the declared Access group. False for anyone not signed in."""
    _require_declared([access_group])
    if not account.is_authenticated:
        return False
    return account.groups.filter(name=access_group).exists()
