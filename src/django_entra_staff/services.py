"""The public Python API for changing Users. Screens, commands and tests all use these.

Each function enforces the package's rules, raises `StaffError` with a stable `ErrorCode` when
it refuses, and sends its signal (see `signals`) once the change is saved. Only
`set_temporary_password` takes a password — the Temporary password IT hands out; no function
returns password data, and none of them touches Django admin access.

`acting_user` is the User making the change; it is only carried to the signals.
"""

from collections.abc import Iterable

from allauth.mfa.models import Authenticator
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction

from . import signals
from .conf import SETTING_NAME, GroupMode, get_settings
from .errors import ErrorCode, StaffError

GroupNames = str | Iterable[str]


def _names(groups: GroupNames) -> frozenset[str]:
    return frozenset([groups] if isinstance(groups, str) else groups)


def _require_declared(names: Iterable[str]) -> None:
    undeclared = sorted(set(names) - set(get_settings().access_groups))
    if undeclared:
        raise StaffError(
            ErrorCode.UNDECLARED_ACCESS_GROUP,
            f"Access groups not declared in {SETTING_NAME}: {', '.join(undeclared)}.",
        )


def _held_groups(user) -> frozenset[str]:
    declared = get_settings().access_groups
    return frozenset(user.groups.filter(name__in=declared).values_list("name", flat=True))


def _check_shape(names: frozenset[str]) -> None:
    _require_declared(names)
    if get_settings().group_mode == GroupMode.EXCLUSIVE and len(names) != 1:
        raise StaffError(
            ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP,
            "Access groups are exclusive: a User holds exactly one.",
        )


def _replace_groups(user, names: frozenset[str], acting_user) -> None:
    previous = _held_groups(user)
    if names == previous:
        return
    user.groups.remove(*user.groups.filter(name__in=previous))
    user.groups.add(*(Group.objects.get_or_create(name=name)[0] for name in names))
    signals.access_groups_changed.send(
        sender=type(user),
        user=user,
        acting_user=acting_user,
        previous_groups=previous,
        groups=names,
    )


@transaction.atomic
def invite_user(email: str, access_groups: GroupNames, *, acting_user=None):
    """Make a User for `email` with `access_groups` and no password, and return it.

    The person then signs in with Microsoft sign-in, which links by this email.
    """
    names = _names(access_groups)
    _check_shape(names)
    model = get_user_model()
    if model.objects.filter(email__iexact=email).exists():
        raise StaffError(ErrorCode.USER_EXISTS, "A User with this email already exists.")
    user = model.objects.create_user(email)
    _replace_groups(user, names, acting_user)
    return user


@transaction.atomic
def set_access_groups(user, access_groups: GroupNames, *, acting_user=None) -> None:
    """Make `access_groups` the User's Access groups, replacing the ones it held.

    Django groups the App declares no Access group for are left alone.
    """
    names = _names(access_groups)
    _check_shape(names)
    _replace_groups(user, names, acting_user)


def _microsoft_links(user):
    # Microsoft is the only provider an App uses, so every social account is the
    # Microsoft link, whatever `provider_id` the App's Microsoft app is stored under.
    return SocialAccount.objects.filter(user=user)


def has_microsoft_link(user) -> bool:
    """Whether the User has a Microsoft link, which rules out any password (ADR 0002)."""
    return _microsoft_links(user).exists()


def _set_active(user, active: bool, signal, acting_user) -> None:
    with transaction.atomic():
        if user.is_active == active:
            return
        user.is_active = active
        user.save(update_fields=["is_active"])
        signal.send(sender=type(user), user=user, acting_user=acting_user)


def block_user(user, *, acting_user=None) -> None:
    """Stop the User signing in. Blocking a blocked User does nothing."""
    _set_active(user, False, signals.user_blocked, acting_user)


def unblock_user(user, *, acting_user=None) -> None:
    """Let a blocked User sign in again. Unblocking an active User does nothing."""
    _set_active(user, True, signals.user_unblocked, acting_user)


@transaction.atomic
def set_temporary_password(user, password: str, *, acting_user=None) -> None:
    """Give the User a Temporary password the person must replace at their next
    Password sign-in."""
    if has_microsoft_link(user):
        raise StaffError(
            ErrorCode.MICROSOFT_LINKED,
            "A User with a Microsoft link cannot get a Temporary password.",
        )
    user.set_password(password)
    user.must_replace_password = True
    user.save(update_fields=["password", "must_replace_password"])
    signals.temporary_password_set.send(sender=type(user), user=user, acting_user=acting_user)


@transaction.atomic
def clear_authenticators(user, *, acting_user=None) -> bool:
    """Remove the User's authenticator, passkeys and recovery codes, so the
    person sets up a new Second step at their next Password sign-in.

    Returns whether anything was removed; the signal is sent only then.
    """
    removed = Authenticator.objects.filter(user=user).delete()[0]
    if not removed:
        return False
    signals.authenticators_cleared.send(sender=type(user), user=user, acting_user=acting_user)
    return True


@transaction.atomic
def remove_microsoft_link(user, *, acting_user=None) -> bool:
    """Remove the User's Microsoft link, so the next Microsoft sign-in links
    again by email.

    The User keeps no password: the person signs in through Microsoft sign-in,
    or IT gives them a Temporary password, which is allowed once the link is gone.
    Returns whether a link was removed; the signal is sent only then.
    """
    removed = _microsoft_links(user).delete()[0]
    if not removed:
        return False
    signals.microsoft_link_removed.send(sender=type(user), user=user, acting_user=acting_user)
    return True


def has_access_group(user, access_group: str) -> bool:
    """Whether `user` holds the declared Access group. False for anyone not signed in."""
    _require_declared([access_group])
    if not user.is_authenticated:
        return False
    return user.groups.filter(name=access_group).exists()
