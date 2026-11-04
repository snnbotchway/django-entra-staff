"""The package's one settings dict, `ENTRA_STAFF`, and the rules it must follow."""

from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

SETTING_NAME = "ENTRA_STAFF"


class SignUpRule(StrEnum):
    INVITE_ONLY = "invite_only"
    OPEN_TO_STAFF = "open_to_staff"


class GroupMode(StrEnum):
    ADDING = "adding"
    EXCLUSIVE = "exclusive"


class CheckId(StrEnum):
    SETTING_NOT_A_DICT = "entra_staff.E001"
    UNKNOWN_KEY = "entra_staff.E002"
    BAD_TENANT_ID = "entra_staff.E003"
    BAD_SIGN_UP_RULE = "entra_staff.E004"
    BAD_GROUP_MODE = "entra_staff.E005"
    BAD_ACCESS_GROUPS = "entra_staff.E006"
    APP_ADMIN_GROUP_NOT_DECLARED = "entra_staff.E007"
    LOWEST_ACCESS_GROUP_NOT_DECLARED = "entra_staff.E008"
    OPEN_TO_STAFF_NEEDS_LOWEST_ACCESS_GROUP = "entra_staff.E009"
    USER_MODEL_NOT_AN_ACCOUNT = "entra_staff.E010"
    ACCOUNT_ADAPTER_NOT_THE_PACKAGES = "entra_staff.E011"
    MICROSOFT_PROVIDER_NOT_THE_PACKAGES = "entra_staff.E012"
    MICROSOFT_NEEDS_TENANT_ID = "entra_staff.E013"
    MICROSOFT_CALLBACK_NOT_THE_PACKAGES = "entra_staff.E014"
    SOCIAL_ACCOUNT_ADAPTER_NOT_THE_PACKAGES = "entra_staff.E015"
    WEBAUTHN_TYPE_NOT_ON = "entra_staff.E016"
    PASSKEY_LOGIN_ON = "entra_staff.E017"
    PASSKEY_SIGNUP_ON = "entra_staff.E018"


class Problem(NamedTuple):
    id: CheckId
    message: str


@dataclass(frozen=True)
class StaffSettings:
    tenant_id: str | None
    sign_up_rule: SignUpRule
    access_groups: tuple[str, ...]
    group_mode: GroupMode
    lowest_access_group: str | None
    app_admin_group: str


KEYS = (
    "TENANT_ID",
    "SIGN_UP_RULE",
    "ACCESS_GROUPS",
    "GROUP_MODE",
    "LOWEST_ACCESS_GROUP",
    "APP_ADMIN_GROUP",
)


def _values(enum: type[StrEnum]) -> str:
    return ", ".join(repr(member.value) for member in enum)


def _is_member(enum: type[StrEnum], value: object) -> bool:
    return isinstance(value, str) and value in {member.value for member in enum}


def validate(raw: object) -> list[Problem]:
    if not isinstance(raw, dict):
        return [Problem(CheckId.SETTING_NOT_A_DICT, f"{SETTING_NAME} must be a dict.")]

    problems = [
        Problem(CheckId.UNKNOWN_KEY, f"{SETTING_NAME} has an unknown key {key!r}.")
        for key in raw
        if key not in KEYS
    ]

    tenant_id = raw.get("TENANT_ID")
    if tenant_id is not None and not (isinstance(tenant_id, str) and tenant_id):
        problems.append(
            Problem(CheckId.BAD_TENANT_ID, "TENANT_ID must be a non-empty string or left out.")
        )

    sign_up_rule = raw.get("SIGN_UP_RULE", SignUpRule.INVITE_ONLY)
    if not _is_member(SignUpRule, sign_up_rule):
        problems.append(
            Problem(CheckId.BAD_SIGN_UP_RULE, f"SIGN_UP_RULE must be one of {_values(SignUpRule)}.")
        )

    if not _is_member(GroupMode, raw.get("GROUP_MODE", GroupMode.ADDING)):
        problems.append(
            Problem(CheckId.BAD_GROUP_MODE, f"GROUP_MODE must be one of {_values(GroupMode)}.")
        )

    groups = raw.get("ACCESS_GROUPS")
    groups_ok = (
        isinstance(groups, list | tuple)
        and len(groups) > 0
        and all(isinstance(name, str) and name for name in groups)
        and len(set(groups)) == len(groups)
    )
    if not groups_ok:
        problems.append(
            Problem(
                CheckId.BAD_ACCESS_GROUPS,
                "ACCESS_GROUPS must be a non-empty list of unique, non-empty group names.",
            )
        )
        return problems
    declared = list(groups)

    app_admin_group = raw.get("APP_ADMIN_GROUP")
    if app_admin_group not in declared:
        problems.append(
            Problem(
                CheckId.APP_ADMIN_GROUP_NOT_DECLARED,
                f"APP_ADMIN_GROUP {app_admin_group!r} must be one of ACCESS_GROUPS.",
            )
        )

    lowest = raw.get("LOWEST_ACCESS_GROUP")
    if lowest is None:
        if sign_up_rule == SignUpRule.OPEN_TO_STAFF:
            problems.append(
                Problem(
                    CheckId.OPEN_TO_STAFF_NEEDS_LOWEST_ACCESS_GROUP,
                    "SIGN_UP_RULE 'open_to_staff' needs LOWEST_ACCESS_GROUP.",
                )
            )
    elif lowest not in declared:
        problems.append(
            Problem(
                CheckId.LOWEST_ACCESS_GROUP_NOT_DECLARED,
                f"LOWEST_ACCESS_GROUP {lowest!r} must be one of ACCESS_GROUPS.",
            )
        )
    return problems


def get_settings() -> StaffSettings:
    raw = getattr(settings, SETTING_NAME, None)
    problems = validate(raw)
    if problems:
        raise ImproperlyConfigured("; ".join(problem.message for problem in problems))
    return StaffSettings(
        tenant_id=raw.get("TENANT_ID"),
        sign_up_rule=SignUpRule(raw.get("SIGN_UP_RULE", SignUpRule.INVITE_ONLY)),
        access_groups=tuple(raw["ACCESS_GROUPS"]),
        group_mode=GroupMode(raw.get("GROUP_MODE", GroupMode.ADDING)),
        lowest_access_group=raw.get("LOWEST_ACCESS_GROUP"),
        app_admin_group=raw["APP_ADMIN_GROUP"],
    )
