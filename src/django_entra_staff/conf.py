"""The package's one settings dict, `ENTRA_STAFF`, and the rules it must follow."""

from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

SETTING_NAME = "ENTRA_STAFF"

# The id of the Microsoft provider app the package ships (the App installs it
# instead of allauth's). The Microsoft app keeps it as its `provider_id`; the
# Microsoft link is a SocialAccount row, whichever provider id it carries.
MICROSOFT_PROVIDER_ID = "microsoft"


class SignUpRule(StrEnum):
    INVITE_ONLY = "invite_only"
    OPEN_TO_STAFF = "open_to_staff"


class GroupMode(StrEnum):
    ADDING = "adding"
    EXCLUSIVE = "exclusive"


class SettingKey(StrEnum):
    """The keys of the `ENTRA_STAFF` dict."""

    TENANT_ID = "TENANT_ID"
    SIGN_UP_RULE = "SIGN_UP_RULE"
    ACCESS_GROUPS = "ACCESS_GROUPS"
    GROUP_MODE = "GROUP_MODE"
    LOWEST_ACCESS_GROUP = "LOWEST_ACCESS_GROUP"
    APP_ADMIN_GROUP = "APP_ADMIN_GROUP"


DEFAULTS = {
    SettingKey.SIGN_UP_RULE: SignUpRule.INVITE_ONLY,
    SettingKey.GROUP_MODE: GroupMode.ADDING,
}


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
    ALLAUTH_PAGES_ON = "entra_staff.E019"
    MFA_ADAPTER_NOT_THE_PACKAGES = "entra_staff.E020"
    LOGIN_BY_CODE_ON = "entra_staff.E021"
    PASSWORD_RESET_BY_CODE_ON = "entra_staff.E022"
    AUTHENTICATION_BACKEND_NOT_ALLAUTHS = "entra_staff.E023"
    EMAIL_AUTHENTICATION_ON = "entra_staff.E024"
    MFA_TRUST_ON = "entra_staff.E025"
    PREVENT_ENUMERATION_OFF = "entra_staff.E026"
    GUARDED_ENDPOINT_NOT_THE_PACKAGES = "entra_staff.E027"
    MICROSOFT_PROVIDER_ID_CHANGED = "entra_staff.E028"


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


MICROSOFT_NEEDS_TENANT_ID_MESSAGE = (
    f"Microsoft sign-in needs {SETTING_NAME}['{SettingKey.TENANT_ID}']."
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
        if key not in set(SettingKey)
    ]

    tenant_id = raw.get(SettingKey.TENANT_ID)
    if tenant_id is not None and not (isinstance(tenant_id, str) and tenant_id):
        problems.append(
            Problem(
                CheckId.BAD_TENANT_ID,
                f"{SettingKey.TENANT_ID} must be a non-empty string or left out.",
            )
        )

    sign_up_rule = raw.get(SettingKey.SIGN_UP_RULE, DEFAULTS[SettingKey.SIGN_UP_RULE])
    if not _is_member(SignUpRule, sign_up_rule):
        problems.append(
            Problem(
                CheckId.BAD_SIGN_UP_RULE,
                f"{SettingKey.SIGN_UP_RULE} must be one of {_values(SignUpRule)}.",
            )
        )

    if not _is_member(GroupMode, raw.get(SettingKey.GROUP_MODE, DEFAULTS[SettingKey.GROUP_MODE])):
        problems.append(
            Problem(
                CheckId.BAD_GROUP_MODE,
                f"{SettingKey.GROUP_MODE} must be one of {_values(GroupMode)}.",
            )
        )

    groups = raw.get(SettingKey.ACCESS_GROUPS)
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
                f"{SettingKey.ACCESS_GROUPS} must be a non-empty list of unique,"
                " non-empty group names.",
            )
        )
        return problems
    declared = list(groups)

    app_admin_group = raw.get(SettingKey.APP_ADMIN_GROUP)
    if app_admin_group not in declared:
        problems.append(
            Problem(
                CheckId.APP_ADMIN_GROUP_NOT_DECLARED,
                f"{SettingKey.APP_ADMIN_GROUP} {app_admin_group!r} must be one of"
                f" {SettingKey.ACCESS_GROUPS}.",
            )
        )

    lowest = raw.get(SettingKey.LOWEST_ACCESS_GROUP)
    if lowest is None:
        if sign_up_rule == SignUpRule.OPEN_TO_STAFF:
            problems.append(
                Problem(
                    CheckId.OPEN_TO_STAFF_NEEDS_LOWEST_ACCESS_GROUP,
                    f"{SettingKey.SIGN_UP_RULE} {SignUpRule.OPEN_TO_STAFF.value!r} needs"
                    f" {SettingKey.LOWEST_ACCESS_GROUP}.",
                )
            )
    elif lowest not in declared:
        problems.append(
            Problem(
                CheckId.LOWEST_ACCESS_GROUP_NOT_DECLARED,
                f"{SettingKey.LOWEST_ACCESS_GROUP} {lowest!r} must be one of"
                f" {SettingKey.ACCESS_GROUPS}.",
            )
        )
    return problems


def get_settings() -> StaffSettings:
    raw = getattr(settings, SETTING_NAME, None)
    problems = validate(raw)
    if problems:
        raise ImproperlyConfigured("; ".join(problem.message for problem in problems))
    return StaffSettings(
        tenant_id=raw.get(SettingKey.TENANT_ID),
        sign_up_rule=SignUpRule(
            raw.get(SettingKey.SIGN_UP_RULE, DEFAULTS[SettingKey.SIGN_UP_RULE])
        ),
        access_groups=tuple(raw[SettingKey.ACCESS_GROUPS]),
        group_mode=GroupMode(raw.get(SettingKey.GROUP_MODE, DEFAULTS[SettingKey.GROUP_MODE])),
        lowest_access_group=raw.get(SettingKey.LOWEST_ACCESS_GROUP),
        app_admin_group=raw[SettingKey.APP_ADMIN_GROUP],
    )
