"""The error the package's service functions raise when they refuse something."""

from enum import StrEnum


class ErrorCode(StrEnum):
    """Stable codes. Apps may match on them, so never rename or reuse a value."""

    UNDECLARED_ACCESS_GROUP = "undeclared_access_group"
    EXCLUSIVE_NEEDS_ONE_GROUP = "exclusive_needs_one_group"
    LAST_APP_ADMIN = "last_app_admin"
    ACCOUNT_EXISTS = "account_exists"
    MICROSOFT_LINKED = "microsoft_linked"


class StaffError(Exception):
    """A refused request. `code` is the stable `ErrorCode`; the message is for logs."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
