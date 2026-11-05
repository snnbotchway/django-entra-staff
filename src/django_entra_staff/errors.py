"""The codes the package refuses with: service errors, and the sign-in refusals the
adapters and views return in allauth's error shape."""

from enum import StrEnum


class ErrorCode(StrEnum):
    """Stable codes. Apps may match on them, so never rename or reuse a value."""

    UNDECLARED_ACCESS_GROUP = "undeclared_access_group"
    EXCLUSIVE_NEEDS_ONE_GROUP = "exclusive_needs_one_group"
    USER_EXISTS = "user_exists"
    MICROSOFT_LINKED = "microsoft_linked"


class SignInErrorCode(StrEnum):
    """Codes of the refusals the package's adapters and views add to allauth's
    error shape. Apps match on them, so never rename or reuse a value."""

    USE_MICROSOFT_SIGNIN = "use_microsoft_signin"
    USER_BLOCKED = "user_blocked"
    INVITE_ONLY = "invite_only"
    NO_WORK_EMAIL = "no_work_email"
    USER_ALREADY_LINKED = "user_already_linked"
    CONNECT_NOT_SUPPORTED = "connect_not_supported"
    DISCONNECT_NOT_SUPPORTED = "disconnect_not_supported"
    EMAIL_CHANGE_NOT_SUPPORTED = "email_change_not_supported"


class StaffError(Exception):
    """A refused request. `code` is the stable `ErrorCode`; the message is for logs."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
