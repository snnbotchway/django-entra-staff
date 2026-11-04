from allauth.account.auth_backends import AuthenticationBackend


class StaffBackend(AuthenticationBackend):
    """An App's own subclass of allauth's backend, which the system check accepts."""
