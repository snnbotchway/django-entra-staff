from django.apps import AppConfig


class EntraStaffConfig(AppConfig):
    name = "django_entra_staff"
    label = "entra_staff"
    verbose_name = "Staff sign-in"

    def ready(self):
        from . import checks  # noqa: F401  (registers the system checks)
