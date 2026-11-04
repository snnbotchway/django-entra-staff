from django.apps import AppConfig
from django.db.models.signals import post_migrate


class EntraStaffConfig(AppConfig):
    name = "django_entra_staff"
    label = "entra_staff"
    verbose_name = "Staff sign-in"

    def ready(self):
        from . import checks  # noqa: F401  (registers the system checks)
        from .groups import sync_access_groups

        post_migrate.connect(
            sync_access_groups, sender=self, dispatch_uid="entra_staff.sync_access_groups"
        )
