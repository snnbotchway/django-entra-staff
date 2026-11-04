from django.apps import AppConfig
from django.conf import settings
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

        if "django.contrib.admin" in settings.INSTALLED_APPS:
            from allauth.account.decorators import secure_admin_login
            from django.contrib import admin

            # The admin sign-in goes through the same allauth flows as the App
            # (Microsoft sign-in, or password plus the Second step), so the
            # admin is not a weaker way in.
            admin.site.login = secure_admin_login(admin.site.login)
