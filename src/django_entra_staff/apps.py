from functools import wraps

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db.models.signals import post_migrate
from django.shortcuts import redirect


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
            from django.contrib import admin

            # The admin sign-in goes through the same allauth flows as the App
            # (Microsoft sign-in, or password plus the Second step), so the
            # admin is not a weaker way in.
            admin.site.login = secure_admin_site_login(admin.site)
            admin.site.password_change = refuse_for_microsoft_linked(admin.site.password_change)


def secure_admin_site_login(site):
    """The sign-in for an `AdminSite`: allauth's flows, and never Django's login form.

    allauth's `secure_admin_login` sends a signed-out person to the App's sign-in, but lets a
    signed-in staff User through to Django's login form, which signs in whoever's password it is
    given, with no Second step and no attempt limit. A signed-in User goes to the site's index if
    the site lets them in, and is refused otherwise.
    """
    from allauth.account.decorators import secure_admin_login

    secured = secure_admin_login(site.login)

    @wraps(site.login)
    def login(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return secured(request, *args, **kwargs)
        if site.has_permission(request):
            return redirect(f"{site.name}:index")
        raise PermissionDenied

    return login


def refuse_for_microsoft_linked(view):
    """Refuse the view to anyone with a Microsoft link.

    Django's admin password change uses its own form, not the package's
    password check, so without this a linked User that somehow has a
    password could choose a new one, against the leaver rule (ADR 0002).
    """

    @wraps(view)
    def wrapped(request, *args, **kwargs):
        from .services import has_microsoft_link  # models load after the app

        if request.user.is_authenticated and has_microsoft_link(request.user):
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped
