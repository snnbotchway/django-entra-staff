from django.contrib.auth.models import Group

from .conf import get_settings


def sync_access_groups(using="default", **kwargs):
    """Create the declared Access groups that are missing. Runs after migrations."""
    for name in get_settings().access_groups:
        Group.objects.using(using).get_or_create(name=name)
