import pytest
from django.core.cache import cache


@pytest.fixture(autouse=True)
def _clear_cache():
    """Allauth's attempt limits live in the cache."""
    cache.clear()
