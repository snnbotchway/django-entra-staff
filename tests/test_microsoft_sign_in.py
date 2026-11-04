import pytest
from allauth.socialaccount.models import SocialAccount

from tests.conftest import error_code, is_signed_in

pytestmark = pytest.mark.django_db

OTHER_TENANT = "22222222-2222-2222-2222-222222222222"


def test_a_token_from_another_tenant_is_refused(microsoft, client):
    response = microsoft.sign_in(client, email="jane.doe@example.org", tid=OTHER_TENANT)

    assert error_code(response) == "unknown"
    assert not is_signed_in(client)
    assert not SocialAccount.objects.exists()
