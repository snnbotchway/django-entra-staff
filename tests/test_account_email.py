import pytest
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core import mail

from tests.conftest import API, PASSWORD

pytestmark = pytest.mark.django_db

COLLEAGUE = "colleague@example.org"


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def post_email(client, email):
    return client.post(f"{API}/account/email", {"email": email}, content_type="application/json")


def patch_primary(client, email):
    return client.patch(
        f"{API}/account/email", {"email": email, "primary": True}, content_type="application/json"
    )


def test_a_linked_account_cannot_add_an_email(microsoft, client, account):
    microsoft.sign_in(client, email=account.email)

    response = post_email(client, COLLEAGUE)

    assert response.status_code == 403
    assert response.json()["errors"][0]["code"] == "email_change_not_supported"
    assert not EmailAddress.objects.exists()
    assert mail.outbox == []


def test_a_linked_account_cannot_make_another_email_its_primary(microsoft, client, account):
    microsoft.sign_in(client, email=account.email)
    EmailAddress.objects.create(user=account, email=COLLEAGUE)

    response = patch_primary(client, COLLEAGUE)

    assert response.status_code == 403
    assert response.json()["errors"][0]["code"] == "email_change_not_supported"
    account.refresh_from_db()
    assert account.email == "jane.doe@example.org"


def test_an_account_with_a_password_can_still_add_an_email(client, account):
    client.force_login(account)

    response = post_email(client, "jane@example.com")

    assert response.status_code == 200
    assert EmailAddress.objects.filter(user=account, email="jane@example.com").exists()
    assert [message.to for message in mail.outbox] == [["jane@example.com"]]
