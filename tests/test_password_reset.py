from urllib.parse import urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core import mail

from tests.conftest import API, PASSWORD, link_microsoft

pytestmark = pytest.mark.django_db


def request_reset(client, email):
    return client.post(
        f"{API}/auth/password/request", {"email": email}, content_type="application/json"
    )


def reset_key_from_mail():
    url = next(line for line in mail.outbox[0].body.splitlines() if line.startswith("http"))
    return urlparse(url).path.rpartition("/")[2]


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def test_a_reset_email_is_sent_to_an_account_with_a_password(client, account):
    response = request_reset(client, account.email)

    assert response.status_code == 200
    assert [message.to for message in mail.outbox] == [[account.email]]


def test_no_reset_email_for_an_account_without_a_password(client):
    get_user_model().objects.create_user("jane.doe@example.org")

    response = request_reset(client, "jane.doe@example.org")

    assert response.status_code == 200
    assert not mail.outbox


def test_no_reset_email_for_a_linked_account_even_with_a_password(client, account):
    link_microsoft(account)

    response = request_reset(client, account.email)

    assert response.status_code == 200
    assert not mail.outbox


def test_the_reset_request_answers_the_same_way_whatever_the_email(client):
    get_user_model().objects.create_user("has.password@example.org", PASSWORD)
    linked = get_user_model().objects.create_user("linked@example.org", PASSWORD)
    link_microsoft(linked, uid="uid-2")

    responses = [
        request_reset(client, email)
        for email in ("has.password@example.org", "linked@example.org", "nobody@example.org")
    ]

    assert all(response.json() == {"status": 200} for response in responses)
