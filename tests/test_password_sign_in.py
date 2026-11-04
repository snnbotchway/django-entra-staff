import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

from tests.conftest import API, PASSWORD, is_signed_in, link_microsoft, sign_in

pytestmark = pytest.mark.django_db


@pytest.fixture
def account():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def test_wrong_password_gets_allauths_error(client, account):
    response = sign_in(client, account.email, "wrong")

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "email_password_mismatch"
    assert not is_signed_in(client)


def test_a_linked_account_is_told_to_use_microsoft_signin(client, account):
    link_microsoft(account)

    response = sign_in(client, account.email, PASSWORD)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "use_microsoft_signin"
    assert not is_signed_in(client)


def test_a_linked_account_with_a_wrong_password_gets_the_usual_error(client, account):
    link_microsoft(account)

    response = sign_in(client, account.email, "wrong")

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "email_password_mismatch"
    assert not is_signed_in(client)


def test_repeated_wrong_passwords_lock_out_even_the_right_one(client, account):
    for _ in range(5):
        sign_in(client, account.email, "wrong")

    response = sign_in(client, account.email, PASSWORD)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "too_many_login_attempts"
    assert not is_signed_in(client)


def test_blocked_account_cannot_sign_in(client, account):
    account.is_active = False
    account.save()

    sign_in(client, account.email, PASSWORD)

    assert not is_signed_in(client)


def test_nobody_can_sign_up_with_a_password(client):
    response = client.post(
        f"{API}/auth/signup",
        {"email": "new@example.org", "password": PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 403
    assert not get_user_model().objects.filter(email="new@example.org").exists()


def test_two_accounts_cannot_share_an_email_in_different_letter_case(account):
    with pytest.raises(IntegrityError), transaction.atomic():
        get_user_model().objects.create_user("JANE.DOE@example.org", PASSWORD)
