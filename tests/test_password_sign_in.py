import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

from tests.conftest import API, PASSWORD, is_signed_in, link_microsoft, sign_in

pytestmark = pytest.mark.django_db


@pytest.fixture
def user():
    return get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)


def test_wrong_password_gets_allauths_error(client, user):
    response = sign_in(client, user.email, "wrong")

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "email_password_mismatch"
    assert not is_signed_in(client)


def test_a_linked_user_is_told_to_use_microsoft_signin(client, user):
    link_microsoft(user)

    response = sign_in(client, user.email, PASSWORD)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "use_microsoft_signin"
    assert not is_signed_in(client)


def test_a_linked_user_with_a_wrong_password_gets_the_usual_error(client, user):
    link_microsoft(user)

    response = sign_in(client, user.email, "wrong")

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "email_password_mismatch"
    assert not is_signed_in(client)


def test_repeated_wrong_passwords_lock_out_even_the_right_one(client, user):
    for _ in range(5):
        sign_in(client, user.email, "wrong")

    response = sign_in(client, user.email, PASSWORD)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "too_many_login_attempts"
    assert not is_signed_in(client)


def test_blocked_user_cannot_sign_in(client, user):
    user.is_active = False
    user.save()

    sign_in(client, user.email, PASSWORD)

    assert not is_signed_in(client)


def test_nobody_can_sign_up_with_a_password(client):
    response = client.post(
        f"{API}/auth/signup",
        {"email": "new@example.org", "password": PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 403
    assert not get_user_model().objects.filter(email="new@example.org").exists()


def test_two_users_cannot_share_an_email_in_different_letter_case(user):
    with pytest.raises(IntegrityError), transaction.atomic():
        get_user_model().objects.create_user("JANE.DOE@example.org", PASSWORD)
