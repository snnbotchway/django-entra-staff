"""Names come from Microsoft: filled at the first Microsoft sign-in and
refreshed at every later one."""

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from tests.conftest import error_code
from tests.testapp import variants

pytestmark = pytest.mark.django_db


def names(email):
    user = get_user_model().objects.get(email=email)
    return user.first_name, user.last_name


@override_settings(ENTRA_STAFF=variants.OPEN_TO_STAFF)
def test_open_to_staff_sign_up_takes_the_names_from_microsoft(microsoft, client):
    response = microsoft.sign_in(
        client, email="new.person@example.org", given_name="Ama", surname="Mensah"
    )

    assert error_code(response) is None
    assert names("new.person@example.org") == ("Ama", "Mensah")


def test_the_first_link_fills_an_invited_users_names(microsoft, client):
    get_user_model().objects.create_user("ama@example.org")

    microsoft.sign_in(client, email="ama@example.org", given_name="Ama", surname="Mensah")

    assert names("ama@example.org") == ("Ama", "Mensah")


def test_every_microsoft_sign_in_refreshes_the_names(microsoft, client):
    get_user_model().objects.create_user("ama@example.org")
    microsoft.sign_in(client, email="ama@example.org", given_name="Ama", surname="Mensah")
    client.logout()

    microsoft.sign_in(client, email="ama@example.org", given_name="Ama", surname="Owusu")

    assert names("ama@example.org") == ("Ama", "Owusu")


def test_a_name_microsoft_leaves_out_is_kept(microsoft, client):
    get_user_model().objects.create_user("ama@example.org", first_name="Ama", last_name="Mensah")

    microsoft.sign_in(client, email="ama@example.org", given_name=None, surname="Owusu")

    assert names("ama@example.org") == ("Ama", "Owusu")


def test_full_and_short_names_work_as_in_django():
    user = get_user_model()(email="ama@example.org", first_name="Ama", last_name="Mensah")

    assert (user.get_full_name(), user.get_short_name()) == ("Ama Mensah", "Ama")
