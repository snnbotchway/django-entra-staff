"""The Open to staff Sign-up rule: a Microsoft person with no User gets one."""

import pytest
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.test import override_settings

from django_entra_staff import services, signals
from tests.conftest import error_code, is_signed_in
from tests.testapp import variants

pytestmark = pytest.mark.django_db

OPEN_VARIANTS = [variants.OPEN_TO_STAFF_ADDING, variants.OPEN_TO_STAFF_EXCLUSIVE]


@pytest.fixture
def signup_events():
    """The signals a sign-up sends: the Access group change and the sign-up."""
    events = []
    receivers = []
    for name in ("access_groups_changed", "user_signed_up_open_to_staff"):

        def receiver(sender, signal, _name=name, **kwargs):
            events.append((_name, kwargs))

        getattr(signals, name).connect(receiver, weak=False)
        receivers.append((name, receiver))
    yield events
    for name, receiver in receivers:
        getattr(signals, name).disconnect(receiver)


def group_names(user):
    return set(user.groups.values_list("name", flat=True))


@pytest.mark.parametrize("variant", OPEN_VARIANTS)
def test_first_sign_in_makes_an_user_with_the_lowest_access_group(
    microsoft, client, signup_events, link_made_events, variant
):
    with override_settings(ENTRA_STAFF=variant):
        response = microsoft.sign_in(client, email="new.person@example.org")

    assert response.status_code == 302
    assert error_code(response) is None
    assert is_signed_in(client)
    user = get_user_model().objects.get(email="new.person@example.org")
    assert group_names(user) == {"viewer"}
    assert not user.has_usable_password()
    link = SocialAccount.objects.get(provider="microsoft", uid="uid-1")
    assert link.user == user
    assert [(name, kw["user"], kw["acting_user"]) for name, kw in signup_events] == [
        ("access_groups_changed", user, None),
        ("user_signed_up_open_to_staff", user, None),
    ]
    assert [(event["user"], event["acting_user"]) for event in link_made_events] == [(user, None)]
    group_change = signup_events[0][1]
    assert (group_change["previous_groups"], group_change["groups"]) == (
        frozenset(),
        frozenset({"viewer"}),
    )


@override_settings(ENTRA_STAFF=variants.OPEN_TO_STAFF_ADDING)
def test_a_second_sign_in_signs_in_instead_of_signing_up(microsoft, client, signup_events):
    microsoft.sign_in(client, email="new.person@example.org")
    client.logout()
    signup_events.clear()

    response = microsoft.sign_in(client, email="new.person@example.org")

    assert error_code(response) is None
    assert is_signed_in(client)
    assert get_user_model().objects.count() == 1
    assert SocialAccount.objects.filter(provider="microsoft").count() == 1
    assert signup_events == []


@override_settings(ENTRA_STAFF=variants.OPEN_TO_STAFF_ADDING)
def test_an_invited_person_still_links_instead_of_signing_up(
    microsoft, client, signup_events, link_made_events
):
    user = services.invite_user("Jane.Doe@example.org", ["viewer", "editor"])
    signup_events.clear()

    response = microsoft.sign_in(client, email="jane.doe@example.org")

    assert error_code(response) is None
    assert is_signed_in(client)
    assert get_user_model().objects.count() == 1
    user.refresh_from_db()
    assert group_names(user) == {"viewer", "editor"}
    assert not user.has_usable_password()
    assert [event["user"] for event in link_made_events] == [user]
    assert signup_events == []


@override_settings(ENTRA_STAFF=variants.OPEN_TO_STAFF_ADDING)
def test_a_microsoft_person_with_no_email_is_refused(microsoft, client, signup_events):
    response = microsoft.sign_in(client, email="")

    assert error_code(response) == "no_work_email"
    assert not is_signed_in(client)
    assert not get_user_model().objects.exists()
    assert not SocialAccount.objects.exists()
    assert signup_events == []


@override_settings(ENTRA_STAFF=variants.OPEN_TO_STAFF_ADDING)
def test_a_failing_sign_up_receiver_rolls_the_sign_up_back(microsoft, client):
    def failing_receiver(sender, **kwargs):
        raise RuntimeError("receiver failed")

    signals.user_signed_up_open_to_staff.connect(failing_receiver, weak=False)
    try:
        with pytest.raises(RuntimeError):
            microsoft.sign_in(client, email="new.person@example.org")
    finally:
        signals.user_signed_up_open_to_staff.disconnect(failing_receiver)

    assert not get_user_model().objects.exists()
    assert not SocialAccount.objects.exists()
