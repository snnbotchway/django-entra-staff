"""The Temporary password: the service that sets it and the forced replacement at sign-in."""

import pytest
from django.contrib.auth import get_user_model

from django_entra_staff import services, signals
from django_entra_staff.errors import ErrorCode, StaffError
from tests.conftest import PASSWORD

pytestmark = pytest.mark.django_db

TEMP_PASSWORD = "temporary-pass-1"


@pytest.fixture
def temporary_password_events():
    """The payloads of every temporary_password_set sent during the test."""
    received = []

    def receiver(sender, **kwargs):
        received.append(kwargs)

    signals.temporary_password_set.connect(receiver, weak=False)
    yield received
    signals.temporary_password_set.disconnect(receiver)


def test_set_temporary_password_sets_the_password_and_the_flag_together(
    temporary_password_events,
):
    account = get_user_model().objects.create_user("jane.doe@example.org")
    it = get_user_model().objects.create_superuser("it@example.org", PASSWORD)

    services.set_temporary_password(account, TEMP_PASSWORD, acting_account=it)

    account.refresh_from_db()
    assert account.check_password(TEMP_PASSWORD)
    assert account.must_replace_password
    assert [(event["account"], event["acting_account"]) for event in temporary_password_events] == [
        (account, it)
    ]


def test_set_temporary_password_refuses_an_account_with_a_microsoft_link(
    microsoft, client, temporary_password_events
):
    account = get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)
    microsoft.sign_in(client, email=account.email)
    account.refresh_from_db()

    with pytest.raises(StaffError) as refused:
        services.set_temporary_password(account, TEMP_PASSWORD)

    assert refused.value.code == ErrorCode.MICROSOFT_LINKED
    account.refresh_from_db()
    assert not account.has_usable_password()
    assert not account.must_replace_password
    assert temporary_password_events == []
