"""The Temporary password: the service that sets it and the forced replacement at sign-in."""

from datetime import timedelta
from unittest import mock

import pytest
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import override_settings
from django.utils import timezone

from django_entra_staff import services
from django_entra_staff.errors import ErrorCode, StaffError
from tests.conftest import (
    API,
    PASSWORD,
    is_signed_in,
    link_microsoft,
    sign_in,
    totp_code,
    totp_secret_of,
)

pytestmark = pytest.mark.django_db

TEMP_PASSWORD = "temporary-pass-1"
NEW_PASSWORD = "quiet meadow ladder seven"


@pytest.fixture
def temp_password_user():
    user = get_user_model().objects.create_user("jane.doe@example.org")
    services.set_temporary_password(user, TEMP_PASSWORD)
    return user


@pytest.fixture
def second_step(temp_password_user):
    TOTP.activate(temp_password_user, generate_totp_secret())
    RecoveryCodes.activate(temp_password_user)
    return temp_password_user


def test_set_temporary_password_sets_the_password_and_the_flag_together(
    temporary_password_events,
):
    user = get_user_model().objects.create_user("jane.doe@example.org")
    it = get_user_model().objects.create_superuser("it@example.org", PASSWORD)

    services.set_temporary_password(user, TEMP_PASSWORD, acting_user=it)

    user.refresh_from_db()
    assert user.check_password(TEMP_PASSWORD)
    assert user.must_replace_password
    assert [(event["user"], event["acting_user"]) for event in temporary_password_events] == [
        (user, it)
    ]


def test_set_temporary_password_refuses_a_user_with_a_microsoft_link(
    microsoft, client, temporary_password_events
):
    user = get_user_model().objects.create_user("jane.doe@example.org", PASSWORD)
    microsoft.sign_in(client, email=user.email)
    user.refresh_from_db()

    with pytest.raises(StaffError) as refused:
        services.set_temporary_password(user, TEMP_PASSWORD)

    assert refused.value.code == ErrorCode.MICROSOFT_LINKED
    user.refresh_from_db()
    assert not user.has_usable_password()
    assert not user.must_replace_password
    assert temporary_password_events == []


@pytest.mark.usefixtures("second_step")
def test_a_temporary_password_is_replaced_after_the_second_step(client, temp_password_user):
    response = sign_in(client, temp_password_user.email, TEMP_PASSWORD)

    assert response.status_code == 401
    assert {
        "id": "mfa_authenticate",
        "is_pending": True,
        "types": ["recovery_codes", "totp"],
    } in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(temp_password_user))},
        content_type="application/json",
    )

    assert response.status_code == 401
    assert {"id": "replace_password", "is_pending": True} in response.json()["data"]["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["data"]["user"]["email"] == temp_password_user.email
    assert is_signed_in(client)
    temp_password_user.refresh_from_db()
    assert not temp_password_user.must_replace_password
    assert temp_password_user.check_password(NEW_PASSWORD)


def test_second_step_set_up_comes_before_replacing_the_temporary_password(
    client, temp_password_user
):
    response = sign_in(client, temp_password_user.email, TEMP_PASSWORD)

    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]

    secret = client.get(f"{API}/auth/2fa/setup").json()["meta"]["secret"]
    response = client.post(
        f"{API}/auth/2fa/setup", {"code": totp_code(secret)}, content_type="application/json"
    )

    assert response.status_code == 401
    data = response.json()["data"]
    assert len(data["recovery_codes"]) > 0
    assert {"id": "replace_password", "is_pending": True} in data["flows"]
    assert not is_signed_in(client)

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)


@pytest.mark.usefixtures("second_step")
def test_the_new_password_must_pass_the_app_s_password_rules(client, temp_password_user):
    sign_in(client, temp_password_user.email, TEMP_PASSWORD)
    client.post(
        f"{API}/auth/2fa/authenticate",
        {"code": totp_code(totp_secret_of(temp_password_user))},
        content_type="application/json",
    )

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": "short"},
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["param"] == "new_password"
    assert not is_signed_in(client)
    temp_password_user.refresh_from_db()
    assert temp_password_user.must_replace_password

    response = client.post(
        f"{API}/auth/password/replace",
        {"new_password": NEW_PASSWORD},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert is_signed_in(client)


def test_a_microsoft_sign_in_is_never_asked_to_replace_a_password(
    client, microsoft, temp_password_user
):
    response = microsoft.sign_in(client, email=temp_password_user.email)

    assert response.status_code == 302
    temp_password_user.refresh_from_db()
    assert not temp_password_user.has_usable_password()
    assert temp_password_user.must_replace_password
    assert is_signed_in(client)


@pytest.fixture
def app_admin():
    return get_user_model().objects.create_user("app.admin@example.org", PASSWORD)


def test_an_app_admin_gives_a_new_person_a_temporary_password_to_share(
    client, app_admin, temporary_password_events
):
    user = services.invite_user("new.person@example.org", "viewer", acting_user=app_admin)

    password = services.give_temporary_password(user, acting_user=app_admin)

    response = sign_in(client, user.email, password)
    assert response.status_code == 401
    assert {"id": "second_step_setup", "is_pending": True} in response.json()["data"]["flows"]
    assert [(event["user"], event["acting_user"]) for event in temporary_password_events] == [
        (user, app_admin)
    ]
    assert all(password not in event.values() for event in temporary_password_events)


def _linked(user):
    link_microsoft(user)


def _chose_a_password(user):
    user.set_password(PASSWORD)
    user.save()


def _set_up_a_second_step(user):
    services.set_temporary_password(user, TEMP_PASSWORD)
    TOTP.activate(user, generate_totp_secret())


def _has_django_admin_access(user):
    user.is_staff = True
    user.save()


@pytest.mark.parametrize(
    ("make", "code"),
    [
        (_linked, "microsoft_linked"),
        (_chose_a_password, "user_in_use"),
        (_set_up_a_second_step, "user_in_use"),
        (_has_django_admin_access, "django_admin_access"),
    ],
    ids=["microsoft-link", "own-password", "second-step", "django-admin-access"],
)
def test_an_app_admin_cannot_give_a_password_into_someone_else_s_account(
    app_admin, temporary_password_events, make, code
):
    user = get_user_model().objects.create_user("jane.doe@example.org")
    make(user)
    password_before = get_user_model().objects.get(pk=user.pk).password
    temporary_password_events.clear()

    with pytest.raises(StaffError) as refused:
        services.give_temporary_password(user, acting_user=app_admin)

    assert refused.value.code == code
    assert get_user_model().objects.get(pk=user.pk).password == password_before
    assert temporary_password_events == []


def test_an_app_admin_can_give_a_new_password_until_the_person_has_used_one(client, app_admin):
    user = get_user_model().objects.create_user("jane.doe@example.org")
    first = services.give_temporary_password(user, acting_user=app_admin)

    second = services.give_temporary_password(user, acting_user=app_admin)

    assert sign_in(client, user.email, first).status_code == 400
    assert sign_in(client, user.email, second).status_code == 401


def test_a_temporary_password_stops_working_after_its_lifetime(client, temp_password_user):
    eight_days_later = timezone.now() + timedelta(days=8)

    with mock.patch("django.utils.timezone.now", return_value=eight_days_later):
        response = sign_in(client, temp_password_user.email, TEMP_PASSWORD)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "temporary_password_expired"
    assert not is_signed_in(client)


def test_an_app_admin_cannot_give_a_password_to_someone_who_signed_in_with_microsoft(
    microsoft, client, app_admin
):
    user = get_user_model().objects.create_user("jane.doe@example.org")
    microsoft.sign_in(client, email=user.email)
    services.remove_microsoft_link(user)

    with pytest.raises(StaffError) as refused:
        services.give_temporary_password(user, acting_user=app_admin)

    assert refused.value.code == "user_in_use"


def test_a_temporary_password_set_before_its_time_was_recorded_has_expired(
    client, temp_password_user
):
    get_user_model().objects.filter(pk=temp_password_user.pk).update(temporary_password_set_at=None)

    response = sign_in(client, temp_password_user.email, TEMP_PASSWORD)

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "temporary_password_expired"


def test_an_app_admin_cannot_give_a_password_to_someone_who_chose_one_since_it_was_read(
    app_admin,
):
    user = get_user_model().objects.create_user("jane.doe@example.org")
    stale = get_user_model().objects.get(pk=user.pk)
    user.set_password(PASSWORD)
    user.save()

    with pytest.raises(StaffError) as refused:
        services.give_temporary_password(stale, acting_user=app_admin)

    assert refused.value.code == "user_in_use"
    assert get_user_model().objects.get(pk=user.pk).check_password(PASSWORD)


class NeedsAnUppercaseLetter:
    def validate(self, password, user=None):
        if password.islower():
            raise ValidationError("Needs an uppercase letter.", code="needs_uppercase")


@override_settings(
    AUTH_PASSWORD_VALIDATORS=[{"NAME": f"{__name__}.{NeedsAnUppercaseLetter.__qualname__}"}]
)
def test_password_rules_that_refuse_every_made_password_are_a_setup_error(app_admin):
    user = get_user_model().objects.create_user("jane.doe@example.org")

    with pytest.raises(ImproperlyConfigured):
        services.give_temporary_password(user, acting_user=app_admin)

    assert not get_user_model().objects.get(pk=user.pk).has_usable_password()
