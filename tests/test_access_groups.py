"""Access groups and the service functions, called the way an App's own code calls them."""

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group

from django_entra_staff import services, signals
from django_entra_staff.errors import ErrorCode, StaffError

pytestmark = pytest.mark.django_db


@pytest.fixture
def sent():
    """Every signal the package sends during a test, as `(signal name, kwargs)`."""
    received = []
    receivers = []
    for name in ("access_groups_changed", "user_blocked", "user_unblocked"):

        def receiver(sender, signal, _name=name, **kwargs):
            received.append((_name, kwargs))

        getattr(signals, name).connect(receiver, weak=False)
        receivers.append((name, receiver))
    yield received
    for name, receiver in receivers:
        getattr(signals, name).disconnect(receiver)


@pytest.fixture
def admin_user():
    return services.invite_user("boss@example.com", ["manager"])


def group_names(user):
    return set(user.groups.values_list("name", flat=True))


def test_declared_access_groups_exist_after_migrations():
    assert set(Group.objects.values_list("name", flat=True)) == {"viewer", "editor", "manager"}


def test_invite_creates_a_user_with_the_groups_and_no_password(sent, admin_user):
    sent.clear()

    user = services.invite_user(
        "Jane.Doe@example.com", ["viewer", "editor"], acting_user=admin_user
    )

    user.refresh_from_db()
    assert group_names(user) == {"viewer", "editor"}
    assert not user.has_usable_password()
    assert user.is_active
    assert (user.is_staff, user.is_superuser) == (False, False)
    assert sent == [
        (
            "access_groups_changed",
            {
                "user": user,
                "acting_user": admin_user,
                "previous_groups": frozenset(),
                "groups": frozenset({"viewer", "editor"}),
            },
        )
    ]


def test_invite_refuses_an_email_that_already_has_a_user_whatever_its_case(admin_user):
    with pytest.raises(StaffError) as refused:
        services.invite_user("BOSS@example.com", ["viewer"])

    assert refused.value.code == ErrorCode.USER_EXISTS
    assert get_user_model().objects.count() == 1


def test_undeclared_group_is_refused_and_nothing_is_saved(admin_user):
    with pytest.raises(StaffError) as refused:
        services.invite_user("new@example.com", ["viewer", "ghost"])
    assert refused.value.code == "undeclared_access_group"
    assert not get_user_model().objects.filter(email="new@example.com").exists()

    person = services.invite_user("p@example.com", ["viewer"])
    with pytest.raises(StaffError) as refused:
        services.set_access_groups(person, ["ghost"], acting_user=admin_user)
    assert refused.value.code == ErrorCode.UNDECLARED_ACCESS_GROUP
    assert group_names(person) == {"viewer"}


def test_adding_mode_sets_the_groups_to_exactly_the_given_ones(sent, admin_user):
    person = services.invite_user("p@example.com", ["viewer"])
    sent.clear()

    services.set_access_groups(person, ["viewer", "editor"], acting_user=admin_user)
    services.set_access_groups(person, ["editor"], acting_user=admin_user)

    assert group_names(person) == {"editor"}
    assert [(name, kw["previous_groups"], kw["groups"]) for name, kw in sent] == [
        ("access_groups_changed", {"viewer"}, {"viewer", "editor"}),
        ("access_groups_changed", {"viewer", "editor"}, {"editor"}),
    ]


def test_setting_the_groups_a_person_already_has_sends_nothing(sent, admin_user):
    person = services.invite_user("p@example.com", ["viewer"])
    sent.clear()

    services.set_access_groups(person, ["viewer"])

    assert sent == []


def test_other_django_groups_are_left_alone(admin_user):
    person = services.invite_user("p@example.com", ["viewer"])
    person.groups.add(Group.objects.create(name="app-specific"))

    services.set_access_groups(person, ["editor"])

    assert group_names(person) == {"app-specific", "editor"}
    assert services.has_access_group(person, "editor")


def test_block_and_unblock_flip_the_user_and_send_their_signals(sent, admin_user):
    person = services.invite_user("p@example.com", ["viewer"])
    sent.clear()

    services.block_user(person, acting_user=admin_user)
    person.refresh_from_db()
    assert not person.is_active
    services.unblock_user(person, acting_user=admin_user)
    person.refresh_from_db()
    assert person.is_active

    assert [(name, kw["user"], kw["acting_user"]) for name, kw in sent] == [
        ("user_blocked", person, admin_user),
        ("user_unblocked", person, admin_user),
    ]


def test_blocking_a_blocked_user_or_unblocking_an_active_one_sends_nothing(sent, admin_user):
    person = services.invite_user("p@example.com", ["viewer"])
    sent.clear()

    services.unblock_user(person)
    services.block_user(person)
    services.block_user(person)

    assert [name for name, _ in sent] == ["user_blocked"]


def test_has_access_group_answers_for_one_declared_group(admin_user):
    assert services.has_access_group(admin_user, "manager")
    assert not services.has_access_group(admin_user, "viewer")
    with pytest.raises(StaffError) as refused:
        services.has_access_group(admin_user, "ghost")
    assert refused.value.code == ErrorCode.UNDECLARED_ACCESS_GROUP


def test_has_access_group_is_false_for_someone_not_signed_in():
    assert not services.has_access_group(AnonymousUser(), "viewer")


def test_no_access_group_change_touches_django_admin_access(admin_user):
    person = services.invite_user("p@example.com", ["viewer"])
    person.is_staff = True
    person.save()

    services.set_access_groups(person, ["manager"], acting_user=admin_user)
    services.block_user(person)
    services.unblock_user(person)

    person.refresh_from_db()
    assert (person.is_staff, person.is_superuser) == (True, False)
    admin_user.refresh_from_db()
    assert (admin_user.is_staff, admin_user.is_superuser) == (False, False)
