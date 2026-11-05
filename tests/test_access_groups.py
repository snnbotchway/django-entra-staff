"""Access groups and the service functions, called the way an App's own code calls them."""

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.test import override_settings

from django_entra_staff import services, signals
from django_entra_staff.errors import ErrorCode, StaffError
from tests.testapp import variants

pytestmark = pytest.mark.django_db


@pytest.fixture
def sent():
    """Every signal the package sends during a test, as `(signal name, kwargs)`."""
    received = []
    receivers = []
    for name in ("access_groups_changed", "account_blocked", "account_unblocked"):

        def receiver(sender, signal, _name=name, **kwargs):
            received.append((_name, kwargs))

        getattr(signals, name).connect(receiver, weak=False)
        receivers.append((name, receiver))
    yield received
    for name, receiver in receivers:
        getattr(signals, name).disconnect(receiver)


@pytest.fixture
def admin_account():
    return services.invite_account("boss@example.com", ["manager"])


def group_names(account):
    return set(account.groups.values_list("name", flat=True))


def test_declared_access_groups_exist_after_migrations():
    assert set(Group.objects.values_list("name", flat=True)) == {"viewer", "editor", "manager"}


def test_invite_creates_an_account_with_the_groups_and_no_password(sent, admin_account):
    sent.clear()

    account = services.invite_account(
        "Jane.Doe@example.com", ["viewer", "editor"], acting_account=admin_account
    )

    account.refresh_from_db()
    assert group_names(account) == {"viewer", "editor"}
    assert not account.has_usable_password()
    assert account.is_active
    assert (account.is_staff, account.is_superuser) == (False, False)
    assert sent == [
        (
            "access_groups_changed",
            {
                "account": account,
                "acting_account": admin_account,
                "previous_groups": frozenset(),
                "groups": frozenset({"viewer", "editor"}),
            },
        )
    ]


def test_invite_refuses_an_email_that_already_has_an_account_whatever_its_case(admin_account):
    with pytest.raises(StaffError) as refused:
        services.invite_account("BOSS@example.com", ["viewer"])

    assert refused.value.code == ErrorCode.ACCOUNT_EXISTS
    assert get_user_model().objects.count() == 1


def test_undeclared_group_is_refused_and_nothing_is_saved(admin_account):
    with pytest.raises(StaffError) as refused:
        services.invite_account("new@example.com", ["viewer", "ghost"])
    assert refused.value.code == "undeclared_access_group"
    assert not get_user_model().objects.filter(email="new@example.com").exists()

    person = services.invite_account("p@example.com", ["viewer"])
    with pytest.raises(StaffError) as refused:
        services.set_access_groups(person, ["ghost"], acting_account=admin_account)
    assert refused.value.code == ErrorCode.UNDECLARED_ACCESS_GROUP
    assert group_names(person) == {"viewer"}


def test_adding_mode_sets_the_groups_to_exactly_the_given_ones(sent, admin_account):
    person = services.invite_account("p@example.com", ["viewer"])
    sent.clear()

    services.set_access_groups(person, ["viewer", "editor"], acting_account=admin_account)
    services.set_access_groups(person, ["editor"], acting_account=admin_account)

    assert group_names(person) == {"editor"}
    assert [(name, kw["previous_groups"], kw["groups"]) for name, kw in sent] == [
        ("access_groups_changed", {"viewer"}, {"viewer", "editor"}),
        ("access_groups_changed", {"viewer", "editor"}, {"editor"}),
    ]


def test_setting_the_groups_a_person_already_has_sends_nothing(sent, admin_account):
    person = services.invite_account("p@example.com", ["viewer"])
    sent.clear()

    services.set_access_groups(person, ["viewer"])

    assert sent == []


def test_other_django_groups_are_left_alone(admin_account):
    person = services.invite_account("p@example.com", ["viewer"])
    person.groups.add(Group.objects.create(name="app-specific"))

    services.set_access_groups(person, ["editor"])

    assert group_names(person) == {"app-specific", "editor"}
    assert services.has_access_group(person, "editor")


@override_settings(ENTRA_STAFF=variants.INVITE_ONLY_EXCLUSIVE)
def test_exclusive_mode_setting_a_group_replaces_the_old_one(admin_account):
    person = services.invite_account("p@example.com", "viewer")

    services.set_access_groups(person, "editor", acting_account=admin_account)

    assert group_names(person) == {"editor"}


@override_settings(ENTRA_STAFF=variants.INVITE_ONLY_EXCLUSIVE)
@pytest.mark.parametrize("groups", [["viewer", "editor"], []])
def test_exclusive_mode_refuses_anything_but_one_group(admin_account, groups):
    person = services.invite_account("p@example.com", "viewer")

    with pytest.raises(StaffError) as refused:
        services.set_access_groups(person, groups)
    assert refused.value.code == ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP
    assert group_names(person) == {"viewer"}

    with pytest.raises(StaffError) as refused:
        services.invite_account("q@example.com", groups)
    assert refused.value.code == ErrorCode.EXCLUSIVE_NEEDS_ONE_GROUP


def test_block_and_unblock_flip_the_account_and_send_their_signals(sent, admin_account):
    person = services.invite_account("p@example.com", ["viewer"])
    sent.clear()

    services.block_account(person, acting_account=admin_account)
    person.refresh_from_db()
    assert not person.is_active
    services.unblock_account(person, acting_account=admin_account)
    person.refresh_from_db()
    assert person.is_active

    assert [(name, kw["account"], kw["acting_account"]) for name, kw in sent] == [
        ("account_blocked", person, admin_account),
        ("account_unblocked", person, admin_account),
    ]


def test_blocking_a_blocked_account_or_unblocking_an_active_one_sends_nothing(sent, admin_account):
    person = services.invite_account("p@example.com", ["viewer"])
    sent.clear()

    services.unblock_account(person)
    services.block_account(person)
    services.block_account(person)

    assert [name for name, _ in sent] == ["account_blocked"]


def test_has_access_group_answers_for_one_declared_group(admin_account):
    assert services.has_access_group(admin_account, "manager")
    assert not services.has_access_group(admin_account, "viewer")
    with pytest.raises(StaffError) as refused:
        services.has_access_group(admin_account, "ghost")
    assert refused.value.code == ErrorCode.UNDECLARED_ACCESS_GROUP


def test_has_access_group_is_false_for_someone_not_signed_in():
    assert not services.has_access_group(AnonymousUser(), "viewer")


def test_no_access_group_change_touches_django_admin_access(admin_account):
    person = services.invite_account("p@example.com", ["viewer"])
    person.is_staff = True
    person.save()

    services.set_access_groups(person, ["manager"], acting_account=admin_account)
    services.block_account(person)
    services.unblock_account(person)

    person.refresh_from_db()
    assert (person.is_staff, person.is_superuser) == (True, False)
    admin_account.refresh_from_db()
    assert (admin_account.is_staff, admin_account.is_superuser) == (False, False)
