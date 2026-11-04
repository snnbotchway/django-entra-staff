"""Signals the service functions send after a change.

Every signal has the Account class as `sender` and these keyword arguments:

- `account`: the Account that changed.
- `acting_account`: the Account that made the change, or `None` (a command, a task, the admin
  acting for nobody in particular).

`access_groups_changed` adds `previous_groups` and `groups`: frozensets of Access group names.

Signals are sent inside the service function's database transaction, with `Signal.send`, so
a receiver that raises rolls the change back. Receivers that do slow or outward-facing work
should use `transaction.on_commit`.
"""

from django.dispatch import Signal

microsoft_link_made = Signal()
access_groups_changed = Signal()
account_blocked = Signal()
account_unblocked = Signal()
temporary_password_set = Signal()
