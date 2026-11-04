"""The package's signals. Each carries the Account and, where there is one,
the acting Account."""

from django.dispatch import Signal

microsoft_link_made = Signal()
