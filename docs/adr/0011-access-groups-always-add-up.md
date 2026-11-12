# Access groups always add up

`GROUP_MODE` is gone. Until 0.6.0 an App could make its Access groups exclusive, so a User held exactly one, and the services and the Django admin refused anything else. Now a User may hold any number of Access groups, none included, in every App. An App that once had one role per person found it hard to give a person a second one later: every check, screen and test assumed one group, and the package refused the change. With groups that add up, each App reads only the groups it cares about, and one that still wants a single role at a time keeps that rule in its own screens.

## Consequences

- An App upgrading with `GROUP_MODE` still in `ENTRA_STAFF` fails the unknown-key check (`entra_staff.E002`) until the key is removed, so nobody keeps an exclusive rule they think is still enforced.
- The error code `exclusive_needs_one_group` (never to be reused) and the admin message "Choose exactly one Access group." are gone. The check id `entra_staff.E005` is retired and not reused.
- IT can give anyone several Access groups in the Django admin. An App whose groups are a ladder (a higher one includes the lower ones' rights) takes the highest group held.
