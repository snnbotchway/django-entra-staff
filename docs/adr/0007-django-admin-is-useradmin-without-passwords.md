# The Django admin is UserAdmin with no password on it, and the only place a Temporary password is set

The package's `UserAdmin` subclasses Django's `django.contrib.auth.admin.UserAdmin`, so IT gets the user admin they already know, but with every password path taken out: no password field, no change-password link, the `<id>/password/` page refuses, the add page invites by email with Access groups and no password, and Django's own "Change password" page in the admin header refuses anyone with a Microsoft link, because it uses Django's form rather than the package's password check and would otherwise let a linked User that somehow has a password choose a new one (ADR 0002). Every change goes through the service functions, so the rules and signals apply in the admin too. The admin sign-in is replaced so it goes through the same allauth flows (Microsoft sign-in, or password plus Second step); a plain admin password form would be a weaker way in.

The only way to give someone a password is a Temporary password, set from this admin by someone with Django admin access, never by an App admin, who never sees or sets passwords. It is refused for a linked User, follows the App's password rules, and must be replaced at the next Password sign-in in a fixed order: password, then the Second step (or setting one up), then the new password, so IT never knows a password in use and every App behaves the same.

## Considered Options

- **A custom admin page from scratch**: less familiar to IT, and loses `UserAdmin`'s filters, groups picker and permissions sections.
- **Letting App admins set passwords**: App admins would then hold a way into other people's Users.
