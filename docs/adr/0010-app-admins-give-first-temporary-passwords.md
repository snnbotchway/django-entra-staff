# App admins give first Temporary passwords, which expire

ADR 0007 kept Temporary passwords with IT, so every person without a work Microsoft account needed IT before they could sign in. Now an App admin can give one too, through `give_temporary_password`. The package makes a random password, saves it as a Temporary password, and returns it once for the App admin to share. Nothing keeps it, and the `temporary_password_set` signal carries the acting User but not the password, so the App can audit who gave it. The package still does not know which Access group is App admin (ADR 0008): the App's own screens decide who may call it, and the package's limits are about the person who gets the password.

An App admin gets no way into someone else's User, so `give_temporary_password` is refused when:

- the User has a Microsoft link (ADR 0002);
- the person has already used their User: they have signed in (with a password or Microsoft), chosen a password, or set up any Second step. Each counts on its own, because IT can clear a Second step or remove a Microsoft link and leave the rest, and a Password reset chooses a password without signing in;
- the User has Django admin access, so IT's own Users stay with IT.

The rest is as before: the person must set up the Second step and then replace the password at their first Password sign-in, so nobody but the person knows a password in use. IT's `set_temporary_password` in the Django admin is unchanged, and it can still give a new password to anyone without a Microsoft link.

Every Temporary password, from IT or an App admin, now stops working after `ENTRA_STAFF["TEMPORARY_PASSWORD_LIFETIME"]` (7 days by default). A password nobody uses does not stay open for good.

## Considered Options

- **Only IT gives passwords (ADR 0007)**: every new person without a Microsoft account waits for IT.
- **Refuse only once the person has a Second step**: misses a User whose Second step IT cleared, who still has a password they chose, and a User who signed in only with Microsoft and whose link IT removed.
- **Refuse work-domain emails**: would stop App admins giving passwords to people who should use Microsoft sign-in, but needs a list of the organisation's domains in every App. Not worth it for now.

## Consequences

- Until the person's first sign-in, the App admin who gave the password can sign in as them, set up their own Second step and choose the password, which locks the person out until IT clears it. The signal records who gave the password; allauth's email about a new Second step is the only other sign. The lifetime shortens this window.
- A person with a work Microsoft account who is given a password and never uses Microsoft sign-in keeps it after IT disables them in Entra, until it expires. If they replace it first, the new password lasts until their first Microsoft sign-in removes it (ADR 0002), or until someone blocks the User.
- A Temporary password set before the package recorded when it was set counts as expired.
