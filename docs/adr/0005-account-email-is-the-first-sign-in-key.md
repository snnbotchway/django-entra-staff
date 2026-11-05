# The Account's email is guarded because the first Microsoft sign-in matches on it

A person's first Microsoft sign-in finds their Account by work email, case-insensitive, among Accounts with no Microsoft link; after that only the link is used and the email is ignored. So whoever can put an address on an unlinked Account decides whose first Microsoft sign-in lands in it. The package therefore owns the email rules instead of leaving them to allauth: its `account/email` view refuses adding an address or changing the primary one for an Account with a Microsoft link (`email_change_not_supported`), and for every other Account allows only a verified address to become primary (`unverified_primary_email`), because allauth lets an Account with no verified address make an unverified one primary, and a person with a password could then take a colleague's address. The match is made only once, in the package's social account adapter, never by allauth's automatic email connect (ADR 0004), and an Account already linked to another Microsoft person is refused, never shared. Connecting a Microsoft account by hand from a signed-in session is refused too (`connect_not_supported`), since the link is made only by that first match.

## Considered Options

- **Match by email on every Microsoft sign-in**: a rename in Entra would move the person to another Account, and a reused address could take over a linked one.
- **Let people connect Microsoft from their settings**: a second way to make the link, with its own takeover cases, for no gain over inviting by email.
