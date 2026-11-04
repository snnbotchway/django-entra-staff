# Staff sign-in: the first release of django-entra-staff

Status: open
Labels: ready-for-agent

## Problem Statement

An organisation runs several internal Django Apps. Its staff sign in with their work Microsoft account, and a few people without one (and developers on their machines) need a password. Each App wrote its own Microsoft sign-in, Password sign-in and Account model, and within weeks they disagreed on the rules: who may get in for the first time, whether a person who has left can still use a password, whether a second proof is needed after the password, and who may hand out access. When IT disables a leaver in Entra, a password can still open every App until someone blocks the Account in each one. Developers of a new App have to make all these security decisions again, and get them wrong in new ways.

## Solution

One public package that an App installs and configures in its settings. It gives every App the same rules, built on django-allauth (ADR 0001):

- Microsoft sign-in for one Entra tenant. At a person's first Microsoft sign-in their Account is tied to them by matching work email (the Microsoft link); after that only the link is used.
- Once an Account has a Microsoft link, its password is removed and Password sign-in is refused for good (ADR 0002), so disabling a leaver in Entra ends their access to every App.
- Password sign-in for everyone else, always followed by the Second step (an authenticator code, a passkey, or a recovery code). A person with neither an authenticator nor a passkey must set one up before the Account opens. A passkey is only ever a Second step, never a way to sign in without a password.
- A Sign-up rule per App: Invite only (default) or Open to staff.
- Access through the App's declared Access groups, which either add up or are exclusive. App admins manage people in the App's own screens and never see or set passwords. Django admin access is separate and is never granted by an Access group.
- A Django admin page for developers and IT, which is the only place a Temporary password can be set.
- Service functions and signals so each App's own screens and code can manage Accounts without touching allauth directly.

The package names no organisation, wording or group; each App supplies those in settings.

## User Stories

### Microsoft sign-in

1. As a staff member, I want to sign in to an App with my work Microsoft account, so that I do not need another password.
2. As a staff member, I want Microsoft to ask for its own MFA and Conditional Access checks, so that the App does not ask me for a second code on top.
3. As a staff member who was invited by email, I want my first Microsoft sign-in to find my existing Account by my work email, so that I keep the Access groups I was given.
4. As a staff member, I want my Account to stay mine after my first Microsoft sign-in even if my email address changes later, so that a rename in Entra does not lock me out or move me to another Account.
5. As an App developer, I want only people from the App's configured Entra tenant to complete Microsoft sign-in, so that guests and people from other tenants cannot get in.
6. As an App developer, I want the email match at first sign-in to ignore letter case, so that `Jane.Doe@` and `jane.doe@` are the same person.
7. As an App developer, I want the email match to be done only once, when no Microsoft link exists yet, so that a later Microsoft person who reuses an email cannot take over an Account that is already linked to someone else.
8. As an App developer, I want a Microsoft sign-in to be refused if the matching Account is already linked to a different Microsoft person, so that one Account is never shared by two people.
9. As a person with a work Microsoft account but no Account in an Invite only App, I want a clear refusal, so that I know to ask an App admin for access instead of retrying.
10. As a staff member signing in to an Open to staff App for the first time, I want an Account made for me with the App's lowest access, so that I can start without waiting for someone.
11. As an App admin, I want to know when someone joined through Open to staff, so that I can give them the right Access groups.
12. As IT, I want disabling a leaver in Entra to stop their Microsoft sign-in in every App at once, so that I do not have to visit each App.
13. As a staff member whose Account is blocked in one App, I want Microsoft sign-in to that App to be refused, so that a block inside the App still works for Microsoft people.

### Password sign-in and the leaver rule

14. As a contractor without a work Microsoft account, I want to sign in with my email and password, so that I can use the App.
15. As a developer on my machine, I want Password sign-in to work with Microsoft sign-in not set up, so that I can run the App locally.
16. As IT, I want an Account's password removed the moment it gets a Microsoft link, so that a leaver's old password cannot open the App.
17. As IT, I want Password sign-in refused for any Account with a Microsoft link, so that the leaver rule holds even if a password was somehow set later.
18. As a linked staff member who tries Password sign-in, I want to be told to use Microsoft sign-in, so that I am not stuck guessing passwords.
19. As an App developer, I want a refused Password sign-in for a linked Account to look the same to an attacker as a wrong password, unless the password was right, so that it does not reveal which emails are linked.
20. As an App developer, I want allauth's attempt limits to apply to Password sign-in, so that passwords cannot be guessed at speed.
21. As an App developer, I want people unable to create their own Account with a password, so that only invited people get passwords.

### Second step

22. As a person using Password sign-in, I want to enter a code from my authenticator app after my password, so that a stolen password alone cannot open my Account.
23. As a person who has lost my authenticator, I want to use a one-time recovery code instead, so that I can still get in.
24. As a person signing in with a password for the first time, I want to be made to set up an authenticator or a passkey before the Account opens, so that no password-only Account ever exists in use.
25. As a person setting up my first authenticator or passkey, I want to be given recovery codes and told to keep them, so that I can recover later.
26. As a person who has used a recovery code, I want each code to work once only, so that a leaked code cannot be reused.
27. As IT, I want to clear a person's authenticator and passkeys from the Django admin, so that they can set up a new one at their next Password sign-in.
28. As an App developer, I want the Second step to be impossible to skip by calling other API endpoints with a half-finished sign-in, so that the rule cannot be bypassed.
29. As a person using Password sign-in, I want to use a passkey (my device's fingerprint, face or PIN, or a security key) as the Second step instead of typing a code, so that signing in is quicker and cannot be phished.
30. As a person with a passkey, I want to add more than one and name them, so that losing one device does not lock me out.
31. As a person, I want to remove one of my passkeys, but not my last Second step, so that I cannot leave my Account with only a password.
32. As IT, I want a passkey to never open an Account on its own without the password, so that there is no third way in for the leaver rule to cover.
33. As an App developer, I want passkeys tied to my App's own domain, so that a passkey for one App cannot be used on another.
34. As a Microsoft person, I want never to be asked for the App's Second step, so that I am not asked twice.

### Temporary password

35. As IT, I want to set a Temporary password on an Account from the Django admin, so that a new contractor can sign in for the first time.
36. As a person given a Temporary password, I want to be made to choose my own password at my next Password sign-in, so that IT does not know my password.
37. As a person replacing a Temporary password, I want the App's password rules to apply to the new one, so that it is strong enough.
38. As IT, I want setting a Temporary password on a linked Account to be refused, so that the leaver rule cannot be undone from the admin.
39. As an App developer, I want the order of the forced steps to be fixed (password, then Second step or Second step set-up, then new password), so that every App behaves the same.

### Password reset

40. As a person with a password who forgot it, I want to get an emailed link to choose a new one, so that I can get back in without IT.
41. As a person resetting my password, I want the Second step still required at my next sign-in, so that access to my mailbox alone does not open the Account.
42. As IT, I want Password reset refused for Accounts with no password (including every linked Account), so that a reset can never add a password to a linked Account.
43. As an App developer, I want the reset request to answer the same way whether or not the email exists or can be reset, so that it does not reveal who has an Account.

### Accounts

44. As an App developer, I want an Account identified by email with no username, so that people sign in the way they think of themselves.
45. As an App developer, I want to extend the package's Account model with my App's own fields, so that I do not need a separate profile table.
46. As an App developer, I want Account emails unique regardless of letter case, so that two Accounts can never match one Microsoft person.
47. As an App admin, I want to invite a person by email with chosen Access groups, so that they can use Microsoft sign-in in an Invite only App.
48. As an App admin, I want to block and unblock an Account, so that I can stop one person using my App without IT.
49. As an App admin, I want to see whether an Account has a Microsoft link, uses a password, or has not signed in yet, so that I can answer questions about access.
50. As an App developer, I want each App's Accounts to be separate, so that one App's data and access decisions never leak into another.

### Access groups

51. As an App developer, I want to declare my App's Access groups in settings, so that the groups exist the same way in every environment.
52. As an App developer, I want to say whether my Access groups add up or are exclusive, so that the package enforces the right shape.
53. As an App developer, I want to name which Access group is the lowest access, so that Open to staff sign-ups get it.
54. As an App developer, I want to name which Access group is App admin, so that the package knows who may manage people.
55. As an App admin, I want to change a person's Access groups in my App's screens, so that I do not need IT.
56. As an App admin in an App with exclusive Access groups, I want setting a person's group to replace their old one, so that they never hold two.
57. As an App developer, I want an attempt to give an Account two exclusive Access groups, or a group the App did not declare, to be refused, so that bad data never gets saved.
58. As an App admin, I want to be stopped from removing the App admin group from the last App admin, so that the App is never left with nobody to manage it.
59. As IT, I want being an App admin never to grant Django admin access, so that App admins cannot reach passwords or developer tools.
60. As an App admin, I want my management actions never to show or set passwords, so that I cannot see or change how people sign in.
61. As an App developer, I want to check an Account's Access groups with one simple call, so that my views and permissions stay short.

### Django admin

62. As IT, I want an Account admin page listing email, Access groups, Microsoft link, password status, Second step status, blocked state and last sign-in, so that I can support people.
63. As IT, I want the Django admin sign-in to follow the same rules (Microsoft sign-in, or password plus Second step), so that the admin is not a weaker way in.
64. As IT, I want only developers and IT to hold Django admin access, granted directly on the Account, so that it is a deliberate choice.
65. As IT, I want to remove a Microsoft link from the admin for a person whose Entra identity was replaced, so that their next Microsoft sign-in can link again by email.

### Integration and operations

66. As an App developer, I want to install the package, add it to settings, and set a tenant and client, so that sign-in works without writing auth code.
67. As an App developer with a single-page frontend, I want to use allauth's headless browser API paths and error shape, so that I can use allauth's documented client flows.
68. As an App developer, I want a clear error at start-up if the settings are inconsistent (an undeclared lowest access group, a missing App admin group, Open to staff with no lowest access), so that mistakes show before users find them.
69. As an App developer, I want signals for Microsoft link made, Account signed up through Open to staff, Access groups changed, Account blocked or unblocked, and Temporary password set, so that my App can audit and notify.
70. As an App developer, I want service functions for every Account change the package allows, so that my screens, commands and tests use the same rules.
71. As an App developer, I want the on-screen wording and email texts to be mine to override, so that my App speaks in my organisation's words.
72. As a maintainer, I want the package to rely on allauth for the Microsoft protocol, token checks, password storage, TOTP, recovery codes and attempt limits, so that we do not own security-critical code in public.

## Implementation Decisions

- **Shape**: a thin policy layer on django-allauth (core accounts, socialaccount with the Microsoft provider, mfa, headless). No sign-in protocol, token, hashing, TOTP or rate-limit code of our own (ADR 0001).
- **Configuration**: one settings dict for the package, holding: Entra tenant ID, the Sign-up rule (`invite_only` default, or `open_to_staff`), the list of Access groups, whether they add up or are exclusive, the lowest access group, and the App admin group. The Microsoft client ID and secret come from allauth's own provider settings. A Django system check validates the dict at start-up. The Sign-up rule and group modes are each defined once as `TextChoices`/`StrEnum`.
- **Account model**: the package ships an abstract Account base (email as the identifier, no username, case-insensitive unique email) and a manager. Each App defines a concrete subclass and points its user-model setting at it, so it can add fields. Blocked means inactive.
- **Microsoft link**: allauth's social account row, not a field on the Account. Linking is done in the package's social account adapter before allauth's own login: check the token's tenant against the configured tenant, and refuse guests of the tenant by the id_token's `idp` claim (present and different from the issuer for B2B and personal-account guests), with the same generic error as a wrong tenant; if a link for this Microsoft person exists, use it and ignore email; otherwise match a single Account by work email, case-insensitive, that has no Microsoft link, make the link and remove the password (set unusable) in the same transaction. A match that is already linked to another Microsoft person is refused. Allauth's automatic email-based connect is not relied on; the adapter owns this rule.
- **Sign-up rule**: the social account adapter answers whether sign-up is open. Invite only refuses with a distinct error code. Open to staff creates the Account with only the lowest access group and sends the sign-up signal. Password-based sign-up is always closed.
- **No password on a linked Account**: every path that adds a password to an Account with a Microsoft link (allauth's password set and change, Password reset from a key) is refused in the account adapter's password check with `use_microsoft_signin`, and removing a Microsoft link is refused everywhere except the admin service `remove_microsoft_link` (self-service disconnect fails with `disconnect_not_supported`). Together these keep ADR 0002 from being undone from inside a signed-in session.
- **Allowed allauth paths**: `HEADLESS_ONLY = True` is required, because allauth's own pages (password set and change, connections, MFA deactivate, sign-in) skip the package's endpoints. Sign-in by emailed code and Password reset by emailed code stay off. `AUTHENTICATION_BACKENDS` holds allauth's authentication backend only; Django's `ModelBackend` would check a password with no Microsoft link check. The package's MFA adapter is required and refuses removing the last Second step as well. The system check refuses settings that break any of these.
- **Password sign-in**: the account adapter refuses authentication for any Account with a Microsoft link. When the password was correct for a linked Account (only possible if a password was set by mistake), the response says to use Microsoft sign-in; otherwise it is the ordinary wrong-credentials error.
- **Second step and forced steps**: implemented with allauth login stages, so a sign-in is not complete until each stage passes. Order: password, then the Second step (or Second step set-up, with recovery codes, when the Account has neither an authenticator nor a passkey), then replacing a Temporary password. Microsoft sign-in skips the package's stages. Endpoints outside the current stage refuse a half-finished sign-in, as allauth's stage handling already does.
- **Passkeys**: allauth's MFA WebAuthn type, enabled next to TOTP and recovery codes; this adds allauth's optional `fido2` dependency. Passkeys work only as the Second step: allauth's passwordless passkey sign-in and passkey sign-up stay off, and the system check refuses settings that turn them on (ADR 0002 would otherwise need a third refusal). The relying party is the App's own domain, taken from the request host as allauth does, so each App's passkeys are its own. A person may hold several passkeys; removing the last remaining Second step (authenticator or passkey) is refused. Apps call the browser's WebAuthn API in their own frontend and pass the results to allauth's headless MFA endpoints.
- **Temporary password**: a flag on the Account set only by a service function that the Django admin calls; it sets the password and the must-replace flag together, and refuses linked Accounts. Replacing the password clears the flag.
- **Password reset**: the account adapter only sends a reset email to Accounts with a usable password and no Microsoft link; the public response is the same in every case.
- **Access groups**: Django `Group` rows whose names come from settings, created or updated after migrations. The service layer enforces declared-only, exclusive mode, and keeping at least one App admin. Django admin access stays on the Account's staff and superuser flags and is never touched by Access group code.
- **Service functions** (the public Python API): invite an Account with Access groups; set Access groups; block and unblock; set a Temporary password (Django admin only); clear a person's authenticators and passkeys; remove a Microsoft link; a check for whether an Account holds an Access group. Each raises a package error type with a stable code on refusal and sends its signal on success. App-admin functions take no password arguments and return no password data.
- **Signals**: Microsoft link made, Account signed up through Open to staff, Access groups changed, Account blocked, Account unblocked, Temporary password set, authenticators and passkeys cleared, Microsoft link removed. Each carries the Account and, where there is one, the acting Account.
- **Django admin**: an Account admin page and actions for set Temporary password, clear authenticators and passkeys, and remove Microsoft link, all going through the service functions. The admin sign-in page is replaced so that signing in to the admin goes through the same allauth flows (no plain password form).
- **API surface**: Apps use allauth headless browser paths (`/_allauth/browser/v1/...`) and its error shape. Package-specific refusals (Invite only, use Microsoft sign-in, Password reset not available) appear as stable error codes inside that shape.
- **Wording**: all user-facing text goes through Django translation and overridable allauth templates; nothing names an organisation.
- **Release**: published to PyPI only through Trusted Publishing behind a manual approval (ADR 0001).

## Testing Decisions

- A good test drives the package the way an App does and checks what a caller would notice: HTTP responses, the Account's resulting state, and signals sent. It does not check adapter calls, internal helpers or mocks. Few, meaningful tests, per the coding standards.
- **Seam 1 (main): the allauth headless HTTP API on a test App.** The test suite includes a minimal test App project with a concrete Account subclass and settings variants (Invite only vs Open to staff; adding vs exclusive Access groups). Tests use the Django test client against the headless browser endpoints and the Django admin. This covers Microsoft sign-in, linking, the leaver rule, Password sign-in, the Second step and set-up (code, passkey and recovery code), Temporary password, Password reset and admin sign-in.
- **Passkeys are tested with a software authenticator** from `fido2` that makes real WebAuthn registration and sign-in responses, so allauth's checks run unmocked.
- **Microsoft is faked only at the network edge**: its token, key-set and user-info endpoints are stubbed at the HTTP layer, with signed test tokens carrying the tenant and email the test needs. Nothing inside allauth or the package is mocked.
- **Seam 2: the public service functions and signals**, for behaviour with no HTTP path of its own (Access group rules, last App admin, Temporary password refusal on linked Accounts, signals). These are tested as an App's own code would call them.
- The system check for settings is tested through Django's check framework with bad settings, including the allauth settings and authentication backends that would open a path around the package.
- Tests run against the database the test setup starts; the CI matrix covers the supported Django, allauth and Python versions.
- Prior art: none in this repo yet. Follow allauth's own test suite for faking provider responses and headless flows.

## Out of Scope

- More than one Entra tenant, and providers other than Microsoft.
- Reading Microsoft Graph for group membership or disabled people (ADR 0002 rejects the latter); Access groups are managed in each App.
- Sign-in screens or a frontend; Apps build their own on the headless API. The package ships only overridable email and fallback templates.
- Sharing Accounts, sessions or Access groups between Apps, or a central sign-in service (ADR 0001).
- Passwordless passkey sign-in and passkey sign-up.
- SMS or email codes as a Second step.
- Keeping both a password and a Microsoft link on one Account (ADR 0002).
- Moving existing Apps' data onto the package; each App does its own migration.

## Further Notes

- Passkeys need HTTPS (localhost is fine in development), and changing an App's domain makes its existing passkeys stop working; say so in the App setup docs.
- Allauth's login stages and headless API change between minor versions; pin a supported range and check the stage API against the pinned version before building the forced-step flow.
- "Lowest access" and "App admin" are named in settings, not inferred, so they work in both adding and exclusive modes. If the glossary should define "lowest access" as a term, add it with `/domain-modeling`.
- Removing a Microsoft link leaves the Account with no password, so the person can only sign in again through Microsoft sign-in (which re-links by email) or after IT sets a Temporary password, which is allowed once the link is gone.
