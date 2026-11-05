# The system check refuses allauth settings and wiring that open a way around the package

The package's rules live in its allauth adapters, login stages and a few guarded views, but allauth and Django offer other ways in that never pass through them. Documenting "leave these off" is not enough for a security package used by several teams, so a Django system check fails `manage.py check` at start-up for each of these:

- `HEADLESS_ONLY` off: allauth's own pages (sign-in, password set and change, connections, MFA deactivate) skip the package's endpoints.
- Sign-in by emailed code, or Password reset by emailed code: a way in, or a way to add a password, that skips the Second step and the leaver rule.
- Passwordless passkey sign-in or passkey sign-up: see ADR 0006.
- Any authentication backend but allauth's (or a subclass of it): Django's `ModelBackend` checks a password without refusing linked Users, and Django calls every backend's `authenticate`, so even a permission-only backend such as django-rules or django-guardian is a password path the package cannot guard.
- allauth's email authentication (`SOCIALACCOUNT_EMAIL_AUTHENTICATION`, its `_AUTO_CONNECT`, a provider's `EMAIL_AUTHENTICATION`): allauth would match the User by email before the package makes the Microsoft link and removes the password. The adapter also treats any such match as the first sign-in, as defence in depth.
- `MFA_TRUST_ENABLED`: a trusted browser would skip the Second step.
- `ACCOUNT_PREVENT_ENUMERATION` off: Password reset and sign-in answers would reveal which emails have Users or links.
- `ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_CHANGE`: a person waiting to verify their email at sign-in could change it, unverified, to a colleague's (ADR 0005).
- allauth's own `account/email` or authenticator management views answering instead of the package's: the package's URLs must come before allauth's headless URLs, so `django_entra_staff.urls` is the only place they are included.
- The package's adapters, Microsoft provider or `webauthn` MFA type not in place, and the provider rules in ADR 0003.

## Consequences

- Apps cannot use permission backends such as django-rules or django-guardian as authentication backends, nor allauth's server-rendered pages; they build their screens on the headless API.
- New allauth releases can add new paths. The supported allauth range is pinned narrowly, and widening it means checking each new setting and endpoint against this list.
