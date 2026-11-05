# Passkeys only as the Second step, never a sign-in on their own

Passkeys are offered next to authenticator codes and recovery codes as a Second step after the password, and allauth's passwordless passkey sign-in and passkey sign-up stay off (the system check refuses them, ADR 0004). A passkey that opened a User on its own would be a third way in beside Microsoft sign-in and Password sign-in, and ADR 0002 would need a third refusal: a leaver's passkey keeps working after IT disables them in Entra. Linked Users get Entra's own MFA instead, and only Users that use a password need the Second step. The relying party is the App's own domain, so each App's passkeys are its own, and removing the last remaining Second step is refused so that no User in use is password-only.

## Consequences

- Passkeys need HTTPS, and changing an App's domain stops its existing passkeys working; people fall back on a code, or IT clears their Second step.
