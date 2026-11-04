# 08: Passkeys as a Second step

Status: open
Labels: ready-for-agent
Blocked by: 02

Spec: [../spec.md](../spec.md)

**What to build:** A person using Password sign-in can register passkeys (device fingerprint, face or PIN, or a security key) and use one as the Second step instead of a code. A passkey never opens an Account without the password.

- [ ] allauth's WebAuthn MFA type is on, next to TOTP and recovery codes; `fido2` is an optional dependency
- [ ] Second step set-up offers a passkey as well as an authenticator, with recovery codes either way
- [ ] A person can register several named passkeys and use any of them as the Second step
- [ ] Removing the last remaining Second step (authenticator or passkey) is refused
- [ ] The system check refuses settings that turn on passwordless passkey sign-in or passkey sign-up
- [ ] Tests use `fido2`'s software authenticator, so allauth's checks run unmocked
