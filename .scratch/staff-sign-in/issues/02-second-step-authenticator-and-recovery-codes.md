# 02: Second step with authenticator code and recovery codes

Status: done
Labels: ready-for-agent
Blocked by: 01

Spec: [../spec.md](../spec.md)

**What to build:** Password sign-in no longer opens the Account after the password alone. The person must give a code from their authenticator app or a one-time recovery code. A person with no Second step must set up an authenticator before the Account opens, and is given recovery codes.

- [ ] After a correct password, the sign-in is unfinished until a valid authenticator code or recovery code is given
- [ ] Each recovery code works once only
- [ ] An Account with no Second step is taken through authenticator set-up, with recovery codes, before it opens
- [ ] A half-finished sign-in cannot reach other endpoints
- [ ] Built on allauth login stages and allauth MFA, with no TOTP or code-checking code of our own
