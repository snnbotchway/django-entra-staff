# 04: Leaver rule: refuse Password sign-in and Password reset for linked Accounts

Status: open
Labels: ready-for-agent
Blocked by: 03

Spec: [../spec.md](../spec.md)

**What to build:** An Account with a Microsoft link can never use Password sign-in or Password reset (ADR 0002), so disabling a leaver in Entra ends their access. Password reset works for Accounts that already have a password, and the Second step is still needed afterwards.

- [ ] Password sign-in is refused for any linked Account, even if a password was set on it by mistake
- [ ] The 'use Microsoft sign-in' error code appears only when the password was right; otherwise the usual wrong-password error is returned
- [ ] A reset email is sent only to Accounts with a usable password and no Microsoft link
- [ ] The reset request answers the same way whatever the email
- [ ] After a Password reset, the next Password sign-in still needs the Second step
