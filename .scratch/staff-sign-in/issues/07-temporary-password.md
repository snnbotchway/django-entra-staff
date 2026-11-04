# 07: Temporary password

Status: done
Labels: ready-for-agent
Blocked by: 02, 03

Spec: [../spec.md](../spec.md)

**What to build:** Someone with Django admin access can set a Temporary password on an Account. At the next Password sign-in, after the Second step, the person must choose a new password that meets the App's password rules.

- [ ] A service function sets the password and the must-replace flag together, and sends a 'Temporary password set' signal
- [ ] It refuses an Account with a Microsoft link
- [ ] Forced order: password, then Second step or Second step set-up, then new password; the Account does not open until all pass
- [ ] The new password must pass the App's password rules; replacing it clears the flag
