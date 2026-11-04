# 09: Django admin page and admin sign-in

Status: open
Labels: ready-for-agent
Blocked by: 03, 05, 07, 08

Spec: [../spec.md](../spec.md)

**What to build:** Developers and IT get an Account admin page to support people, and actions that go through the service functions. Signing in to the Django admin follows the same rules as the App, so the admin is not a weaker way in.

- [ ] Account admin page shows email, Access groups, Microsoft link, password status, Second step status, blocked state and last sign-in
- [ ] Admin actions: set a Temporary password, clear authenticators and passkeys, remove a Microsoft link, each through a service function
- [ ] After a Microsoft link is removed, the next Microsoft sign-in links again by email
- [ ] The Django admin sign-in has no plain password form; it uses Microsoft sign-in or password plus Second step
- [ ] Django admin access is granted only on the Account itself, never by an Access group
