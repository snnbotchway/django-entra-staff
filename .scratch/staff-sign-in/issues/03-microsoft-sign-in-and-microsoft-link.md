# 03: Microsoft sign-in with the Microsoft link (Invite only)

Status: open
Labels: ready-for-agent
Blocked by: 01

Spec: [../spec.md](../spec.md)

**What to build:** Staff sign in with their work Microsoft account for the App's one Entra tenant. At a person's first Microsoft sign-in, their Account is found by work email and the Microsoft link is made; their password is removed in the same step. After that only the link is used, even if the email changes. Invite only (the default) refuses people with no Account.

- [ ] Microsoft is faked only at the network edge (token, key-set and user-info endpoints), with signed test tokens
- [ ] A token from another tenant is refused
- [ ] First sign-in links to the one Account whose email matches, ignoring case, and that has no Microsoft link; its password becomes unusable in the same transaction
- [ ] A later sign-in uses the link and ignores the email, so a changed email keeps the same Account
- [ ] An Account already linked to a different Microsoft person is refused, never shared
- [ ] With Invite only, a person with no Account is refused with a stable error code
- [ ] A blocked Account is refused
- [ ] Microsoft sign-in is never asked for the App's Second step
- [ ] A 'Microsoft link made' signal is sent
