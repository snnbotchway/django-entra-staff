# 06: Open to staff Sign-up rule

Status: open
Labels: ready-for-agent
Blocked by: 03, 05

Spec: [../spec.md](../spec.md)

**What to build:** In an App set to Open to staff, a person with no Account who completes Microsoft sign-in gets a new Account holding only the lowest access group, and the App is told through a signal.

- [ ] With Open to staff, first Microsoft sign-in makes an Account with the lowest access group only, and links it
- [ ] A sign-up signal is sent
- [ ] The system check refuses Open to staff without a lowest access group
- [ ] Invite only behaviour is unchanged
