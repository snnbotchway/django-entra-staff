# 01: Package skeleton and Password sign-in

Status: done
Labels: ready-for-agent
Blocked by: None (can start immediately)

Spec: [../spec.md](../spec.md)

**What to build:** An installable package that an App can add to its settings, with a minimal test App inside the test suite. A person whose Account has a password can sign in through allauth's headless browser API. Nobody can create their own Account with a password. This sets up the test App and the main test seam (headless HTTP API through the Django test client) that every later ticket uses.

- [ ] Abstract Account base: email as the identifier, no username, unique ignoring letter case; blocked means inactive
- [ ] The test App defines a concrete Account subclass and uses it as its user model
- [ ] One settings dict for the package; a Django system check refuses inconsistent settings, with a test for each refusal
- [ ] The Sign-up rule and group modes are each defined once as `TextChoices` or `StrEnum`
- [ ] Password sign-in through the headless browser API opens the Account; a wrong password gets allauth's usual error and its attempt limits apply
- [ ] Password sign-up is refused
- [ ] CI runs the tests on the supported Django, allauth and Python versions; the supported allauth range is pinned
