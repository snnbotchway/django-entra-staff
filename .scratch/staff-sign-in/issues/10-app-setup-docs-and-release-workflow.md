# 10: App setup docs and PyPI release workflow

Status: done
Labels: ready-for-agent
Blocked by: 09

Spec: [../spec.md](../spec.md)

**What to build:** An App developer can follow the README to install and configure the package. Releases go to PyPI only through Trusted Publishing behind a manual approval (ADR 0001).

- [ ] README covers install, settings, the concrete Account model, the headless API paths, the Microsoft provider settings, signals and service functions
- [ ] README states the passkey HTTPS and domain caveat, and how to override wording and email templates
- [ ] README tells Apps to lock hashes with `uv.lock` and set `exclude-newer`
- [ ] A release workflow publishes through PyPI Trusted Publishing and waits for manual approval
- [ ] No organisation names, wording or groups anywhere in the package
