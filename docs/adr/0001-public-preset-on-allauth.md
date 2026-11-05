# A public preset on top of django-allauth, not shared private code

Three internal Django apps each wrote their own Microsoft sign-in, Password sign-in and User model, and drifted apart within weeks. We put the shared rules in one public package, `django-entra-staff`, published on PyPI from a personal GitHub user and written fresh rather than copied from the company repos. The package is a thin layer: `django-allauth` does the security-critical work (the Microsoft protocol, token checks, password storage, TOTP, recovery codes, attempt limits and the headless JSON API), and this package adds only the policy: the User model, Access groups, the Sign-up rule, linking by work email once, refusing Password sign-in once linked, requiring the Second step, an admin page, service functions and signals.

## Considered Options

- **Private shared repo** (git dependency or submodule): needs a GitHub token in every Docker build and CI run, or submodules that are easy to forget to update.
- **Our own code without allauth**: keeps our exact URL and error shapes, but we would own TOTP, rate limiting and OAuth code, and their security fixes, in public.
- **A central sign-in service** that every app trusts: a security-critical system to run forever, doing a job Entra already does.

## Consequences

- Apps use allauth's API paths (`/_allauth/browser/v1/...`) and error shape, and the Microsoft link is allauth's `SocialAccount` row rather than a field on the User.
- A compromised release would run in every App, so Apps lock hashes with `uv.lock`, set `exclude-newer = "1 week"`, and the package publishes only through PyPI Trusted Publishing behind a manual approval.
