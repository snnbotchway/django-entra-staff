# django-entra-staff

Sign-in for internal Django apps whose staff use Microsoft Entra: Microsoft sign-in for one tenant, Password sign-in with a required authenticator code for everyone else, and access through Django groups. Built on [django-allauth](https://allauth.org).

The rules are in [`GLOSSARY.md`](GLOSSARY.md) (the words this README uses, such as Account and Second step) and [`docs/adr/`](docs/adr/). In short:

- A person's first Microsoft sign-in links their Account by work email. From then on the link is the identity, the password is removed and Password sign-in is refused for good ([ADR 0002](docs/adr/0002-no-password-once-microsoft-linked.md)).
- Password sign-in always ends with a Second step: an authenticator code, a passkey or a recovery code. A passkey never signs anyone in on its own.
- Nobody creates an Account with a password. People get in by invitation, or by Microsoft sign-in if the App is Open to staff.
- The package ships no sign-in screens. The App builds them on allauth's headless API.

## Install

```sh
uv add django-entra-staff
```

This brings Django and django-allauth with its `headless`, `mfa` (TOTP, recovery codes, passkeys) and `socialaccount` extras. Python 3.12 to 3.14, Django 5.2 to 6.1, django-allauth 65.21.x.

### Lock the version

A compromised release would run inside every App, so lock it:

- Commit `uv.lock`. It records a hash for every file, and `uv sync --locked` (or `uv run --locked`) in your build refuses anything else.
- Set `exclude-newer` in your `pyproject.toml`, so a release must be a week old before your next `uv lock` can pick it up:

  ```toml
  [tool.uv]
  exclude-newer = "1 week"
  ```

## Set up an App

The test App in [`tests/testapp/`](tests/testapp/) is a complete, working example of everything below.

### The Account model

Define a concrete Account in your App, with any fields you like, and point `AUTH_USER_MODEL` at it. Email is the identifier (no username) and is unique regardless of letter case. A blocked Account is an inactive one.

```python
# accounts/models.py
from django_entra_staff.models import AbstractAccount


class Account(AbstractAccount):
    department = models.CharField(max_length=100, blank=True)
```

```python
# settings.py
AUTH_USER_MODEL = "accounts.Account"
```

If you give your model its own `Meta`, extend `AbstractAccount.Meta` so the case-insensitive email constraint stays. Run `makemigrations` and `migrate` as usual; `migrate` also creates the Access groups you declare below.

### Installed apps, middleware, URLs

```python
INSTALLED_APPS = [
    # ...Django's apps, then your Account app, then:
    "allauth",
    "allauth.account",
    "allauth.mfa",
    "allauth.headless",
    "allauth.socialaccount",
    "django_entra_staff.providers.microsoft",  # instead of allauth's Microsoft provider
    "django_entra_staff",
]

MIDDLEWARE = [
    # ...
    "allauth.account.middleware.AccountMiddleware",
]
```

```python
# urls.py
urlpatterns = [
    path("_allauth/", include("django_entra_staff.urls")),
    path("", include("django_entra_staff.providers.microsoft.urls")),
    # ...
]
```

`django_entra_staff.urls` is the only place allauth's headless URLs are included; it adds the package's own endpoints in front of them. Do not also include `allauth.headless.urls`.

Leave out `django_entra_staff.providers.microsoft` and its URL line if the App has no Microsoft sign-in (for example in local development). Do not install `allauth.socialaccount.providers.microsoft`: it never checks the tenant of the token.

### Package settings

```python
ENTRA_STAFF = {
    "TENANT_ID": "00000000-0000-0000-0000-000000000000",
    "SIGN_UP_RULE": "invite_only",
    "ACCESS_GROUPS": ["viewer", "editor", "manager"],
    "GROUP_MODE": "adding",
    "LOWEST_ACCESS_GROUP": "viewer",
}
```

| Key | Meaning |
|---|---|
| `TENANT_ID` | The one Entra tenant allowed to sign in. Required once the Microsoft provider is installed; leave it out for Password sign-in only. |
| `SIGN_UP_RULE` | `"invite_only"` (default): a Microsoft person with no Account is refused. `"open_to_staff"`: they get an Account with only the lowest access group. |
| `ACCESS_GROUPS` | Required. The App's Access groups, created as Django groups after every `migrate`. |
| `GROUP_MODE` | `"adding"` (default): an Account may hold several Access groups. `"exclusive"`: exactly one. |
| `LOWEST_ACCESS_GROUP` | The group Open to staff sign-ups get. Required for `open_to_staff`. |

The group names are yours; the package names none. Unknown keys are refused.

### allauth settings

```python
ACCOUNT_ADAPTER = "django_entra_staff.adapters.AccountAdapter"
SOCIALACCOUNT_ADAPTER = "django_entra_staff.adapters.SocialAccountAdapter"  # with Microsoft
MFA_ADAPTER = "django_entra_staff.adapters.MFAAdapter"
AUTHENTICATION_BACKENDS = ["allauth.account.auth_backends.AuthenticationBackend"]
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_VERIFICATION = "none"
MFA_SUPPORTED_TYPES = ["recovery_codes", "totp", "webauthn"]
HEADLESS_ONLY = True
```

The adapters may be subclassed. Leave `MFA_PASSKEY_LOGIN_ENABLED`, `MFA_PASSKEY_SIGNUP_ENABLED`, `ACCOUNT_LOGIN_BY_CODE_ENABLED` and `ACCOUNT_PASSWORD_RESET_BY_CODE_ENABLED` off (their default): each is a way in or a way to add a password that skips the package's rules. Leave allauth's email authentication (`SOCIALACCOUNT_EMAIL_AUTHENTICATION`, `SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT`, a provider's `EMAIL_AUTHENTICATION`) and `MFA_TRUST_ENABLED` off, and `ACCOUNT_PREVENT_ENUMERATION` on. Mount `django_entra_staff.urls` rather than allauth's headless URLs alone, so the package's guarded `account/email` and authenticator views answer. Through that view an Account with a Microsoft link cannot add an address or change its primary one (`email_change_not_supported`), and no Account can make an unverified address primary (`unverified_primary_email`): the Account's email is what a first Microsoft sign-in matches, so an unverified colleague's address would otherwise send that colleague's sign-in into the wrong Account. `HEADLESS_ONLY` must be `True`, because allauth's own pages skip the package's endpoints. Allow no other backend in `AUTHENTICATION_BACKENDS` than that one or a subclass of it: Django's `ModelBackend` and anything built on it checks passwords without refusing linked Accounts. The check also refuses permission-only backends such as django-rules or django-guardian: Django calls every backend's `authenticate`, so each one is a password path the package cannot guard. Leave `ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_CHANGE` off: a person waiting to verify their email at sign-in could change it, unverified, to a colleague's. Install no allauth provider app besides the package's Microsoft one: the package treats every social account as the Microsoft link.

A headless-only App has no allauth pages, so tell allauth and Django where the App's own frontend lives. All three `HEADLESS_FRONTEND_URLS` entries are needed, and `LOGIN_URL` is where the Django admin sends people to sign in:

```python
HEADLESS_FRONTEND_URLS = {
    "socialaccount_login_error": "/sign-in/error",  # Microsoft refusals arrive here
    "account_signup": "/sign-up",
    "account_reset_password_from_key": "/reset-password/{key}",  # the link in the reset email
}
LOGIN_URL = "/sign-in/"
```

Also needed:

- A cache shared by all workers (Redis, Memcached, a database cache). allauth's attempt limits, authenticator code replay protection and the Microsoft token replay protection live there. The per-process default is not enough with more than one worker.
- Email sending for Password reset and for allauth's notifications. On Django 6.1 and later configure it in `MAILERS` (a `"default"` entry with its `BACKEND`); without it Django warns, and Django 2028 will send no email at all.
- Strong password rules in `AUTH_PASSWORD_VALIDATORS`. They apply to a Password reset, to the Temporary password IT sets and to replacing it.

### Microsoft sign-in

1. In Entra, register an application (single tenant) with the redirect URI `https://<your host>/microsoft/login/callback/` and create a client secret.
2. Give allauth the client in settings, or as a `SocialApp` row:

   ```python
   SOCIALACCOUNT_PROVIDERS = {"microsoft": {"APP": {"client_id": "...", "secret": "..."}}}
   ```

3. The tenant comes only from `ENTRA_STAFF["TENANT_ID"]`. Do not set the provider's own `TENANT` setting; it is ignored.
4. Leave out the app's `provider_id`, in settings and in a `SocialApp` row. The system check sees only the settings, not rows in the database, so check those yourself. Microsoft is the only provider the package supports, so every social account an Account has counts as its Microsoft link; a custom `provider_id` would only confuse the sign-in URLs.

The package checks the token's signature, issuer (which contains the tenant), audience and expiry before it links or signs anyone in. A token from any other tenant is refused. Guests of your tenant (B2B guests from another tenant, or personal Microsoft accounts you invited) are refused too: their token's `idp` claim names their home identity provider instead of your tenant's issuer. Give such people a member account in your tenant, or a password Account.

Refusals come back to the page named in `socialaccount_login_error` as `?error=<code>&error_process=login`:

| Code | When |
|---|---|
| `invite_only` | No Account, and the Sign-up rule is Invite only. |
| `account_blocked` | The Account is blocked. |
| `account_already_linked` | The Account with this email is already linked to a different Microsoft person. |
| `no_work_email` | Microsoft gave no email address (Open to staff only). |
| `connect_not_supported` | Someone asked to connect a Microsoft account by hand. Links are made only at first sign-in. |

Any other failure, such as a token from the wrong tenant or from a guest, comes back as `error=unknown`.

### Django admin

Register the package's admin page for your Account:

```python
# accounts/admin.py
from django.contrib import admin
from django_entra_staff.admin import AccountAdmin
from .models import Account

admin.site.register(Account, AccountAdmin)
```

`AccountAdmin` is Django's `UserAdmin` fitted to the package's rules, so it looks and works like the user admin IT already knows. The list shows email, Access groups, Microsoft link, password status, Second step status, Active and last sign-in, with Django's filters (Django admin access, superuser, Active, groups) and search by email. The change page keeps `UserAdmin`'s sections (Permissions, Important dates) and adds a read-only Sign-in section: Microsoft link, password status and Second step status. The email is read-only once the Account exists. The admin calls Accounts "users", as Django does; to use another name, set `verbose_name` and `verbose_name_plural` in your Account's `Meta`.

There is no password anywhere on it (ADR 0002): no password field, no change-password link, and the `<id>/password/` page refuses. Django's own "Change password" page in the admin header refuses anyone with a Microsoft link. What IT changes goes through the service functions with the signed-in Account as `acting_account`, so every rule and signal applies:

- **Add** invites a person by email with chosen Access groups (`invite_account`). There are no password fields. Creating the first App admin of a new App works this way.
- **Access groups** is Django's groups picker, offering only the declared Access groups, and is saved with `set_access_groups`. With exclusive Access groups, choosing anything but one is a form error and nothing is saved. Django groups the App didn't declare are left alone.
- **Active** unticked blocks the Account (`block_account`); ticked again, it unblocks it (`unblock_account`).
- **Django admin access** and **superuser status** are the Account's own `is_staff` and `is_superuser`, set only here and never by Access groups.
- **Actions** block or unblock the selected Accounts, set a Temporary password, clear the Second step, and remove a Microsoft link, next to Django's delete.

Subclass `AccountAdmin` to add columns or fields. Override the Temporary password form with a template at `django_entra_staff/set_temporary_password.html`.

The admin sign-in page is replaced on the default `admin.site`: it sends people to `LOGIN_URL`, so the admin opens only after Microsoft sign-in or password plus Second step. An App with its own `AdminSite` must wrap its `login` the same way:

```python
from allauth.account.decorators import secure_admin_login

my_site.login = secure_admin_login(my_site.login)
```

Being an App admin never grants Django admin access. Only IT and developers hold `is_staff`, set on the Account itself.

### System checks

`manage.py check` fails at start-up, before anyone signs in, when the settings above are inconsistent (ids `entra_staff.E001` to `E030`): a bad or incomplete `ENTRA_STAFF`, an `AUTH_USER_MODEL` that is not an Account, the package's adapters or Microsoft provider not in place, `webauthn` missing from `MFA_SUPPORTED_TYPES`, passkey sign-in or sign-up switched on, `HEADLESS_ONLY` off, sign-in or Password reset by emailed code switched on, a backend other than allauth's (or a subclass of it) in `AUTHENTICATION_BACKENDS`, allauth's email authentication or MFA trust switched on, `ACCOUNT_PREVENT_ENUMERATION` off, allauth's own `account/email` or authenticator management views answering instead of the package's, a `provider_id` on the Microsoft app in `SOCIALACCOUNT_PROVIDERS`, changing the email while verifying it at sign-in switched on, or an installed app that brings a sign-in provider other than Microsoft (allauth's own or any other).

## The sign-in API

The App's frontend calls allauth's headless browser API under `/_allauth/browser/v1/` (and `/_allauth/app/v1/` for native clients, unless `HEADLESS_CLIENTS` leaves them out), with allauth's error shape: `{"errors": [{"code": "...", "message": "..."}]}`. Follow [allauth's headless documentation](https://docs.allauth.org/en/latest/headless/) for sessions, CSRF and the flow objects. The package adds these paths and error codes:

| Path | Use |
|---|---|
| `POST auth/login` | Password sign-in (email, password). An Account with a Microsoft link gets `use_microsoft_signin`, but only when the password was right; otherwise the ordinary `email_password_mismatch`. |
| `POST auth/provider/redirect` | Start Microsoft sign-in (`provider`: `microsoft`, `callback_url`, `process`: `login`), as a form post. |
| `POST auth/password/request`, `POST auth/password/reset` | Password reset. The request answers the same whether or not the email exists or can be reset. |
| `POST auth/2fa/authenticate` | Second step with an authenticator code or a recovery code. |
| `GET`, `POST auth/webauthn/authenticate` | Second step with a passkey. |
| `GET`, `POST auth/2fa/setup` | Set up the first Second step with an authenticator (`GET` returns the secret, `POST` the code). The response carries the recovery codes. |
| `GET`, `POST auth/2fa/setup/webauthn` | Set up the first Second step with a passkey. Also returns recovery codes. |
| `POST auth/password/replace` | Replace a Temporary password (`new_password`). |
| `GET auth/session` | Whether the person is signed in, and which flows are pending. |
| `account/authenticators/...` | Manage authenticators and passkeys once signed in. Removing the last Second step is refused with `cannot_delete_authenticator`. |
| `POST account/password/change` | Set or change the password once signed in. Refused with `use_microsoft_signin` for an Account with a Microsoft link, as is completing a Password reset for one. |
| `DELETE account/providers` | Refused with `disconnect_not_supported` for the Microsoft link. Only IT removes it, through `remove_microsoft_link`. |

After a correct password the response is `401` with `data.flows` listing what is pending, in this fixed order: `mfa_authenticate` or `second_step_setup`, then `replace_password`. The sign-in is complete only when none is pending. Other endpoints refuse a half-finished sign-in. Microsoft sign-in has none of these steps.

## Service functions

Use these from the App's own screens, commands and tests, never the models and allauth directly. Import them from `django_entra_staff.services`. They apply the package's rules, send the signals below, and raise `StaffError` with a stable `code` (an `ErrorCode` from `django_entra_staff.errors`) when they refuse.

| Function | Does |
|---|---|
| `invite_account(email, access_groups, *, acting_account=None)` | Makes an Account with no password; the person then uses Microsoft sign-in. |
| `set_access_groups(account, access_groups, *, acting_account=None)` | Replaces the Account's Access groups. |
| `block_account(account, *, acting_account=None)`, `unblock_account(...)` | Stops and restores sign-in. |
| `set_temporary_password(account, password, *, acting_account=None)` | For the Django admin only. Refused for a linked Account. |
| `clear_authenticators(account, *, acting_account=None)` | Removes all authenticators, passkeys and recovery codes; returns whether anything was removed, and sends its signal only then. |
| `remove_microsoft_link(account, *, acting_account=None)` | Lets the next Microsoft sign-in link again. The Account keeps no password. |
| `has_access_group(account, access_group)` | Whether the Account holds the group; `False` when not signed in. |
| `has_microsoft_link(account)` | Whether the Account has a Microsoft link, so it can never have a password. |

Error codes: `undeclared_access_group`, `exclusive_needs_one_group`, `account_exists`, `microsoft_linked`.

Only `set_temporary_password` takes a password. No function returns password data, and none touches Django admin access.

## Signals

In `django_entra_staff.signals`. Each is sent with the Account class as `sender`, and `account` and `acting_account` (the Account that made the change, or `None`):

| Signal | Sent when |
|---|---|
| `microsoft_link_made` | A first Microsoft sign-in linked an Account, including one Open to staff has just made. |
| `account_signed_up_open_to_staff` | Open to staff made an Account. |
| `access_groups_changed` | Access groups changed. Also has `previous_groups` and `groups` (frozensets). |
| `account_blocked`, `account_unblocked` | An Account was blocked or unblocked. |
| `temporary_password_set` | IT set a Temporary password. |
| `authenticators_cleared` | IT cleared an Account's authenticators, passkeys and recovery codes. |
| `microsoft_link_removed` | IT removed an Account's Microsoft link. Not sent when there was none. |

They are sent inside the transaction that makes the change, so a receiver that raises undoes it. Do slow or outward-facing work, such as email, in `transaction.on_commit`.

## Passkeys

A passkey is the Second step only. It is tied to the App's own domain, taken from the request host, so a passkey for one App does not work in another. Two things follow:

- **HTTPS.** Browsers allow passkeys only on HTTPS (`localhost` is fine in development).
- **Changing the domain.** Existing passkeys stop working if the App moves to a different domain. People fall back on an authenticator code or a recovery code, or IT clears their Second step in the Django admin so they set up a new one.

The package does not call the browser. The App's frontend uses the browser's WebAuthn API and passes the results to the passkey paths above.

## Wording and email templates

All text the package shows goes through Django translation, and no wording names an organisation.

- **Error messages** (such as "Use Microsoft sign-in for this account."): translate them in your own locale catalog (listed in `LOCALE_PATHS`), or subclass the adapters and change `error_messages`.
- **Emails** (Password reset, and allauth's notices when an authenticator or passkey is added or removed) are allauth's templates, `account/email/*` and `mfa/email/*`. Override one by adding a template with the same name in a template directory listed in `TEMPLATES["DIRS"]`, which Django searches before installed apps.
- The Temporary password form in the Django admin is the only template the package ships (see above).

## Development

Needs [uv](https://docs.astral.sh/uv/). The tests run the test App (`tests/testapp/`) against SQLite.

```sh
uv run pytest                 # tests on the newest Python and Django that uv picks
uv run --python 3.12 --isolated --with "django==5.2.*" pytest   # one cell of the CI matrix
uv run ruff check . && uv run ruff format --check . && uv run vulture
```

## Releasing

Releases go to PyPI only through [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) from GitHub Actions ([`release.yml`](.github/workflows/release.yml)). There is no PyPI token anywhere, and the publish job waits for a maintainer to approve it.

1. In GitHub, open **Actions → Release → Run workflow** on `main` and pick the size: **patch** for fixes, **minor** for new features, **major** for changes that break Apps. For the first release (the version is `0.0.0` until then), pick **minor** to publish `0.1.0`.
2. The workflow bumps the version, lints, tests and builds with uv, then commits `Release vX.Y.Z` to `main` and tags it. If a test fails, nothing is committed.
3. It then waits in the `pypi` environment. Open the run and choose **Review deployments → Approve** to publish.

Each version number can be published once, ever: to fix a bad release, publish the next one. Pushing a `v*` tag by hand also releases; the tag must then match the version in `pyproject.toml`.

One-time setup, in GitHub and PyPI:

- GitHub: create an environment named `pypi` (Settings, Environments) with **Required reviewers** set to the maintainers, and allow only the `main` branch and `v*` tags to deploy to it.
- PyPI: add a trusted publisher for the project `django-entra-staff` (for a first release, a pending publisher under Your account, Publishing): this repository, workflow `release.yml`, environment `pypi`.
