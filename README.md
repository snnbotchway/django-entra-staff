# django-entra-staff

Sign-in for internal Django apps whose staff use Microsoft Entra: Microsoft sign-in for one tenant, Password sign-in with a required authenticator code for everyone else, and access through Django groups. Built on [django-allauth](https://allauth.org).

Not built yet. The design is in [`GLOSSARY.md`](GLOSSARY.md) and [`docs/adr/`](docs/adr/).

## Development

Needs [uv](https://docs.astral.sh/uv/). The tests run a small test App (`tests/testapp/`) against SQLite.

```sh
uv run pytest                 # tests on the newest Python and Django that uv picks
uv run --python 3.12 --isolated --with "django==5.2.*" pytest   # one cell of the CI matrix
uv run ruff check . && uv run ruff format --check .
```
