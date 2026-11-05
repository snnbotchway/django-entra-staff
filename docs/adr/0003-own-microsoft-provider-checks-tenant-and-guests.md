# The package's own Microsoft provider, the only provider, checks the tenant and refuses guests

allauth's Microsoft provider is plain OAuth2: it never verifies the id_token, so a token from any tenant would be accepted, and its own tenant setting only picks the endpoints. The package therefore ships its own provider app, used instead of allauth's, which asks for the `openid` scope and verifies the id_token (signature from the tenant's key set, issuer, audience, expiry) against the one tenant in `ENTRA_STAFF["TENANT_ID"]`. The issuer carries the tenant, so the issuer check is the tenant check. A guest of the tenant (a B2B guest from another tenant, or an invited personal Microsoft account) gets a token from the same issuer, so the package also refuses any id_token whose `idp` claim is present and differs from the issuer; such people need a member account in the tenant or a password Account. Microsoft is the only sign-in provider the package supports, so every social account an Account has counts as its Microsoft link. That keeps the linking, the leaver rule (ADR 0002) and the admin's Sign-in section simple, and it is why the system check refuses any other installed provider app (allauth's own or another app's) and a custom `provider_id` on the Microsoft app.

## Considered Options

- **allauth's provider with its tenant setting**: does not verify the token, so the tenant is not enforced.
- **The `tid` claim for guests**: a guest's `tid` is the resource tenant (ours), so it lets guests in.
- **Other providers next to Microsoft**: each would need its own leaver story; out of scope until an App needs one.

## Consequences

- A wrong-tenant or guest token fails with allauth's generic `unknown` error, so the refusal reveals nothing about the tenant.
- Adding a second provider later means telling a Microsoft link apart from other social accounts everywhere the package now counts "any social account".
