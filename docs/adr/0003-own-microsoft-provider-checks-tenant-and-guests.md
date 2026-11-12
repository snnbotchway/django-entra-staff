# The package's own Microsoft provider, the only provider, checks the tenant and refuses guests

allauth's Microsoft provider is plain OAuth2: it never verifies the id_token, so a token from any tenant would be accepted, and its own tenant setting only picks the endpoints. The package therefore ships its own provider app, used instead of allauth's, which asks for the `openid` scope and verifies the id_token (signature from the tenant's key set, issuer, audience, expiry) against the one tenant in `ENTRA_STAFF["TENANT_ID"]`. The issuer carries the tenant, so the issuer check is the tenant check. A guest of the tenant (a B2B guest from another tenant, or an invited personal Microsoft account) gets a token from the same issuer, so the package also refuses any id_token whose `idp` claim is present and differs from the issuer; such people need a member account in the tenant or a password User. Microsoft is the only sign-in provider the package supports, so every social account a User has counts as its Microsoft link. That keeps the linking, the leaver rule (ADR 0002) and the admin's Sign-in section simple, and it is why the system check refuses any other installed provider app (allauth's own or another app's) and a custom `provider_id` on the Microsoft app.

## Considered Options

- **allauth's provider with its tenant setting**: does not verify the token, so the tenant is not enforced.
- **The `tid` claim for guests**: a guest's `tid` is the resource tenant (ours), so it lets guests in.
- **Other providers next to Microsoft**: each would need its own leaver story; out of scope until an App needs one.

## Consequences

- A wrong-tenant token fails with allauth's generic `unknown` error, so the refusal reveals nothing about the tenant. A guest token fails with its own `guest_account` code, so the App can send the person to IT for a member account or a password User. The person already knows they are a guest, so the code tells them nothing new.
- Adding a second provider later means telling a Microsoft link apart from other social accounts everywhere the package now counts "any social account".
- The package verifies the id_token itself rather than through allauth's `jwtkit.verify_and_decode`, so it can keep the tenant's key set in the cache for a day (Microsoft's own `max-age`) instead of downloading it at every sign-in. A `kid` missing from the cached set downloads it again, so a key Microsoft rotates in works at once. allauth declined caching in allauth itself (allauth/django-allauth#4769).
