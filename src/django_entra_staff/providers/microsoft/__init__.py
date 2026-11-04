"""Microsoft sign-in for the App's one Entra tenant.

The App installs this provider app instead of allauth's
`allauth.socialaccount.providers.microsoft`: allauth's adapter is plain OAuth2
and never verifies the id_token, so a token from any tenant would be accepted.
This one requests the `openid` scope and verifies the id_token against the
App's one tenant (`ENTRA_STAFF["TENANT_ID"]`): signature via the tenant key
set, issuer, audience and expiry. The id_token's issuer carries the tenant, so
the issuer check is the tenant check. Guests of the tenant are refused too, by
the id_token's `idp` claim (see `views.MicrosoftGraphOAuth2Adapter`).
"""
