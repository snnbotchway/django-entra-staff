import jwt
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.providers.microsoft.views import (
    MicrosoftGraphOAuth2Adapter as AllauthMicrosoftGraphOAuth2Adapter,
)
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2CallbackView,
    OAuth2LoginView,
)
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured

from django_entra_staff.conf import MICROSOFT_NEEDS_TENANT_ID_MESSAGE, get_settings

DEFAULT_LOGIN_URL = "https://login.microsoftonline.com"
# Microsoft serves the key set with `max-age=86400`.
KEY_SET_CACHE_SECONDS = 24 * 60 * 60


class GuestAccountError(OAuth2Error):
    """The id_token belongs to a guest of the tenant (ADR 0003)."""


class MicrosoftGraphOAuth2Adapter(AllauthMicrosoftGraphOAuth2Adapter):
    """The Microsoft Graph adapter, verifying the id_token's tenant.

    The tenant is `ENTRA_STAFF["TENANT_ID"]`, not the provider's own tenant
    setting: the App configures the tenant once, and the authorize and token
    endpoints, the key set and the issuer all come from it.
    """

    def _build_tenant_url(self, path):
        return f"{self._login_url()}/{self._tenant_id()}{path}"

    def _login_url(self):
        app = get_adapter().get_app(self.request, provider=self.provider_id)
        return app.settings.get("login_url", DEFAULT_LOGIN_URL)

    def _tenant_id(self):
        tenant_id = get_settings().tenant_id
        if not tenant_id:
            raise ImproperlyConfigured(MICROSOFT_NEEDS_TENANT_ID_MESSAGE)
        return tenant_id

    def complete_login(self, request, app, token, **kwargs):
        self._verify_tenant(app, kwargs.get("response") or {})
        return super().complete_login(request, app, token, **kwargs)

    def _verify_tenant(self, app, token_response):
        id_token = token_response.get("id_token")
        if not id_token:
            raise OAuth2Error("The token response carries no id_token.")
        issuer = self._build_tenant_url("/v2.0")
        claims = self._verify_and_decode(id_token, issuer=issuer, audience=app.client_id)
        # A B2B guest gets a token from the tenant's issuer too, so the issuer
        # alone lets guests in. Entra's `idp` claim names who authenticated the
        # person: absent or equal to the issuer for the tenant's own members, and
        # another tenant's STS URI or `live.com` for a guest.
        idp = claims.get("idp")
        if idp is not None and idp != issuer:
            raise GuestAccountError("The id_token belongs to a guest of the tenant.")

    def _verify_and_decode(self, id_token, *, issuer, audience):
        """allauth's `jwtkit.verify_and_decode`, with the key set kept in the cache.

        allauth downloads the key set at every sign-in, about 0.7 s against
        Microsoft.
        """
        try:
            header = jwt.get_unverified_header(id_token)
            key = self._signing_key(header.get("kid"))
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=[header["alg"]],
                issuer=issuer,
                audience=audience,
                options={"verify_iss": True, "verify_aud": True, "verify_exp": True},
            )
        except (jwt.PyJWTError, KeyError) as e:
            raise OAuth2Error("Invalid id_token") from e
        jwtkit.verify_jti(claims)
        return claims

    def _signing_key(self, kid):
        """The tenant's public key named `kid`.

        A `kid` missing from the cached key set downloads it again, so a key
        Microsoft has rotated in signs in at once.
        """
        keys_url = self._build_tenant_url("/discovery/v2.0/keys")
        cache_key = f"django_entra_staff:microsoft_keys:{keys_url}"
        keys = cache.get(cache_key)
        key = keys and jwtkit.lookup_kid_jwk(keys, kid)
        if key is None:
            with get_adapter().get_requests_session() as session:
                response = session.get(keys_url)
                response.raise_for_status()
                keys = response.json()
            cache.set(cache_key, keys, KEY_SET_CACHE_SECONDS)
            key = jwtkit.lookup_kid_jwk(keys, kid)
        if key is None:
            raise OAuth2Error(f"Invalid 'kid': '{kid}'")
        return key


oauth2_login = OAuth2LoginView.adapter_view(MicrosoftGraphOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(MicrosoftGraphOAuth2Adapter)
