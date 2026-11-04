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
from django.core.exceptions import ImproperlyConfigured

from django_entra_staff.conf import get_settings

DEFAULT_LOGIN_URL = "https://login.microsoftonline.com"


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
            raise ImproperlyConfigured("Microsoft sign-in needs ENTRA_STAFF['TENANT_ID'].")
        return tenant_id

    def complete_login(self, request, app, token, **kwargs):
        self._verify_tenant(app, kwargs.get("response") or {})
        return super().complete_login(request, app, token, **kwargs)

    def _verify_tenant(self, app, token_response):
        id_token = token_response.get("id_token")
        if not id_token:
            raise OAuth2Error("The token response carries no id_token.")
        issuer = self._build_tenant_url("/v2.0")
        claims = jwtkit.verify_and_decode(
            credential=id_token,
            keys_url=self._build_tenant_url("/discovery/v2.0/keys"),
            issuer=issuer,
            audience=app.client_id,
            lookup_kid=jwtkit.lookup_kid_jwk,
        )
        # A B2B guest gets a token from the tenant's issuer too, so the issuer
        # alone lets guests in. Entra's `idp` claim names who authenticated the
        # person: absent or equal to the issuer for the tenant's own members, and
        # another tenant's STS URI or `live.com` for a guest.
        idp = claims.get("idp")
        if idp is not None and idp != issuer:
            raise OAuth2Error("The id_token belongs to a guest of the tenant.")


oauth2_login = OAuth2LoginView.adapter_view(MicrosoftGraphOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(MicrosoftGraphOAuth2Adapter)
