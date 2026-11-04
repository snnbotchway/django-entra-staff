from allauth.socialaccount.providers.microsoft.provider import (
    MicrosoftGraphProvider as AllauthMicrosoftGraphProvider,
)

from .views import MicrosoftGraphOAuth2Adapter


class MicrosoftGraphProvider(AllauthMicrosoftGraphProvider):
    oauth2_adapter_class = MicrosoftGraphOAuth2Adapter

    def get_scope(self):
        scope = list(super().get_scope())
        if "openid" not in scope:
            # The id_token carries the tenant the adapter verifies.
            scope.append("openid")
        return scope


provider_classes = [MicrosoftGraphProvider]
