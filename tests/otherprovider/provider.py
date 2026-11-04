"""A sign-in provider that does not come from allauth, for the E030 check."""

from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider


class OtherProvider(OAuth2Provider):
    id = "other"
    name = "Other"


provider_classes = [OtherProvider]
