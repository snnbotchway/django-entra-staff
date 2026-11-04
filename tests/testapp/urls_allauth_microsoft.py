"""The URLconf of an App that wired Microsoft sign-in the allauth way instead
of the package's: the callback then runs allauth's adapter, which never
verifies the id_token's tenant."""

from django.urls import include, path

urlpatterns = [
    path("", include("allauth.socialaccount.providers.microsoft.urls")),
]
