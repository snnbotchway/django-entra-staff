"""The URLconf of an App that mounted allauth's headless endpoints directly
instead of the package's: the package's guarded views never get the request,
so the last Second step and the linked User's email can be changed."""

from django.urls import include, path

urlpatterns = [
    path("_allauth/", include("allauth.headless.urls")),
    path("", include("django_entra_staff.providers.microsoft.urls")),
]
