from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path


def sign_in_page(request):
    """The App's own frontend sign-in screen, which drives the headless flows."""
    return HttpResponse("Sign in")


urlpatterns = [
    path("admin/", admin.site.urls),
    path("sign-in/", sign_in_page),
    path("_allauth/", include("django_entra_staff.urls")),
    path("", include("django_entra_staff.providers.microsoft.urls")),
]
