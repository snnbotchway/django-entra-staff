from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("_allauth/", include("allauth.headless.urls")),
    path("_allauth/", include("django_entra_staff.urls")),
    path("", include("django_entra_staff.providers.microsoft.urls")),
]
