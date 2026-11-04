from allauth.headless import app_settings as headless_settings
from allauth.headless.constants import Client
from django.urls import path

from .views import SecondStepSetupView

urlpatterns = []
if Client.BROWSER in headless_settings.CLIENTS:
    urlpatterns.append(
        path(
            "browser/v1/auth/2fa/setup",
            SecondStepSetupView.as_api_view(client=Client.BROWSER),
            name="second_step_setup",
        )
    )
if Client.APP in headless_settings.CLIENTS:
    urlpatterns.append(
        path(
            "app/v1/auth/2fa/setup",
            SecondStepSetupView.as_api_view(client=Client.APP),
            name="second_step_setup_app",
        )
    )
