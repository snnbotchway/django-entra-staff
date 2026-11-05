from tests.testapp.variants import INVITE_ONLY_ADDING

SECRET_KEY = "test-only"
DEBUG = False
ALLOWED_HOSTS = ["testserver"]
ROOT_URLCONF = "tests.testapp.urls"
LOGIN_URL = "/sign-in/"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "allauth",
    "allauth.account",
    "allauth.mfa",
    "allauth.headless",
    "allauth.socialaccount",
    "django_entra_staff.providers.microsoft",
    "django_entra_staff",
    "tests.testapp",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    }
]

AUTH_USER_MODEL = "testapp.User"
AUTHENTICATION_BACKENDS = ["allauth.account.auth_backends.AuthenticationBackend"]

ENTRA_STAFF = INVITE_ONLY_ADDING

ACCOUNT_ADAPTER = "django_entra_staff.adapters.AccountAdapter"
SOCIALACCOUNT_ADAPTER = "django_entra_staff.adapters.SocialAccountAdapter"
MFA_ADAPTER = "django_entra_staff.adapters.MFAAdapter"
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_VERIFICATION = "none"
MFA_SUPPORTED_TYPES = ["recovery_codes", "totp", "webauthn"]
HEADLESS_ONLY = True
HEADLESS_FRONTEND_URLS = {
    "socialaccount_login_error": "/next",
    "account_confirm_email": "/confirm-email/{key}",
    "account_signup": "/sign-up",
    "account_reset_password_from_key": "/reset-password/{key}",
}

SOCIALACCOUNT_PROVIDERS = {
    "microsoft": {"APP": {"client_id": "test-client-id", "secret": "test-secret"}}
}

MAILERS = {"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}}
