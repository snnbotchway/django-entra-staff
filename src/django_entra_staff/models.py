from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    use_in_migrations = True

    def get_by_natural_key(self, email):
        return self.get(email__iexact=email)

    def create_user(self, email, password=None, **fields):
        if not email:
            raise ValueError("A User needs an email.")
        user = self.model(email=self.normalize_email(email), **fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **fields):
        fields.setdefault("is_staff", True)
        fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **fields)


class AbstractUser(AbstractBaseUser, PermissionsMixin):
    """A User is one person's record in one App. Blocked means inactive."""

    email = models.EmailField(_("email address"), unique=True)
    # As on Django's AbstractUser. A Microsoft sign-in fills them (adapters.py).
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    is_active = models.BooleanField(_("active"), default=True)
    is_staff = models.BooleanField(_("Django admin access"), default=False)
    must_replace_password = models.BooleanField(_("must replace password"), default=False)
    # When the current Temporary password was set; it stops working after
    # ENTRA_STAFF["TEMPORARY_PASSWORD_LIFETIME"].
    temporary_password_set_at = models.DateTimeField(
        _("Temporary password set at"), null=True, blank=True, editable=False
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"

    class Meta:
        abstract = True
        # Django admin users know this screen as "Users"; Apps can rename it.
        verbose_name = _("user")
        verbose_name_plural = _("users")
        constraints = [
            models.UniqueConstraint(Lower("email"), name="%(app_label)s_%(class)s_email_ci_unique"),
        ]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        return self.first_name
