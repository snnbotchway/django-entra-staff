from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class AccountManager(BaseUserManager):
    use_in_migrations = True

    def get_by_natural_key(self, email):
        return self.get(email__iexact=email)

    def create_user(self, email, password=None, **fields):
        if not email:
            raise ValueError("An Account needs an email.")
        account = self.model(email=self.normalize_email(email), **fields)
        account.set_password(password)
        account.save(using=self._db)
        return account

    def create_superuser(self, email, password=None, **fields):
        fields.setdefault("is_staff", True)
        fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **fields)


class AbstractAccount(AbstractBaseUser, PermissionsMixin):
    """An Account is one person's record in one App. Blocked means inactive."""

    email = models.EmailField(_("email address"), unique=True)
    is_active = models.BooleanField(_("active"), default=True)
    is_staff = models.BooleanField(_("Django admin access"), default=False)
    must_replace_password = models.BooleanField(_("must replace password"), default=False)
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    objects = AccountManager()

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
