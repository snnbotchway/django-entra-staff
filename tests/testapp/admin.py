from django.contrib import admin

from django_entra_staff.admin import AccountAdmin

from .models import Account

admin.site.register(Account, AccountAdmin)
