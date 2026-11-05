from django.contrib import admin

from django_entra_staff.admin import UserAdmin

from .models import User

admin.site.register(User, UserAdmin)
