"""Names vulture reports as unused that a framework calls by name.

Each group says who calls them. Add a name here only when its caller is outside
this repo; dead code of our own gets deleted instead.
"""

# ruff: noqa
# fmt: off
_ = object()

# allauth adapter hooks (adapters.py)
_.is_open_for_signup
_.validate_disconnect
_.pre_social_login
accounts              # validate_disconnect(account, accounts) keeps allauth's parameter names

# allauth headless input and view hooks (views.py)
input_class
_.get_input_kwargs
_.clean_new_password

# allauth provider wiring: default_urlpatterns imports views.oauth2_login by name
oauth2_adapter_class
oauth2_login

# Django admin options and hooks (admin.py)
add_form
add_form_template
add_fieldsets
fieldsets
readonly_fields
list_display
search_fields
ordering
actions
help_texts
_.clean_email
_.save_model
_.user_change_password
form_url              # part of UserAdmin.user_change_password's signature
_.can_add_related     # read by Django's related-field widget
_.current_app         # read by Django's url reversing in admin templates

# Django app config (apps.py)
EntraStaffConfig
label
verbose_name
_.ready

# Django user model and manager (models.py)
use_in_migrations
_.get_by_natural_key
USERNAME_FIELD
EMAIL_FIELD
date_joined
abstract
verbose_name_plural
constraints

# requests.Response fields read by allauth (tests/conftest.py fake Microsoft)
headers
_.text
_.raise_for_status

# fido2 CtapDevice interface (tests/software_authenticator.py)
_.enabled
capabilities
_.list_devices
_.call
cmd
on_keepalive

# Named by its dotted path in a settings check test (tests/testapp/backends.py)
StaffBackend
