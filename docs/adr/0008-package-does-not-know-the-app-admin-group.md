# The package does not know which Access group is App admin

Each App names its Access groups and its Lowest access in settings, but not which group is App admin. Each App decides in its own screens who may manage people, and IT can always give someone the App admin group in the Django admin. An earlier design had an `APP_ADMIN_GROUP` setting and refused to let the last App admin lose the group; we dropped both, because IT can always make someone App admin in the Django admin, so the rule only got in the way, and nothing else in the package read the setting.

Lowest access is still named, not inferred from order, because Open to staff sign-ups need exactly one group and that must work in both adding and exclusive modes.
