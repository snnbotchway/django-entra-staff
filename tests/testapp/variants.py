"""The `ENTRA_STAFF` dicts the test App is run with. Apply one with `override_settings`."""

INVITE_ONLY_ADDING = {
    "TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "SIGN_UP_RULE": "invite_only",
    "ACCESS_GROUPS": ["viewer", "editor", "manager"],
    "LOWEST_ACCESS_GROUP": "viewer",
}

OPEN_TO_STAFF_ADDING = {**INVITE_ONLY_ADDING, "SIGN_UP_RULE": "open_to_staff"}

ALL = [INVITE_ONLY_ADDING, OPEN_TO_STAFF_ADDING]
