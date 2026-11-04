from allauth.account.adapter import DefaultAccountAdapter


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        """Nobody creates their own Account with a password."""
        return False

    def get_login_stages(self):
        stages = super().get_login_stages()
        stages.insert(
            stages.index("allauth.mfa.stages.AuthenticateStage") + 1,
            "django_entra_staff.stages.SecondStepSetupStage",
        )
        return stages
