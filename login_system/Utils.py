from .models.PreviousPassword import PreviousPassword


def savePre(self, *args, **kwargs):
    if not self.pk or self.pk == 1:
        previous_password = PreviousPassword(
            user=self, password=self.password
        )
        previous_password.save()
