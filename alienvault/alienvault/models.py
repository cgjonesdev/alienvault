from django.db import models


class User(models.Model):
    alienvaultid = models.CharField(max_length=255)
    visits = models.CharField(max_length=1024)
