# Generated by Django 4.2 on 2023-05-14 08:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login_system', '0003_account_forget_password_token_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='account',
            name='forget_password_token',
            field=models.CharField(default=None, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='forget_password_token',
            field=models.CharField(default=None, max_length=100, null=True),
        ),
    ]