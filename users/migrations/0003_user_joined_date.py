# Generated by Django 5.1 on 2024-09-23 20:37

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_alter_user_role"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="joined_date",
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
