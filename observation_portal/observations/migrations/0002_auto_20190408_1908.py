# Generated by Django 2.1.7 on 2019-04-08 19:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('observations', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='configurationstatus',
            options={'ordering': ['id'], 'verbose_name_plural': 'Configuration statuses'},
        ),
    ]
