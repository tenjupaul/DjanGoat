# -*- coding: utf-8 -*-

# Generated by Django 1.11.1 on 2017-06-20 23:08
from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Analytics',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=255)),
                ('referrer', models.CharField(max_length=255)),
                ('user_agent', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(verbose_name='date created')),
                ('updated_at', models.DateTimeField(verbose_name='date updated')),
            ],
            options={
                'db_table': 'app_analytics',
            },
        ),
        migrations.CreateModel(
            name='Benefits',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_benefits',
            },
        ),
        migrations.CreateModel(
            name='KeyManagement',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('iv', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_key_managements',
            },
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('creator_id', models.PositiveIntegerField()),
                ('receiver_id', models.PositiveIntegerField()),
                ('message', models.TextField(max_length=65535)),
                ('read', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_messages',
            },
        ),
        migrations.CreateModel(
            name='Note',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('note_name', models.CharField(max_length=200)),
                ('pub_date', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_notes',
            },
        ),
        migrations.CreateModel(
            name='PaidTimeOff',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sick_days_taken', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('sick_days_earned', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('pto_taken', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('pto_earned', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_paid_time_offs',
            },
        ),
        migrations.CreateModel(
            name='Pay',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bank_account_num', models.CharField(max_length=255)),
                ('bank_routing_num', models.CharField(max_length=255)),
                ('percent_of_deposit', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_pays',
            },
        ),
        migrations.CreateModel(
            name='Performance',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_submitted', models.DateField(verbose_name='date submitted')),
                ('score', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('comments', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_performances',
            },
        ),
        migrations.CreateModel(
            name='Retirement',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total', models.CharField(max_length=255)),
                ('employee_contrib', models.CharField(max_length=255)),
                ('employer_contrib', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'app_retirements',
            },
        ),
        migrations.CreateModel(
            name='Schedule',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_begin', models.DateField()),
                ('date_end', models.DateField()),
                ('event_name', models.CharField(max_length=255)),
                ('event_type', models.CharField(max_length=255)),
                ('event_desc', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('pto', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='app.PaidTimeOff')),
            ],
            options={
                'db_table': 'app_schedules',
            },
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(max_length=255)),
                ('password', models.CharField(max_length=255)),
                ('is_admin', models.BooleanField()),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('user_id', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('auth_token', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='WorkInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('income', models.CharField(max_length=255)),
                ('bonuses', models.CharField(max_length=255)),
                ('years_worked', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(4294967295)])),
                ('SSN', models.CharField(max_length=255)),
                ('DoB', models.DateField(verbose_name='DoB')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('encrypted_ssn', models.BinaryField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.User')),
            ],
            options={
                'db_table': 'app_work_infos',
            },
        ),
        migrations.AddField(
            model_name='schedule',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.User'),
        ),
        migrations.AddField(
            model_name='retirement',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.User'),
        ),
        migrations.AddField(
            model_name='performance',
            name='reviewer',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='r_id', to='app.User'),
        ),
        migrations.AddField(
            model_name='performance',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='u_id', to='app.User'),
        ),
        migrations.AddField(
            model_name='pay',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.User'),
        ),
        migrations.AddField(
            model_name='paidtimeoff',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.User'),
        ),
        migrations.AddField(
            model_name='keymanagement',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.User'),
        ),
    ]
