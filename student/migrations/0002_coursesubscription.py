# Generated by Django 3.1.1 on 2020-11-02 11:19

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('mysite', '0006_lecturecomment'),
        ('student', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CourseSubscription',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('course', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='mysite.course', verbose_name='title')),
                ('student', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='student.studentinfo', verbose_name='username')),
            ],
        ),
    ]
