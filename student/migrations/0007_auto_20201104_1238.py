# Generated by Django 3.1.1 on 2020-11-04 07:08

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('mysite', '0007_course_course_price'),
        ('student', '0006_auto_20201104_1008'),
    ]

    operations = [
        migrations.AddField(
            model_name='coursesubscription',
            name='order_id',
            field=models.CharField(default='-', max_length=50),
        ),
        migrations.CreateModel(
            name='PaymentProcess',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order_id', models.CharField(default='-', max_length=50)),
                ('payment_status', models.BooleanField(default=False)),
                ('datestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mysite.course')),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='student.studentinfo')),
            ],
        ),
    ]