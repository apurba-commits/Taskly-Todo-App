import uuid
from django.db import models
from django.contrib.auth.models import  User
import uuid
class Task(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status_choices=[
        ('not_started','Not started'),
        ('pending','Pending'),
        ('completed','Completed')
    ]
    title=models.CharField(max_length=100,null=False)
    description=models.TextField()
    deadline=models.DateField(null=True,blank=True)
    status=models.CharField(
        max_length=100,
        choices=status_choices,
        default='not_started'
    )
    user=models.ForeignKey(User,on_delete=models.CASCADE)


    def __str__(self):
        return f"{self.title} : {self.status}"

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='profile_images/', null=True, blank=True,default='default.png')

    def __str__(self):
        return self.user.username