from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.db.models.signals import post_save

from .managers import CustomUserManager


class AppUser(AbstractBaseUser, PermissionsMixin):
    class Meta:
        verbose_name_plural = "users"

    email = models.EmailField(max_length=500, unique=True)
    password = models.CharField(max_length=1000, default='')
    username = models.CharField(max_length=500, unique=True)
    first_name = models.CharField(default="", max_length=500, null=True, blank=True)
    last_name = models.CharField(default="", max_length=500, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    phone_number = models.CharField(default="0", max_length=500, unique=True)
    created_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()


class Profile(models.Model):
    user = models.OneToOneField(AppUser, on_delete=models.CASCADE, )
    slug = models.SlugField()
    friends = models.ManyToManyField("Profile", blank=True)

    def __str__(self):
        return str(self.user.username)

    def get_absolute_url(self):
        return "/users/{}".format(self.slug)


def post_save_user_model_receiver(sender, instance, created, *args, **kwargs):
    if created:
        try:
            Profile.objects.create(user=instance)
        except:
            pass


post_save.connect(post_save_user_model_receiver, sender=AppUser)


class FriendRequest(models.Model):
    to_user = models.ForeignKey(AppUser, related_name='to_user', on_delete=models.CASCADE, )
    from_user = models.ForeignKey(AppUser, related_name='from_user', on_delete=models.CASCADE, )
    timestamp = models.DateTimeField(auto_now_add=True)  # set when created

    def __str__(self):
        return "From {}, to {}".format(self.from_user.username, self.to_user.username)
