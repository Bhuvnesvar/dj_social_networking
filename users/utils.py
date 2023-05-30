from django.contrib.auth import authenticate
from rest_framework import serializers

from .models import AppUser


def get_and_authenticate_user(username, password):
    user = authenticate(username=username, password=password)
    if user is None:
        raise serializers.ValidationError("Invalid username/password. Please try again!")
    return user


def check_user(email):
    try:
        obj = AppUser.objects.filter(email=email)
        if obj == None or len(obj) > 0:
            return False
        else:
            return True
    except Exception as error:
        return True
