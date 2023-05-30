from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views
from .views import LoginApiView

router = DefaultRouter()
router.register(r'login', LoginApiView, basename='login')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.RegisterView.as_view(), name="register"),
    path('logout/', views.LogoutApiView.as_view(), name="register"),
    path('all_users/', views.AllUsersView.as_view({'get': 'list'}), name="all_users"),
    path('search_user/', views.SearchUserAPIView.as_view(), name="search_user"),
    path('send_request/', views.SendFriendRequestAPIView.as_view(), name="send_request"),
    path('accept_request/', views.AcceptFriendRequestAPIView.as_view(), name="accept_request"),
    path('reject_request/', views.RejectFriendRequestAPIView.as_view(), name="reject_request"),
    path('profile/', views.MyProfileAPIView.as_view(), name="profile"),
]
