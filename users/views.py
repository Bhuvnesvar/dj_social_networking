# Create your views here.
from django.contrib.auth import logout
from django.shortcuts import get_object_or_404
from rest_framework import views
from rest_framework import viewsets, status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .decorators import RateLimitDecorator
from .models import AppUser, FriendRequest, Profile
from .serializers import RegisterSerializer, UserSerializer
from .utils import check_user


class LoginApiView(viewsets.ViewSet):
    """Checks email and password and returns an auth token."""
    serializer_class = AuthTokenSerializer
    permission_classes = [AllowAny]

    def create(self, request):
        """Use the ObtainAuthToken APIView to validate and create a token."""
        try:
            serializer = self.serializer_class(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            data = {'message': 'LoggedIn Successfully.', 'status': status.HTTP_200_OK,
                    'data': {'id': user.pk, 'token': token.key, 'username': user.username, 'email': user.email,
                             'first_name': user.first_name, 'last_name': user.last_name,
                             'created': user.created_at, }}
            return Response(data, status=status.HTTP_200_OK)
        except Exception as error:
            data = {'message': str(error), 'status': status.HTTP_400_BAD_REQUEST, 'data': {}}
            return Response(data, status=status.HTTP_400_BAD_REQUEST)


class LogoutApiView(views.APIView):
    """Checks permissions."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Logout user if valid token."""
        try:
            request.user.auth_token.delete()
            logout(request)
            data = {'message': 'Logout Successfully.', 'status': status.HTTP_200_OK}
            return Response(data=data, status=status.HTTP_200_OK)
        except Exception as error:
            data = {'message': str(error), 'status': status.HTTP_400_BAD_REQUEST}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(views.APIView):
    """Create a new user"""
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            email = request.POST.get('email')
            if check_user(email):
                serializer = self.serializer_class(data=request.data)
                serializer.is_valid(raise_exception=True)
                if serializer.is_valid():
                    serializer.save()
                    data = {'message': 'Signup Successfully.', 'status': status.HTTP_200_OK, 'data': serializer.data}
                    return Response(data=data, status=status.HTTP_201_CREATED)
            else:
                data = {'message': 'Email already exists.', 'status': status.HTTP_406_NOT_ACCEPTABLE}
                return Response(data=data, status=status.HTTP_406_NOT_ACCEPTABLE)
        except Exception as error:
            data = {'message': str(error), 'status': status.HTTP_400_BAD_REQUEST, 'data': {}}
            return Response(data, status=status.HTTP_400_BAD_REQUEST)


class AllUsersView(viewsets.ModelViewSet):
    """All users"""
    permission_classes = [AllowAny]
    serializer_class = UserSerializer
    queryset = AppUser.objects.all().exclude(is_superuser=True)


class SearchUserAPIView(views.APIView):
    """Search users"""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            q = request.data['query']
            if '@' in q:
                user_obj = AppUser.objects.get(email__exact=q)
                data = {'email': str(user_obj.email)}
                return Response(data, status=status.HTTP_200_OK)
            else:
                user_obj = AppUser.objects.filter(username__icontains=q).values_list('username')
                data = {'username': user_obj}
                return Response(data, status=status.HTTP_200_OK)

        except Exception as error:
            data = {'data': str(error)}
            return Response(data, status=status.HTTP_404_NOT_FOUND)


class SendFriendRequestAPIView(views.APIView):
    """Send Request to users"""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @RateLimitDecorator(calls=3, period=60)  # max 3 calls per second
    def post(self, request, *args, **kwargs):
        try:
            user = get_object_or_404(AppUser, id=request.POST.get('to_user'))

            frequest, created = FriendRequest.objects.get_or_create(
                from_user=request.user,
                to_user=user)
            print("USER " + str(user))
            data = {'data': 'Friend Request Sent.'}
            return Response(data, status=status.HTTP_200_OK)

        except Exception as error:
            data = {'error': str(error)}
            return Response(data, status=status.HTTP_404_NOT_FOUND)


class AcceptFriendRequestAPIView(views.APIView):
    """Accept Request to users"""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            from_user = get_object_or_404(AppUser, id=request.POST.get('to_user', ''))
            frequest = FriendRequest.objects.filter(from_user=from_user, to_user=request.user).first()
            user1 = frequest.to_user
            user2 = from_user
            user1.profile.friends.add(user2.profile)
            user2.profile.friends.add(user1.profile)
            frequest.delete()

            data = {'msg': 'Friend Request Accepted.'}
            return Response(data, status=status.HTTP_200_OK)
        except Exception as error:
            data = {'error': 'Friend Request not found. May be earlier you accepted ! else canceled by sender user.'}
            return Response(data, status=status.HTTP_404_NOT_FOUND)


class RejectFriendRequestAPIView(views.APIView):
    """Reject Request to users"""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            from_user = get_object_or_404(AppUser, id=request.POST.get('from_user', ''))
            frequest = FriendRequest.objects.filter(from_user=from_user, to_user=request.user).first()
            frequest.delete()
            data = {'msg': 'Friend Request Rejected.'}
            return Response(data, status=status.HTTP_200_OK)
        except Exception as error:
            data = {
                'error': 'Friend Request not found. May be earlier you accepted ! else rejected by you.',
                'error1': str(error)}
            return Response(data, status=status.HTTP_404_NOT_FOUND)


class MyProfileAPIView(views.APIView):
    """Get Profile"""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            print(request.user)
            p = Profile.objects.filter(user=request.user).first()
            print('DATA : ' + str(p))
            u = p.user
            sent_friend_requests = list(FriendRequest.objects.filter(from_user=request.user).values())
            rec_friend_requests = list(FriendRequest.objects.filter(to_user=request.user).values())
            friends = list(p.friends.all().values())

            data = {'email': str(u), 'sent_friend_requests': sent_friend_requests,
                    'pending_friend_requests': rec_friend_requests,
                    'friends_list': friends}
            return Response(data, status=status.HTTP_200_OK)
        except Exception as error:
            data = {'error': str(error)}
            return Response(data, status=status.HTTP_404_NOT_FOUND)
