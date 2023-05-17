import jwt
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from .serializers import UserSerializer, SpartaTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.contrib.auth import authenticate
from .models import User
from rest_framework import status
from rest_framework.response import Response
from django.shortcuts import render, get_object_or_404
from config.settings import SECRET_KEY

class SparataTokenObtainPairView(TokenObtainPairView):
    serializer_class = SpartaTokenObtainPairSerializer

class RegisterAPIView(APIView):
    def post(self, request):
        serializer_class = UserSerializer(data=request.data)
        if serializer_class.is_valid():
            user = serializer_class.save()
            
            # jwt 토큰 접근
            token = SpartaTokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            return Response(
                {
                    "user": serializer_class.data,
                    "message": "register successs",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
        
        return Response(serializer_class.errors, status=status.HTTP_400_BAD_REQUEST)


class AuthAPIView(APIView):
    # 유저 정보 확인
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', False)
            if token:
                token = str(token).split()[1].encode("utf-8")
            # access token을 decode 해서 유저 id 추출 => 유저 식별
            access = token
            payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            pk = payload.get('user_id')
            user = get_object_or_404(User, pk=pk)
            serializer_class = UserSerializer(instance=user)
            return Response(
                {
                    "user": serializer_class.data,
                    "message": "get User info successs",
                },
                status=status.HTTP_200_OK,
            )

        except(jwt.exceptions.ExpiredSignatureError):
            # 토큰 만료 시 토큰 갱신
            data = {'refresh': request.data('refresh', None)}
            serializer = TokenRefreshSerializer(data=data)
            if serializer.is_valid(raise_exception=True):
                access = serializer.data.get('access', None)
                refresh = serializer.data.get('refresh', None)
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
                pk = payload.get('user_id')
                user = get_object_or_404(User, pk=pk)
                serializer = UserSerializer(instance=user)
                res = Response(serializer.data, status=status.HTTP_200_OK)
                res.set_cookie('access', access)
                res.set_cookie('refresh', refresh)
                return res
            raise jwt.exceptions.InvalidTokenError

        except(jwt.exceptions.InvalidTokenError):
            # 사용 불가능한 토큰일 때
            return Response(status=status.HTTP_400_BAD_REQUEST)

    # 로그인
    def post(self, request):
    	# 유저 인증
        user = authenticate(
            email=request.data.get("email"), password=request.data.get("password")
        )
        # 이미 회원가입 된 유저일 때
        if user is not None:
            serializer = UserSerializer(user)
            # jwt 토큰 접근
            token = SpartaTokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            return Response(
                {
                    "user": serializer.data,
                    "message": "login success",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', False)
            if token:
                token = str(token).split()[1].encode("utf-8")
            # access token을 decode 해서 유저 id 추출 => 유저 식별
            access = token
            payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            pk = payload.get('user_id')
            user = get_object_or_404(User, pk=pk)
            serializer_class = UserSerializer(user, data=request.data)
            if serializer_class.is_valid():
                serializer_class.save()
                return Response(
                    {
                        "user": serializer_class.data,
                        "message": "update User info successs",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)

        except(jwt.exceptions.ExpiredSignatureError):
            raise jwt.exceptions.InvalidTokenError

        except(jwt.exceptions.InvalidTokenError):
            return Response(status=status.HTTP_400_BAD_REQUEST)
        

    # 로그아웃
    def delete(self, request):
        # 쿠키에 저장된 토큰 삭제 => 로그아웃 처리
        return Response({
            "message": "Logout success"
            }, status=status.HTTP_202_ACCEPTED)