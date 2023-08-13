from django.urls import path
from .views import RegisterView, LoginView, CustomTokenRefreshView, VerifyTokenView
from . import views

    
urlpatterns = [
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view()),
    path('refresh', CustomTokenRefreshView.as_view()),
    path('verify', VerifyTokenView.as_view()),
    path('', views.react),
    
    # path('protected-resource', ProtectedResourceView.as_view())
    
]
