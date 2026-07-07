from django.urls import path
from monitor import views

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("api/chart-data/", views.chart_data_api, name="chart_data_api"),
    path("api/chatbot/", views.chatbot_api, name="chatbot_api"),
]
