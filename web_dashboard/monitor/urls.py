from django.urls import path
from monitor import views

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("api/chart-data/", views.chart_data_api, name="chart_data_api"),
    path("api/chatbot/", views.chatbot_api, name="chatbot_api"),
    
    # Custom User Management
    path("users/", views.user_management_view, name="user_management"),
    path("users/create/", views.user_create_view, name="user_create"),
    path("users/<int:user_id>/update/", views.user_update_view, name="user_update"),
    path("users/<int:user_id>/delete/", views.user_delete_view, name="user_delete"),
    path("users/<int:user_id>/toggle-active/", views.user_toggle_active_view, name="user_toggle_active"),
    path("users/<int:user_id>/change-password/", views.user_change_password_view, name="user_change_password"),

    # Investigation Dashboard & AI Analysis API
    path("investigation/", views.investigation_dashboard_view, name="investigation_dashboard"),
    path("api/investigate-ip/", views.investigate_ip_api, name="investigate_ip_api"),
]
