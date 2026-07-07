"""
ASGI config for web_dashboard project.
"""
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web_dashboard.settings")
application = get_asgi_application()
