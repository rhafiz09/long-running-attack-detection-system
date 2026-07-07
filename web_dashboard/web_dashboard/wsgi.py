"""
WSGI config for web_dashboard project.
"""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web_dashboard.settings")
application = get_wsgi_application()
