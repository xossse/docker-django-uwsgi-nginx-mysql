# mysite/asgi.py
import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import coreWallet.routing

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "easyWallet.settings")
#application = get_asgi_application()
application = ProtocolTypeRouter({
  "http": get_asgi_application(),
  "websocket": AuthMiddlewareStack(
        URLRouter(
            coreWallet.routing.websocket_urlpatterns
        )
    ),
})