import os

from channels.routing import ProtocolTypeRouter, URLRouter
import coreWallet.routing

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "easyWallet.settings")

application = ProtocolTypeRouter({
  "http": get_asgi_application(),
  "websocket":
        URLRouter(
            coreWallet.routing.websocket_urlpatterns
        )

})
