from flask import Flask

from ironic.conf import CONF
from ironic.redfish_proxy.blueprints.root import root
from ironic.redfish_proxy.blueprints.v1 import v1


def setup_app():
    app = Flask(__name__)
    app.config.update(CONF)

    app.register_blueprint(root)
    app.register_blueprint(v1)

    return app.wsgi_app


class RedfishProxyApplication(object):
    def __init__(self):
        self.app = setup_app()

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)
