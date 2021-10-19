from flask import Flask
from ironic_lib import auth_basic
from keystonemiddleware import auth_token

from ironic.conf import CONF
from ironic.api.middleware.auth_public_routes import AuthPublicRoutes

from ironic.redfish_proxy.blueprints.root import root
from ironic.redfish_proxy.blueprints.v1 import v1
from ironic.redfish_proxy.blueprints.SessionService import SessionService


def setup_app():
    app = Flask(__name__)
    app.config.update(CONF)

    app.register_blueprint(root)
    app.register_blueprint(v1)
    app.register_blueprint(SessionService)

    auth_middleware = None
    if app.config['auth_strategy'] == "keystone":
        auth_middleware = auth_token.AuthProtocol(
            app.wsgi_app, {"oslo_config_config": CONF})
    elif app.config['auth_strategy'] == "http_basic":
        auth_middleware = auth_basic.BasicAuthMiddleware(
            app.wsgi_app, CONF.http_basic_auth_user_file)

    if auth_middleware:
        app.wsgi_app = AuthPublicRoutes(app.wsgi_app, auth=auth_middleware)

    return app.wsgi_app


class RedfishProxyApplication(object):
    def __init__(self):
        self.app = setup_app()

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)
