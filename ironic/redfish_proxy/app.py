from flask import Flask, request
from ironic_lib import auth_basic
from keystonemiddleware import auth_token

from ironic.conf import CONF
from ironic.redfish_proxy.blueprints.root import root
from ironic.redfish_proxy.blueprints.v1 import v1
from ironic.redfish_proxy.blueprints.SessionService import SessionService


def setup_app():
    app = Flask(__name__)
    app.config.update(CONF)
    app.url_map.strict_slashes = False

    app.register_blueprint(root)
    app.register_blueprint(v1)

    auth_middleware = None
    if app.config['auth_strategy'] == "keystone":
        auth_middleware = auth_token.AuthProtocol(
            app.wsgi_app, {"oslo_config_config": CONF})

        app.config.update({
            'keystone_uri': auth_middleware._www_authenticate_uri
        })
        app.register_blueprint(SessionService)
    elif app.config['auth_strategy'] == "http_basic":
        auth_middleware = auth_basic.BasicAuthMiddleware(
            app.wsgi_app, app.config.http_basic_auth_user_file)

    app.config['auth_middleware'] = auth_middleware

    @app.after_request
    def auth(fun):
        return (app.config['auth_middleware'] if 
            (app.config['auth_middleware'] and
             ('is_public_api' not in request.environ.keys() or
              not request.environ['is_public_api'])) else fun)

    return app.wsgi_app


class RedfishProxyApplication(object):
    def __init__(self):
        self.app = setup_app()

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)
