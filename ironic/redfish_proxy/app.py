# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from flask import Flask
from ironic_lib import auth_basic
from keystonemiddleware import auth_token

from ironic.conf import CONF
from ironic.redfish_proxy.blueprints.root import root
from ironic.redfish_proxy.blueprints.SessionService import SessionService
from ironic.redfish_proxy.blueprints.Systems import Systems
from ironic.redfish_proxy.blueprints.v1 import v1
from ironic.redfish_proxy.hooks import context as ContextHooks
from ironic.redfish_proxy.middleware.auth_public_routes import AuthPublicRoutes


def setup_app():
    app = Flask(__name__)
    app.config.update(CONF)
    app.url_map.strict_slashes = False

    app.register_blueprint(root)
    app.register_blueprint(v1)
    app.register_blueprint(Systems)

    wsgi_middleware = None
    if app.config['auth_strategy'] == 'keystone':
        wsgi_middleware = auth_token.AuthProtocol(app.wsgi_app, app.config)
        app.register_blueprint(SessionService)
    elif app.config['auth_strategy'] == 'http_basic':
        wsgi_middleware = auth_basic.BasicAuthMiddleware(
            app.wsgi_app, app.config.http_basic_auth_user_file)

    if wsgi_middleware:
        app.config['public_routes'] = {
            '/': AuthPublicRoutes.DEFAULT_METHODS,
            '/redfish': AuthPublicRoutes.DEFAULT_METHODS,
            '/redfish/v1': AuthPublicRoutes.DEFAULT_METHODS,
        }
        if app.config['auth_strategy'] == 'keystone':
            app.config['public_routes'].update({
                '/redfish/v1/SessionService/Sessions': ['POST']
            })
        app.wsgi_app = AuthPublicRoutes(app.wsgi_app,
                                        wsgi_middleware,
                                        app.config['public_routes'])

    with app.app_context():
        ContextHooks.register()

    return app.wsgi_app


class RedfishProxyApplication(object):
    def __init__(self):
        self.app = setup_app()

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)
