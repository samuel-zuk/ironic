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
from ironic.redfish_proxy.blueprints.ServiceRoot import ServiceRoot
from ironic.redfish_proxy.blueprints.SessionService import SessionService
from ironic.redfish_proxy.blueprints.Systems import Systems
from ironic.redfish_proxy.hooks import context as ContextHooks
from ironic.redfish_proxy.hooks import error as ErrorHooks
from ironic.redfish_proxy.hooks import rpcapi as RPCAPIHooks
from ironic.redfish_proxy.middleware.auth_public_routes import AuthPublicRoutes


def setup_app(testing=False):
    """Sets up the Ironic Redfish proxy, returns the underlying WSGI app."""
    if not CONF.redfish_proxy.enabled:
        raise RuntimeError('The Ironic Redfish proxy service is currently '
                           'disabled and must be enabled in ironic.conf.')
    app = Flask(__name__)
    app.config.update(CONF)
    # (e.g. requests to /endpoint/ and /endpoint should resolve identically)
    app.url_map.strict_slashes = False

    app.register_blueprint(root)
    app.register_blueprint(ServiceRoot)
    app.register_blueprint(Systems)

    wsgi_middleware = None
    if app.config['auth_strategy'] == 'keystone':
        wsgi_middleware = auth_token.AuthProtocol(app.wsgi_app,
                                                  {'oslo_config_config': CONF})
        # Only enable Sessions auth if Keystone is in use.
        app.register_blueprint(SessionService)
    elif app.config['auth_strategy'] == 'http_basic':
        wsgi_middleware = auth_basic.BasicAuthMiddleware(
            app.wsgi_app, app.config.http_basic_auth_user_file)
    # If noauth is not explicitly specified, abort initialization.
    elif app.config['auth_strategy'] != 'noauth':
        raise Exception('A valid authentication strategy was not specified.')

    if wsgi_middleware:
        app.config['public_routes'] = {
            '/': AuthPublicRoutes.DEFAULT_METHODS,
            '/redfish': AuthPublicRoutes.DEFAULT_METHODS,
            '/redfish/v1': AuthPublicRoutes.DEFAULT_METHODS,
            '/redfish/v1/odata': AuthPublicRoutes.DEFAULT_METHODS,
            '/redfish/v1/$metadata': AuthPublicRoutes.DEFAULT_METHODS
        }
        if app.config['auth_strategy'] == 'keystone':
            app.config['public_routes'].update({
                '/redfish/v1/SessionService/Sessions': ['POST']
            })
        # Wrap the underlying WSGI app if we're using auth middleware.
        app.wsgi_app = AuthPublicRoutes(app.wsgi_app,
                                        wsgi_middleware,
                                        app.config['public_routes'])

    with app.app_context():
        for hook in (ContextHooks, RPCAPIHooks, ErrorHooks):
            hook.register()

    return app.test_client() if testing else app.wsgi_app


class RedfishProxyApplication(object):
    """A callable object wrapping the Ironic Redfish proxy application."""
    def __init__(self):
        self.app = setup_app()

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)
