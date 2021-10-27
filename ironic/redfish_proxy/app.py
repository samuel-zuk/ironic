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

from flask import current_app
from flask import Flask
from flask import request
from ironic_lib import auth_basic
from keystonemiddleware import auth_token

from ironic.conf import CONF
from ironic.redfish_proxy.blueprints.root import root
from ironic.redfish_proxy.blueprints.SessionService import SessionService
from ironic.redfish_proxy.blueprints.v1 import v1


def setup_app():
    app = Flask(__name__)
    app.config.update(CONF)
    app.url_map.strict_slashes = False

    app.register_blueprint(root)
    app.register_blueprint(v1)

    auth_middleware = None
    if app.config['auth_strategy'] == "keystone":
        with app.app_context():
            auth_middleware = auth_token.AuthProtocol(
                current_app.wsgi_app, {'oslo_config_config': CONF})

        app.config.update({'keystone_uri': (
            app.config['keystone_authtoken']['www_authenticate_uri'])})

        app.register_blueprint(SessionService)
    elif app.config['auth_strategy'] == "http_basic":
        auth_middleware = auth_basic.BasicAuthMiddleware(
            app.wsgi_app, app.config.http_basic_auth_user_file)

    app.config['auth_middleware'] = auth_middleware

    # TODO(sam_z): get this to work
    @app.after_request
    def auth(resp):
        if (current_app.config['auth_middleware'] and (
            'is_public_api' not in request.environ.keys()
            or not request.environ['is_public_api'])):
            return current_app.make_response(
                current_app.config['auth_middleware'])
    return app.wsgi_app


class RedfishProxyApplication(object):
    def __init__(self):
        self.app = setup_app()

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)
