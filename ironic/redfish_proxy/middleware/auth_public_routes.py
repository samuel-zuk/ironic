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

import re

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import utils


class AuthPublicRoutes(object):
    """A wrapper on authentication middleware.

    Does not perform verification of authentication tokens
    for public routes in the API.

    """

    ALL_METHODS = None
    DEFAULT_METHODS = ['GET', 'HEAD']

    def __init__(self, app, auth, public_api_routes=None):
        api_routes = {} if public_api_routes is None else public_api_routes
        self._app = app
        self._middleware = auth
        # TODO(mrda): Remove .xml and ensure that doesn't result in a
        # 401 Authentication Required instead of 404 Not Found
        route_pattern_tpl = '%s(\\.json|\\.xml)?$'

        if type(public_api_routes) == list:
            api_routes = dict.fromkeys(public_api_routes, self.ALL_METHODS)

        try:
            self.public_api_routes = {
                re.compile(route_pattern_tpl % route): method
                for route, method in api_routes.items()
            }
        except re.error as e:
            raise exception.ConfigInvalid(
                error_msg=_('Cannot compile public API routes: %s') % e)

    def __call__(self, env, start_response):
        path = utils.safe_rstrip(env.get('PATH_INFO'), '/')

        # The information whether the API call is being performed against the
        # public API is required for some other components. Saving it to the
        # WSGI environment is reasonable thereby.
        for route in self.public_api_routes.keys():
            if re.match(route, path):
                # If the value corresponding to this route is None (the value
                # of AuthPublicRoutes.ALL_METHODS), allow the request.
                if not self.public_api_routes[route]:
                    env['is_public_api'] = True
                else:
                    method = env.get('REQUEST_METHOD')
                    env['is_public_api'] = (True if method
                                            in self.public_api_routes[route]
                                            else False)
            else:
                env['is_public_api'] = False

        if env['is_public_api']:
            return self._app(env, start_response)

        return self._middleware(env, start_response)
