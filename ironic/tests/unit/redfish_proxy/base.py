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

import gzip
import pprint

from ironic.conf import CONF
from ironic.redfish_proxy.app import setup_app
from ironic.tests import base


class RedfishProxyTestCase(base.TestCase):
    """Test class for the Redfish proxy that provides an app instance."""
    def setUp(self, defer_client_init=False):
        super(RedfishProxyTestCase, self).setUp()
        self._set_cfg_opts()

        # NOTE: this exists to allow individual test cases within a test class
        # to change things before initializing the client. if this is set, each
        # test within the class will need to manually call _init_client().
        if not defer_client_init:
            self._init_client()

    def _set_cfg_opts(self):
        """Helper function that sets config options before instantiation."""
        CONF.set_override('enabled', True, group='redfish_proxy')

    def _init_client(self):
        """Gets the Flask testing client."""
        self.client = setup_app(testing=True)

    def _make_request(self, path, method='GET', headers=None, data=None,
                      environ_overrides={}, is_json=True):
        """Sends a simulated HTTP request to the Flask test client.

        This should not be called directly by tests; it exists for use by the
        other helper functions in this test class.

        :param path: the URI of the endpoint to be tested
        :param method: the request method type
        :param headers: a dict of headers to send along with the request
        :param data: the data to be sent in the request body
        :param is_json: if the data should be parsed and sent as json
        :param environ_overrides: a dict of WSGI environment overrides
        """
        if method in ('POST', 'PUT', 'PATCH') and data and is_json:
            resp = self.client.open(path=path, method=method, headers=headers,
                                    environ_overrides=environ_overrides,
                                    json=data)
        else:
            resp = self.client.open(path=path, method=method, headers=headers,
                                    environ_overrides=environ_overrides,
                                    data=data)

        print('GOT: %s' % resp.status)
        for header in resp.headers:
            print('%s: %s' % header)
        # If response specifies gzip content encoding, decode the body
        if resp.content_encoding and 'gzip' in resp.content_encoding:
            resp.set_data(gzip.decompress(resp.data))
        # Pretty print JSON if possible
        if resp.is_json:
            pprint.pprint(resp.get_json())
        else:
            print(resp.get_data(as_text=True))
        return resp

    def http_get(self, path, headers=None, environ_overrides={}):
        """Sends a simulated GET request to the Flask test client.

        :param path: the URI of the endpoint to be tested
        :param headers: a dict of headers to send along with the request
        :param environ_overrides: a dict of WSGI environment overrides
        """
        return self._make_request(path=path, method='GET', headers=headers,
                                  environ_overrides=environ_overrides)

    def http_head(self, path, headers=None, environ_overrides={}):
        """Sends a simulated HEAD request to the Flask test client.

        :param path: the URI of the endpoint to be tested
        :param headers: a dict of headers to send along with the request
        :param environ_overrides: a dict of WSGI environment overrides
        """
        return self._make_request(path=path, method='HEAD', headers=headers,
                                  environ_overrides=environ_overrides)

    def http_delete(self, path, headers=None, environ_overrides={}):
        """Sends a simulated DELETE request to the Flask test client.

        :param path: the URI of the endpoint to be tested
        :param headers: a dict of headers to send along with the request
        :param environ_overrides: a dict of WSGI environment overrides
        """
        return self._make_request(path=path, method='DELETE', headers=headers,
                                  environ_overrides=environ_overrides)

    def http_put(self, path, headers=None, data=None, is_json=True,
                 environ_overrides={}):
        """Sends a simulated PUT request to the Flask test client.

        :param path: the URI of the endpoint to be tested
        :param headers: a dict of headers to send along with the request
        :param data: the data to be sent in the request body
        :param is_json: if the data should be parsed and sent as json
        :param environ_overrides: a dict of WSGI environment overrides
        """
        return self._make_request(path=path, method='PUT', headers=headers,
                                  data=data, is_json=is_json,
                                  environ_overrides=environ_overrides)

    def http_post(self, path, headers=None, data=None, is_json=True,
                  environ_overrides={}):
        """Sends a simulated POST request to the Flask test client.

        :param path: the URI of the endpoint to be tested
        :param headers: a dict of headers to send along with the request
        :param data: the data to be sent in the request body
        :param is_json: if the data should be parsed and sent as json
        :param environ_overrides: a dict of WSGI environment overrides
        """
        return self._make_request(path=path, method='POST', headers=headers,
                                  data=data, is_json=is_json,
                                  environ_overrides=environ_overrides)

    def http_patch(self, path, headers=None, data=None, is_json=True,
                   environ_overrides={}):
        """Sends a simulated PATCH request to the Flask test client.

        :param path: the URI of the endpoint to be tested
        :param headers: a dict of headers to send along with the request
        :param data: the data to be sent in the request body
        :param is_json: if the data should be parsed and sent as json
        :param environ_overrides: a dict of WSGI environment overrides
        """
        return self._make_request(path=path, method='PATCH', headers=headers,
                                  data=data, is_json=is_json,
                                  environ_overrides=environ_overrides)
