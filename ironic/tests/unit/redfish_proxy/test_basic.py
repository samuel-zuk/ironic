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

from re import match
import xml.etree.ElementTree as ET

from ironic.conf import CONF
from ironic.tests.unit.redfish_proxy import base


class RedfishProxyBasicTests(base.RedfishProxyTestCase):
    """Tests asserting that basic functions of the Redfish proxy work."""

    def _set_cfg_opts(self):
        """Set authentication strategy to "noauth" for these tests."""
        super(RedfishProxyBasicTests, self)._set_cfg_opts()
        CONF.set_override('auth_strategy', 'noauth')

    def test_get_redfish_root(self):
        """Tests that GET requests to the root resolve correctly."""
        resp = self.http_get('/redfish')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertEqual(resp_body, {'v1': '/redfish/v1/'})

    def test_get_serviceroot(self):
        """Tests that GET requests to the ServiceRoot resolve correctly."""
        resp = self.http_get('/redfish/v1/')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        for x in ('Name', 'Id', 'Links'):
            self.assertIn(x, resp_body.keys())
        self.assertEqual(resp_body['RedfishVersion'], '1.0.0')
        self.assertEqual(resp_body['@odata.id'], '/redfish/v1/')
        self.assertEqual(resp_body['@odata.type'],
                         '#ServiceRoot.v1_0_0.ServiceRoot')
        self.assertEqual(resp_body['Systems']['@odata.id'],
                         '/redfish/v1/Systems')

    def test_get_odata_doc(self):
        """Tests that GET requests to the OData document resolve correctly."""
        resp = self.http_get('/redfish/v1/odata')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertEqual(resp_body['@odata.context'], '/redfish/v1/$metadata')
        for name, url in (('Service', '/redfish/v1/'),
                          ('Systems', '/redfish/v1/Systems')):
            self.assertIn({'kind': 'Singleton', 'name': name, 'url': url},
                          resp_body['value'])

    def test_resolve_url_slashes(self):
        """Tests that requests to /url and /url/ resolve identically."""
        resp = self.http_get('/redfish/')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertEqual(resp_body, {'v1': '/redfish/v1/'})

    def test_get_root(self):
        """Tests that the Redfish proxy doesn't handle requests to the root."""
        resp = self.http_get('/')
        self.assertEqual(resp.status_code, 404)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertTrue(resp_body['error'])
        self.assertEqual(resp_body['error']['code'], 404)


class RedfishProxyConfigTests(base.RedfishProxyTestCase):
    """Tests asserting that basic configuration options work."""

    def setUp(self):
        super(RedfishProxyConfigTests, self).setUp(defer_client_init=True)

    def test_proxy_disabled(self):
        """Tests that the app fails to initialize itself if disabled."""
        CONF.set_override('enabled', False, group='redfish_proxy')
        self.assertRaises(RuntimeError, self._init_client)

    def test_serviceroot_keystone(self):
        """Validates ServiceRoot response when using Keystone."""
        CONF.set_override('auth_strategy', 'keystone')
        self._init_client()

        resp = self.http_get('/redfish/v1/')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertEqual(resp_body['Links']['Sessions']['@odata.id'],
                         '/redfish/v1/SessionService/Sessions')
        self.assertEqual(resp_body['SessionService']['@odata.id'],
                         '/redfish/v1/SessionService')

    def test_serviceroot_no_keystone(self):
        """Validates ServiceRoot response when not using Keystone."""
        CONF.set_override('auth_strategy', 'noauth')
        self._init_client()

        resp = self.http_get('/redfish/v1/')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertNotIn('SessionService', resp_body.keys())
        self.assertNotIn('Sessions', resp_body['Links'].keys())

    def test_odata_doc_keystone(self):
        """Validates OData doc endpoint response when using Keystone."""
        CONF.set_override('auth_strategy', 'keystone')
        self._init_client()

        resp = self.http_get('/redfish/v1/odata')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        for name, url in (('Sessions', '/redfish/v1/SessionService/Sessions'),
                          ('SessionService', '/redfish/v1/SessionService')):
            self.assertIn({'kind': 'Singleton', 'name': name, 'url': url},
                          resp_body['value'])

    def test_odata_doc_no_keystone(self):
        """Validates OData doc endpoint response when not using Keystone."""
        CONF.set_override('auth_strategy', 'noauth')
        self._init_client()

        resp = self.http_get('/redfish/v1/odata')
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        for value in resp_body['value']:
            self.assertNotEqual(value['name'], 'SessionService')
            self.assertNotEqual(value['name'], 'Sessions')

    def test_metadata_doc_keystone(self):
        """Validates metadata doc endpoint response using Keystone."""
        CONF.set_override('auth_strategy', 'keystone')
        self._init_client()

        resp = self.http_get('/redfish/v1/$metadata')
        self.assertEqual(resp.status_code, 200)

        root = ET.fromstring(resp.data)
        ns = {'edmx': 'http://docs.oasis-open.org/odata/ns/edmx'}
        refs = [x.attrib['Uri'] for x in root.findall('./edmx:Reference', ns)]

        present = ('ServiceRoot',
                   'ComputerSystem',
                   'ComputerSystemCollection',
                   'Session',
                   'SessionCollection',
                   'SessionService')

        # Create a regex string that matches the given ref names
        re_present = '.*({s}).*'.format(s='|'.join(present))

        expected_refs = tuple(filter(lambda x: match(re_present, x), refs))
        self.assertEqual(len(expected_refs), len(present))

    def test_metadata_doc_no_keystone(self):
        """Validates metadata doc endpoint response when not using Keystone."""
        CONF.set_override('auth_strategy', 'noauth')
        self._init_client()

        resp = self.http_get('/redfish/v1/$metadata')
        self.assertEqual(resp.status_code, 200)

        root = ET.fromstring(resp.data)
        ns = {'edmx': 'http://docs.oasis-open.org/odata/ns/edmx'}
        refs = [x.attrib['Uri'] for x in root.findall('./edmx:Reference', ns)]

        present = ('ServiceRoot',
                   'ComputerSystem',
                   'ComputerSystemCollection')
        absent = ('Session',
                  'SessionCollection',
                  'SessionService')

        # Create a regex string that matches the given ref names
        re_present = '.*({s}).*'.format(s='|'.join(present))
        re_absent = '.*({s}).*'.format(s='|'.join(absent))

        expected_refs = tuple(filter(lambda x: match(re_present, x), refs))
        unexpected_refs = tuple(filter(lambda x: match(re_absent, x), refs))
        self.assertEqual(len(expected_refs), len(present))
        self.assertEqual(unexpected_refs, ())
