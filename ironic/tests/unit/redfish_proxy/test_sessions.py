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

from unittest.mock import patch

from ironic.conf import CONF
from ironic.tests.unit.redfish_proxy import base
from ironic.tests.unit.redfish_proxy import utils
from ironic.tests.unit.redfish_proxy.utils import FAKE_CREDS


class RedfishProxySessionTests(base.RedfishProxyTestCase):
    """Tests asserting that the emulated SessionService works."""
    def setUp(self):
        # Patch the keystone middleware and keystone Session objects
        # to return dummy values
        mw_patch = patch('keystonemiddleware.auth_token.AuthProtocol',
                         utils.FakeKeystoneMiddleware)
        self.fake_middleware = mw_patch.start()
        sess_patch = patch('keystoneauth1.session.Session',
                           utils.FakeKeystoneClientSession)
        self.fake_session = sess_patch.start()
        self.addCleanup(mw_patch.stop)
        self.addCleanup(sess_patch.stop)
        super(RedfishProxySessionTests, self).setUp()

    def _set_cfg_opts(self):
        super(RedfishProxySessionTests, self)._set_cfg_opts()
        CONF.set_override('auth_strategy', 'keystone')

    def test_get_sesionservice_info(self):
        resp = self.http_get('/redfish/v1/SessionService',
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        for x in ('Name', 'Id', 'SessionTimeout', 'Status', 'Sessions'):
            self.assertIsNotNone(resp_body[x])
        self.assertEqual(resp_body['@odata.type'],
                         '#SessionService.v1_0_0.SessionService')
        self.assertEqual(resp_body['@odata.id'], '/redfish/v1/SessionService')
        self.assertEqual(resp_body['Status']['State'], 'Enabled')
        self.assertEqual(resp_body['Status']['Health'], 'OK')
        self.assertTrue(resp_body['ServiceEnabled'])
        self.assertEqual(resp_body['Sessions']['@odata.id'],
                         '/redfish/v1/SessionService/Sessions')

    def test_get_sessions(self):
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertIsNotNone(resp_body['Name'])
        self.assertEqual(resp_body['@odata.type'],
                         '#SessionCollection.SessionCollection')
        self.assertEqual(resp_body['@odata.id'],
                         '/redfish/v1/SessionService/Sessions')
        self.assertGreater(resp_body['Members@odata.count'], 0)
        self.assertEqual(resp_body['Members@odata.count'],
                         len(resp_body['Members']))
        self.assertIn({'@odata.id': '/redfish/v1/SessionService/Sessions/%s' %
                                    FAKE_CREDS['TOKEN_ID']},
                      resp_body['Members'])

    def test_authentication(self):
        auth = {'UserName': FAKE_CREDS['APP_CRED_ID'],
                'Password': FAKE_CREDS['APP_CRED_SECRET']}
        resp = self.http_post('/redfish/v1/SessionService/Sessions', data=auth)
        self.assertEqual(resp.status_code, 201)

        resp_body = resp.get_json()
        resp_headers = resp.headers
        for x in (resp_body, resp_headers):
            self.assertIsNotNone(x)
        self.assertIsNotNone(resp_body['Name'])
        self.assertEqual(resp_headers['X-Auth-Token'], FAKE_CREDS['TOKEN'])
        self.assertEqual(resp_headers['Location'],
                         '/redfish/v1/SessionService/Sessions/%s' %
                         FAKE_CREDS['TOKEN_ID'])
        self.assertEqual(resp_headers['Location'], resp_body['@odata.id'])
        self.assertEqual(resp_body['@odata.type'], '#Session.1.0.0.Session')
        self.assertEqual(resp_body['Id'], FAKE_CREDS['TOKEN_ID'])
        self.assertEqual(resp_body['UserName'], FAKE_CREDS['APP_CRED_ID'])

    def test_get_current_session(self):
        resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                             FAKE_CREDS['TOKEN_ID'],
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 200)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertIsNotNone(resp_body['Name'])
        self.assertEqual(resp_body['@odata.id'],
                         '/redfish/v1/SessionService/Sessions/%s' %
                         FAKE_CREDS['TOKEN_ID'])
        self.assertEqual(resp_body['@odata.type'], '#Session.1.0.0.Session')
        self.assertEqual(resp_body['Id'], FAKE_CREDS['TOKEN_ID'])
        self.assertEqual(resp_body['UserName'], FAKE_CREDS['APP_CRED_ID'])

    def test_delete_current_sesison(self):
        auth = {'UserName': FAKE_CREDS['APP_CRED_ID'],
                'Password': FAKE_CREDS['APP_CRED_SECRET']}
        resp = self.http_post('/redfish/v1/SessionService/Sessions', data=auth)
        self.assertEqual(resp.status_code, 201)
        location = resp.headers['Location']

        resp = self.http_delete(location,
                                headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 204)
