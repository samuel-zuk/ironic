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
        patch1 = patch('keystonemiddleware.auth_token.AuthProtocol',
                       utils.FakeKeystoneMiddleware)
        patch1.start()
        patch2 = patch('keystoneauth1.session.Session',
                       utils.FakeKeystoneClientSession)
        patch2.start()
        self.addCleanup(patch1.stop)
        self.addCleanup(patch2.stop)
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
            self.assertIn(x, resp_body.keys())
        self.assertEqual(resp_body['@odata.type'],
                         '#SessionService.v1_0_0.SessionService')
        self.assertEqual(resp_body['@odata.id'], '/redfish/v1/SessionService')
        self.assertEqual(resp_body['Status']['State'], 'Enabled')
        self.assertEqual(resp_body['Status']['Health'], 'OK')
        self.assertTrue(resp_body['ServiceEnabled'])
        self.assertEqual(resp_body['Sessions']['@odata.id'],
                         '/redfish/v1/SessionService/Sessions')
