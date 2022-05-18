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
        """Tests that requests for SessionService info resolve correctly."""
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

    def test_get_current_session(self):
        """Tests that requests for session info resolve, given valid token."""
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

    def test_get_all_sessions(self):
        """Tests that requests to get a list of Sessions resolve correctly."""
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
        """Tests that requests for new tokens resolve, given correct creds."""
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

    def test_delete_current_sesison(self):
        """Tests that requests to revoke token resolve, given valid token."""
        auth = {'UserName': FAKE_CREDS['APP_CRED_ID'],
                'Password': FAKE_CREDS['APP_CRED_SECRET']}
        resp = self.http_post('/redfish/v1/SessionService/Sessions', data=auth)
        self.assertEqual(resp.status_code, 201)
        token = resp.headers['X-Auth-Token']
        location = resp.headers['Location']

        resp = self.http_delete(location, headers={'X-Auth-Token': token})
        self.assertEqual(resp.status_code, 204)

    def test_authentication_invalid_creds(self):
        """Tests that authentication fails given invalid credentials."""
        # checks: invalid app cred id + invalid secret
        #         valid app cred id + invalid secret
        invalid_auths = ({'UserName': 'foo', 'Password': 'bar'},
                         {'UserName': FAKE_CREDS['APP_CRED_ID'],
                          'Password': 'foobar'})
        for auth in invalid_auths:
            resp = self.http_post('/redfish/v1/SessionService/Sessions',
                                  data=auth)
            self.assertEqual(resp.status_code, 403)

    def test_authentication_no_auth(self):
        """Tests that authentication fails if no credentials are provided."""
        resp = self.http_post('/redfish/v1/SessionService/Sessions', data={})
        self.assertEqual(resp.status_code, 400)

    def test_authentication_bad_request(self):
        """Tests that authentication fails if request body is malformed."""
        # checks missing password, missing username, intentional typo
        malformed_data = ({'UserName': FAKE_CREDS['APP_CRED_ID']},
                          {'Password': FAKE_CREDS['APP_CRED_SECRET']},
                          {'UserName': FAKE_CREDS['APP_CRED_ID'],
                           'Pasword': FAKE_CREDS['APP_CRED_SECRET']})
        for auth in malformed_data:
            resp = self.http_post('/redfish/v1/SessionService/Sessions',
                                  data=auth)
            self.assertEqual(resp.status_code, 400)

        # checks w/ data of incorrect mimetype
        resp = self.http_post('/redfish/v1/SessionService/Sessions',
                              data='UserName: jim\nPassword: bob',
                              is_json=False)
        self.assertEqual(resp.status_code, 400)

    def test_get_invalid_session(self):
        """Tests that trying to get a nonexistent session fails."""
        resp = self.http_get('/redfish/v1/SessionService/Sessions/bingus',
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 404)

    def test_get_session_invalid_token(self):
        """Tests that trying to get a session fails with invalid token."""
        # check with both valid and invalid session identifiers
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                                 session_id,
                                 headers={'X-Auth-Token': 'foobar'})
            self.assertEqual(resp.status_code, 403)

    def test_get_session_no_token(self):
        """Tests that trying to get a session fails without a token."""
        # check with both valid and invalid session identifiers
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                                 session_id,
                                 headers={})
            self.assertEqual(resp.status_code, 403)

    def test_get_all_sessions_invalid_auth(self):
        """Tests that trying to get session list fails with invalid creds."""
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers={'X-Auth-Token': 'foobar'})
        self.assertEqual(resp.status_code, 403)

    def test_get_all_sessions_no_auth(self):
        """Tests that trying to get session list fails without a token."""
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers={})
        self.assertEqual(resp.status_code, 403)

    def test_delete_invalid_session(self):
        """Tests that trying to delete a nonexistent session fails."""
        resp = self.http_delete('/redfish/v1/SessionService/Sessions/bingus',
                                headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 404)

    def test_delete_session_invalid_token(self):
        """Tests that trying to delete a session fails with invalid token."""
        # check with both valid and invalid session identifiers
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_delete('/redfish/v1/SessionService/Sessions/%s' %
                                    session_id,
                                    headers={'X-Auth-Token': 'foobar'})
            self.assertEqual(resp.status_code, 403)

    def test_delete_session_no_token(self):
        """Tests that trying to delete a session fails without a token."""
        # check with both valid and invalid session identifiers
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_delete('/redfish/v1/SessionService/Sessions/%s' %
                                    session_id,
                                    headers={})
            self.assertEqual(resp.status_code, 403)
