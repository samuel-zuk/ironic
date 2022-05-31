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

from unittest import mock

import keystoneauth1.exceptions as ks_exceptions
from oslo_config import cfg

from ironic.conf import CONF
from ironic.tests.unit.redfish_proxy import base
from ironic.tests.unit.redfish_proxy import utils
from ironic.tests.unit.redfish_proxy.utils import FAKE_CREDS


class RedfishProxySessionTests(base.RedfishProxyTestCase):
    """Tests asserting that the emulated SessionService works."""

    def setUp(self):
        # Patch the keystone middleware and keystone Session objects
        # to return dummy values
        mw_patch = mock.patch('keystonemiddleware.auth_token.AuthProtocol',
                              utils.FakeMiddleware)
        self.addCleanup(mw_patch.stop)
        self.fake_middleware = mw_patch.start()

        sess_patch = mock.patch('keystoneauth1.session.Session', autospec=True)
        self.addCleanup(sess_patch.stop)
        self.fake_session = sess_patch.start()
        self.fake_session.return_value = self.fake_session
        super(RedfishProxySessionTests, self).setUp()

    def _set_cfg_opts(self):
        super(RedfishProxySessionTests, self)._set_cfg_opts()
        CONF.set_override('auth_strategy', 'keystone')
        # Keystone middleware sets this value upon initialization and our
        # SessionService code expects it so we set it here.
        CONF.register_opt(cfg.StrOpt('auth_url',
                                     default='http://localhost'),
                          group='keystone_authtoken')

    def _mock_get_helper(self):
        """Returns info the SessionService expects for a GET request."""
        resp = {
            'token': {
                'audit_ids': [FAKE_CREDS['TOKEN_ID']],
                'application_credential': {'id': FAKE_CREDS['APP_CRED_ID']}
            }
        }
        return utils.FakeResponse(resp)

    def _auth_header(self, token=FAKE_CREDS['TOKEN']):
        """Returns an auth token header in dict form with specified token."""
        return {'X-Auth-Token': token}

    def parse_ks_session_auth(self, auth):
        if auth.__class__.__name__ == 'ApplicationCredential':
            auth_info = auth.auth_methods[0]
            return {'uuid': auth_info.application_credential_id,
                    'secret': auth_info.application_credential_secret}
        elif auth.__class__.__name__ == 'Token':
            return auth.token

    def mock_call_kwarg(self, kwarg, method=None):
        if method:
            mock_method = getattr(self.fake_session, method)
            return mock_method.call_args.kwargs[kwarg]
        else:
            return self.fake_session.call_args.kwargs[kwarg]

    def test_get_sesionservice_info(self):
        """Tests that requests for SessionService info resolve correctly."""
        resp = self.http_get('/redfish/v1/SessionService',
                             headers=self._auth_header())

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
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                             FAKE_CREDS['TOKEN_ID'],
                             headers=self._auth_header())

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

        self.fake_session.assert_called()
        self.assertEqual(
            self.parse_ks_session_auth(self.mock_call_kwarg('auth')),
            FAKE_CREDS['TOKEN'])
        self.fake_session.get.assert_called_once()
        self.assertEqual(
            self.mock_call_kwarg('headers', method='get')['X-Subject-Token'],
            FAKE_CREDS['TOKEN'])

    def test_get_all_sessions(self):
        """Tests that requests to get a list of Sessions resolve correctly."""
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers=self._auth_header())
        self.assertEqual(resp.status_code, 200)

        self.fake_session.assert_called()
        self.assertEqual(
            self.parse_ks_session_auth(self.mock_call_kwarg('auth')),
            FAKE_CREDS['TOKEN'])
        self.fake_session.get.assert_called_once()
        self.assertEqual(
            self.mock_call_kwarg('headers', method='get')['X-Subject-Token'],
            FAKE_CREDS['TOKEN'])

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
        self.fake_session.get_auth_headers.return_value = self._auth_header()
        self.fake_session.get.return_value = self._mock_get_helper()
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

        self.fake_session.assert_called()
        auth_rcvd = self.parse_ks_session_auth(self.mock_call_kwarg('auth'))
        self.assertEqual(auth_rcvd['uuid'], FAKE_CREDS['APP_CRED_ID'])
        self.assertEqual(auth_rcvd['secret'], FAKE_CREDS['APP_CRED_SECRET'])
        self.fake_session.get.assert_called_once()
        self.assertEqual(
            self.mock_call_kwarg('headers', method='get')['X-Subject-Token'],
            FAKE_CREDS['TOKEN'])

    def test_delete_current_sesison(self):
        """Tests that requests to revoke token resolve, given valid token."""
        self.fake_session.get.return_value = self._mock_get_helper()
        self.fake_session.delete.return_value = utils.FakeResponse({}, 204)

        resp = self.http_delete('/redfish/v1/SessionService/Sessions/%s' %
                                FAKE_CREDS['TOKEN_ID'],
                                headers=self._auth_header())
        self.assertEqual(resp.status_code, 204)

        self.fake_session.assert_called()
        self.assertEqual(
            self.parse_ks_session_auth(self.mock_call_kwarg('auth')),
            FAKE_CREDS['TOKEN'])
        self.fake_session.get.assert_called_once()
        self.assertEqual(
            self.mock_call_kwarg('headers', method='get')['X-Subject-Token'],
            FAKE_CREDS['TOKEN'])
        self.fake_session.delete.assert_called_once()
        delete_headers = self.mock_call_kwarg('headers', method='delete')
        self.assertEqual(delete_headers['X-Subject-Token'],
                         FAKE_CREDS['TOKEN'])

    def test_authentication_invalid_creds(self):
        """Tests that authentication fails given invalid credentials."""
        self.fake_session.get_auth_headers.side_effect = (
            ks_exceptions.http.NotFound())
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_post('/redfish/v1/SessionService/Sessions',
                              data={'UserName': 'foo', 'Password': 'bar'})

        self.assertEqual(resp.status_code, 403)
        self.fake_session.assert_called()
        auth_rcvd = self.parse_ks_session_auth(self.mock_call_kwarg('auth'))
        self.assertNotEqual(auth_rcvd['uuid'], FAKE_CREDS['APP_CRED_ID'])
        self.assertNotEqual(auth_rcvd['secret'], FAKE_CREDS['APP_CRED_SECRET'])
        self.fake_session.get.assert_not_called()

    def test_authentication_invalid_secret(self):
        """Tests that authentication fails given invalid app cred secret."""
        self.fake_session.get_auth_headers.side_effect = (
            ks_exceptions.http.Unauthorized())
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_post('/redfish/v1/SessionService/Sessions',
                              data={'UserName': FAKE_CREDS['APP_CRED_ID'],
                                    'Password': 'foobar'})

        self.assertEqual(resp.status_code, 403)
        self.fake_session.assert_called()
        auth_rcvd = self.parse_ks_session_auth(self.mock_call_kwarg('auth'))
        self.assertEqual(auth_rcvd['uuid'], FAKE_CREDS['APP_CRED_ID'])
        self.assertNotEqual(auth_rcvd['secret'], FAKE_CREDS['APP_CRED_SECRET'])
        self.fake_session.get.assert_not_called()

    def test_authentication_no_auth(self):
        """Tests that authentication fails if no credentials are provided."""
        self.fake_session.get_auth_headers.return_value = self._auth_header()
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_post('/redfish/v1/SessionService/Sessions', data={})

        self.assertEqual(resp.status_code, 400)
        self.fake_session.assert_not_called()
        self.fake_session.get_auth_headers.assert_not_called()
        self.fake_session.get.assert_not_called()

    def test_authentication_malformed_data(self):
        """Tests that authentication fails if request body is malformed."""
        # checks missing password, missing username, intentional typo
        malformed_data = ({'UserName': FAKE_CREDS['APP_CRED_ID']},
                          {'Password': FAKE_CREDS['APP_CRED_SECRET']},
                          {'UserName': FAKE_CREDS['APP_CRED_ID'],
                           'Pasword': FAKE_CREDS['APP_CRED_SECRET']})
        self.fake_session.get_auth_headers.return_value = self._auth_header()
        self.fake_session.get.return_value = self._mock_get_helper()
        for auth in malformed_data:
            resp = self.http_post('/redfish/v1/SessionService/Sessions',
                                  data=auth)

            self.assertEqual(resp.status_code, 400)
            self.fake_session.assert_not_called()
            self.fake_session.get_auth_headers.assert_not_called()
            self.fake_session.get.assert_not_called()
            self.fake_session.reset_mock()

    def test_authentication_bad_mimetype(self):
        """Tests that authentication fails if request is not JSON."""
        self.fake_session.get_auth_headers.return_value = self._auth_header()
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_post('/redfish/v1/SessionService/Sessions',
                              data='UserName: jim\nPassword: bob',
                              is_json=False)

        self.assertEqual(resp.status_code, 400)
        self.fake_session.assert_not_called()
        self.fake_session.get_auth_headers.assert_not_called()
        self.fake_session.get.assert_not_called()

    def test_get_invalid_session(self):
        """Tests that trying to get a nonexistent session fails."""
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_get('/redfish/v1/SessionService/Sessions/bingus',
                             headers=self._auth_header())

        self.assertEqual(resp.status_code, 404)
        self.fake_session.assert_called()
        self.fake_session.get.assert_called()

    def test_get_session_invalid_token(self):
        """Tests that trying to get a session fails with invalid token."""
        # check with both valid and invalid session identifiers
        self.fake_session.get.side_effect = ks_exceptions.http.Unauthorized()
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                                 session_id,
                                 headers=self._auth_header('foobar'))

            self.assertEqual(resp.status_code, 403)
            self.fake_session.assert_called()
            self.fake_session.get.assert_called()

    def test_get_session_no_token(self):
        """Tests that trying to get a session fails without a token."""
        # check with both valid and invalid session identifiers
        self.fake_session.get.return_value = self._mock_get_helper()
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                                 session_id,
                                 headers={})

            self.assertEqual(resp.status_code, 403)
            self.fake_session.assert_not_called()
            self.fake_session.get.assert_not_called()

    def test_get_all_sessions_invalid_auth(self):
        """Tests that trying to get session list fails with invalid creds."""
        self.fake_session.get.side_effect = ks_exceptions.http.Unauthorized()
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers=self._auth_header('foobar'))

        self.assertEqual(resp.status_code, 403)
        self.fake_session.assert_called()
        self.fake_session.get.assert_called()

    def test_get_all_sessions_no_auth(self):
        """Tests that trying to get session list fails without a token."""
        self.fake_session.get.return_value = self._mock_get_helper()
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers={})

        self.assertEqual(resp.status_code, 403)
        self.fake_session.assert_not_called()
        self.fake_session.get.assert_not_called()

    def test_delete_invalid_session(self):
        """Tests that trying to delete a nonexistent session fails."""
        self.fake_session.get.return_value = self._mock_get_helper()
        self.fake_session.delete.return_value = utils.FakeResponse({}, 204)
        resp = self.http_delete('/redfish/v1/SessionService/Sessions/bingus',
                                headers=self._auth_header())

        self.assertEqual(resp.status_code, 404)
        self.fake_session.assert_called()
        self.fake_session.get.assert_called()
        self.fake_session.delete.assert_not_called()

    def test_delete_session_invalid_token(self):
        """Tests that trying to delete a session fails with invalid token."""
        self.fake_session.get.side_effect = ks_exceptions.http.Unauthorized()
        # check with both valid and invalid session identifiers
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_delete('/redfish/v1/SessionService/Sessions/%s' %
                                    session_id,
                                    headers=self._auth_header('foobar'))

            self.assertEqual(resp.status_code, 403)
            self.fake_session.assert_called()
            self.fake_session.get.assert_called()
            self.fake_session.delete.assert_not_called()

    def test_delete_session_no_token(self):
        """Tests that trying to delete a session fails without a token."""
        self.fake_session.get.return_value = self._mock_get_helper()
        self.fake_session.delete.return_value = utils.FakeResponse({}, 204)
        # check with both valid and invalid session identifiers
        for session_id in FAKE_CREDS['TOKEN_ID'], 'bingus':
            resp = self.http_delete('/redfish/v1/SessionService/Sessions/%s' %
                                    session_id,
                                    headers={})

            self.assertEqual(resp.status_code, 403)
            self.fake_session.assert_not_called()
            self.fake_session.get.assert_not_called()
            self.fake_session.delete.assert_not_called()


class RedfishProxySessionDisabledTests(base.RedfishProxyTestCase):
    """Tests asserting that SessionService requests fail when not enabled."""

    def setUp(self):
        # Patch the keystone middleware and keystone Session objects
        # to return dummy values
        mw_patch = mock.patch('keystonemiddleware.auth_token.AuthProtocol',
                              utils.FakeMiddleware)
        self.addCleanup(mw_patch.stop)
        self.fake_middleware = mw_patch.start()

        sess_patch = mock.patch('keystoneauth1.session.Session', autospec=True)
        self.addCleanup(sess_patch.stop)
        self.fake_session = sess_patch.start()
        self.fake_session.return_value = self.fake_session
        super(RedfishProxySessionDisabledTests, self).setUp()

    def _set_cfg_opts(self):
        super(RedfishProxySessionDisabledTests, self)._set_cfg_opts()
        CONF.set_override('auth_strategy', 'noauth')
        # Keystone middleware sets this value upon initialization and our
        # SessionService code expects it so we set it here.
        CONF.register_opt(cfg.StrOpt('auth_url',
                                     default='http://localhost'),
                          group='keystone_authtoken')

    def test_get_sessionservice_info_disabled(self):
        resp = self.http_get('/redfish/v1/SessionService',
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 404)

    def test_get_current_session_disabled(self):
        resp = self.http_get('/redfish/v1/SessionService/Sessions/%s' %
                             FAKE_CREDS['TOKEN_ID'],
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 404)

    def test_get_all_sessions_disabled(self):
        resp = self.http_get('/redfish/v1/SessionService/Sessions',
                             headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 404)

    def test_delete_session_disabled(self):
        resp = self.http_delete('/redfish/v1/SessionService/Sessions/%s' %
                                FAKE_CREDS['TOKEN_ID'],
                                headers={'X-Auth-Token': FAKE_CREDS['TOKEN']})
        self.assertEqual(resp.status_code, 404)

    def test_authentication_disabled(self):
        auth = {'UserName': FAKE_CREDS['APP_CRED_ID'],
                'Password': FAKE_CREDS['APP_CRED_SECRET']}
        resp = self.http_post('/redfish/v1/SessionService/Sessions', data=auth)
        self.assertEqual(resp.status_code, 404)
