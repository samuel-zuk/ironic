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

from oslo_config import cfg

from ironic.conf import CONF


FAKE_CREDS = {'APP_CRED_ID': 'im-a-uuid-haha',
              'APP_CRED_SECRET': 'hunter2',
              'TOKEN_ID': 'dQw4w9WgXcQ',
              'TOKEN': 'im-a-token-lol'}


class FakeKeystoneClientSession(object):
    """An object that simulates a keystoneauth1 Session for use with tests."""
    def __init__(self, auth={}, *args, **kwargs):
        if auth.__class__.__name__ == 'ApplicationCredential':
            auth_info = auth.auth_methods[0]
            self.app_cred_id = auth_info.application_credential_id
            self.app_cred_secret = auth_info.application_credential_secret
        elif auth.__class__.__name__ == 'Token':
            self.token = auth.token

    def get_token(self, *args, **kwargs):
        # We assume if get_token is called, the session was initialized with
        # an ApplicationCredential as the auth parameter.
        if self.app_cred_id != FAKE_CREDS['APP_CRED_ID']:
            raise Exception('Unauthorized')
        if self.app_cred_secret != FAKE_CREDS['APP_CRED_SECRET']:
            raise Exception('Unauthorized')

        return FAKE_CREDS['TOKEN']

    def get(self, url, headers={}, *args, **kwargs):
        # We assume if get gis being called, we are using a session token.
        if '/auth/tokens' not in url:
            return self.FakeResponse({})
        if headers['X-Subject-Token'] != FAKE_CREDS['TOKEN']:
            raise Exception('Unauthorized')

        # The info the SessionService expects to receive.
        resp = {
            'token': {
                'audit_ids': FAKE_CREDS['TOKEN_ID'],
                'application_credential': {'id': FAKE_CREDS['APP_CRED_ID']}
            }
        }
        return self.FakeResponse(resp)

    # Exists because .json() is called on Responses and that breaks dicts
    class FakeResponse(object):
        def __init__(self, data):
            self.data = data

        def json(self):
            return self.data


class FakeKeystoneMiddleware(object):
    """Middleware that does nothing for use with tests requiring Keystone."""
    def __init__(self, app, *args, **kwargs):
        self.app = app
        # Keystone middleware sets this value upon initialization and our
        # SessionService code expects it so we set it here.
        CONF.register_opt(cfg.StrOpt('auth_url',
                                     default='http://localhost'),
                          group='keystone_authtoken')

    def __call__(self, env, start_response, *args, **kwargs):
        return self.app(env, start_response)
