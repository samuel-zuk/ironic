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

import ironic.common.states as ir_states


FAKE_CREDS = {'APP_CRED_ID': 'dc95dc97-0880-4bfb-815d-08234dfa07e8',
              'APP_CRED_SECRET': 'hunter2',
              'TOKEN_ID': 'dQw4w9WgXcQ',
              'TOKEN': 'super-secret-token-shhhhh',
              'NODE_UUID': '3b0060e4-f4d7-4078-9559-e356702bc1f6',
              'NODE_OWNER': 'mario',
              'NODE_PROJECT': 'mario-party',
              'NODE_PROJECT_ID': 'mario-party-4',
              'DOMAIN_ID': 'default_test',
              'DOMAIN_NAME': 'Testing',
              'REQUEST_ID': '063517b3-640d-4505-8dd8-df09843cb805'}


class FakeResponse(object):
    """Object that imitates a Flask response for use with tests."""
    def __init__(self, data={}, status_code=200):
        """Provide the request info needed for the Ironic proxy to work."""
        self.data = data
        self.status_code = status_code

    def json(self):
        """Return the object's data as a python dictionary."""
        return self.data


class FakeMiddleware(object):
    """Middleware that does nothing for use with tests requiring auth."""
    def __init__(self, app, *args, **kwargs):
        """Store a reference to the app (note: app must be first pos arg)."""
        self.app = app

    def __call__(self, env, start_response, *args, **kwargs):
        """Do nothing, pass the request data thru to the WSGI app."""
        return self.app(env, start_response)


class FakeNode(object):
    """Object that behaves enough like a Node object for use in tests."""
    def __init__(self, uuid=FAKE_CREDS['NODE_UUID'],
                 power_state=ir_states.POWER_ON,
                 provision_state=ir_states.ENROLL,
                 owner=FAKE_CREDS['NODE_PROJECT_ID'],
                 lessee=None, name=None, desc=None):
        """Provide the object with values to expose as instance variables."""
        self.uuid = uuid
        self.power_state = power_state
        self.provision_state = provision_state
        self.name = name
        self.description = desc
        self.owner = owner
        self.lessee = lessee

    def __call__(self, *args, **kwargs):
        """If the object is called, do nothing and return itself."""
        return self

    def __getitem__(self, item):
        """Make object subscriptable."""
        return getattr(self, item)


class FakeContext(object):
    """Object that behaves like an Ironic request context for use in tests."""
    def __init__(self, **kwargs):
        """Initialize with fake values which can be overwritten via kwargs."""
        self.cdict = {
            'auth_token': FAKE_CREDS['TOKEN'],
            'user_id': FAKE_CREDS['NODE_OWNER'],
            'project_id': FAKE_CREDS['NODE_PROJECT_ID'],
            'project_name': FAKE_CREDS['NODE_PROJECT'],
            'read_only': True,
            'show_deleted': True,
            'request_id': FAKE_CREDS['REQUEST_ID'],
            'is_public_api': True,
            'domain_id': FAKE_CREDS['DOMAIN_ID'],
            'user_domain_id': FAKE_CREDS['DOMAIN_ID'],
            'user_domain_name': FAKE_CREDS['DOMAIN_NAME'],
            'project_domain_id': FAKE_CREDS['DOMAIN_ID'],
            'roles': None,
            'overwrite': True
        }

        for key in kwargs.keys():
            if key in self.cdict.keys():
                self.cdict[key] = kwargs[key]

    def to_policy_values(self):
        """Return the internal context values as a dict."""
        return self.cdict
