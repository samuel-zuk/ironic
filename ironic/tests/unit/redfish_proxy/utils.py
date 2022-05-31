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
              'NODE_PROJECT': 'mario-party'}


class FakeResponse(object):
    def __init__(self, data={}, status_code=200):
        self.data = data
        self.status_code = status_code

    def json(self):
        return self.data


class FakeMiddleware(object):
    """Middleware that does nothing for use with tests requiring auth."""
    def __init__(self, app, *args, **kwargs):
        self.app = app

    def __call__(self, env, start_response, *args, **kwargs):
        return self.app(env, start_response)


class FakeNode(object):
    def __init__(self, uuid=FAKE_CREDS['NODE_UUID'],
                 power_state=ir_states.POWER_ON,
                 provision_state=ir_states.ENROLL,
                 name=None, desc=None):
        self.uuid = uuid
        self.power_state = power_state
        self.provision_state = provision_state
        self.name = name
        self.description = desc

    def __call__(self, *args, **kwargs):
        return self
