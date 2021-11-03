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

from flask import Blueprint
from flask import current_app
from flask import jsonify


v1 = Blueprint('v1', __name__)


@v1.get('/redfish/v1')
def response():
    v1 = {
        '@odata.type': '#ServiceRoot.v1_0_0.ServiceRoot',
        'Id': 'IronicProxy',
        'Name': 'Ironic Redfish Proxy',
        'RedfishVersion': '1.0.0',
        'Links': {},
        'Systems': {
            '@odata.id': '/redfish/v1/Systems'
        },
        '@odata.id': '/redfish/v1/'
    }

    if current_app.config['auth_strategy'] == 'keystone':
        v1.update({
            'SessionService': {
                '@odata.id': '/redfish/v1/SessionService'
            },
            'Links': {
                'Sessions': {
                    '@odata.id': '/redfish/v1/SessionService/Sessions'
                }
            }
        })

    return jsonify(v1)
