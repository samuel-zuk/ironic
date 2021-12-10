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
from flask import make_response


ServiceRoot = Blueprint('ServiceRoot', __name__)


@ServiceRoot.get('/redfish/v1')
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


@ServiceRoot.get('/redfish/v1/odata')
def odata_document():
    # Modeled after the sample service document provided in section 6.3 of:
    # https://www.dmtf.org/sites/default/files/standards/documents/DSP2052_1.0.0.pdf
    doc = {
        '@odata.context': '/redfish/v1/$metadata',
        'value': [
            {
                'name': 'Service',
                'kind': 'Singleton',
                'url': '/redfish/v1/'
            },
            {
                'name': 'Systems',
                'kind': 'Singleton',
                'url': '/redfish/v1/Systems'
            }
        ]
    }

    if current_app.config['auth_strategy'] == 'keystone':
        doc['value'].extend((
            {
                'name': 'SessionService',
                'kind': 'Singleton',
                'url': '/redfish/v1/SessionService'
            },
            {
                'name': 'Sessions',
                'kind': 'Singleton',
                'url': '/redfish/v1/SessionService/Sessions'
            }
        ))

    return jsonify(doc)


@ServiceRoot.get('/redfish/v1/$metadata')
def metadata_document():
    # placeholder
    doc_file = open('ironic/redfish_proxy/schema.xml', 'r')
    doc_str = doc_file.read()
    doc_file.close()

    response = make_response(doc_str, 200)
    response.headers['Content-Type'] = 'application/xml'
    return response
