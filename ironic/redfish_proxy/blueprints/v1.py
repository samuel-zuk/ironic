from flask import Blueprint, current_app, jsonify

from ironic.redfish_proxy.decorators.auth import is_public_api


v1 = Blueprint('v1', __name__)


@v1.get('/redfish/v1')
@is_public_api
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
