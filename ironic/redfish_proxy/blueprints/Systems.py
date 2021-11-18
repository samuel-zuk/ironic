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

from flask import abort
from flask import Blueprint
from flask import g
from flask import jsonify

from ironic.common import exception
from ironic.objects.node import Node
from ironic.redfish_proxy import utils as proxy_utils


Systems = Blueprint('Systems', __name__)


@Systems.get('/redfish/v1/Systems')
def systems_collection_info():
    try:
        project = proxy_utils.check_list_policy(context=g.context,
                                                object_type='node')
    except Exception:
        abort(403)

    node_list = Node.list(g.context,
                          filters={'project': project},
                          fields=['uuid'])

    return jsonify({
        '@odata.type': '#ComputerSystemCollection.ComputerSystemCollection',
        'Name': 'Ironic Node Collection',
        'Members@odata.count': len(node_list),
        'Members': list(map(
            (lambda node: {'@odata.id': '/redfish/v1/Systems/%s' % node.uuid}),
            node_list)),
        '@odata.id': '/redfish/v1/Systems'
    })


@Systems.get('/redfish/v1/Systems/<node_uuid>')
def system_info(node_uuid):
    try:
        node = proxy_utils.check_node_policy_and_retrieve(
            g.context, 'baremetal:node:get', node_uuid)
    except exception.HTTPForbidden:
        abort(403)
    except exception.NodeNotFound:
        abort(404)

    node_dict = {
        '@odata.type': '#ComputerSystem.v1.0.0.ComputerSystem',
        'Id': node_uuid,
        'UUID': node_uuid,
        'PowerState': (
            proxy_utils.ironic_to_redfish_power_state(node.power_state)),
        'Actions': {
            '#ComputerSystem.Reset': {
                'target': (
                    '/redfish/v1/Systems/%s/Actions/ComputerSystem.Reset'
                    % node_uuid),
                'ResetType@Redfish.AllowableValues': [
                    'On',
                    'ForceOn',
                    'ForceOff',
                    'ForceRestart',
                    'GracefulRestart',
                    'GracefulShutdown'
                ]
            }
        },
        '@odata.id': '/redfish/v1/Systems/%s' % node_uuid
    }
    if node.name:
        node_dict['Name'] = node.name
    if node.description:
        node_dict['Description'] = node.description

    return jsonify(node_dict)


@Systems.post('/redfish/v1/Systems/<node_uuid>/Actions/ComputerSystem.Reset')
def set_system_power_state(node_uuid):
    return 'Setting the power state of system %s' % node_uuid
