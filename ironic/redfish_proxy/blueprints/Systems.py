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

import json

from flask import abort
from flask import Blueprint
from flask import g
from flask import jsonify
from flask import make_response
from flask import request

from ironic.common import exception
from ironic.common import states as ir_states
from ironic.objects.node import Node
from ironic.redfish_proxy import utils as proxy_utils


Systems = Blueprint('Systems', __name__)


@Systems.get('/redfish/v1/Systems')
def systems_collection_info():
    """Returns a Systems Collection containing a list of Ironic nodes.

    Lists all the nodes the user has access to, represented here as Redfish
    System objects. Requires the user to be authenticated.
    """
    # Ensure the user is allowed by policy to list baremetal nodes.
    try:
        project = proxy_utils.check_list_policy(g.context, object_type='node')
    except Exception:
        abort(403)

    # Query the DB to get the list of nodes to be returned.
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
    """Returns the Ironic node with the specified UUID as a Redfish System.

    Requires the user to be authenticated and to be allowed by policy to get
    the node in question. Currently, the only info to be returned is the node
    UUID, name, description, and power state.
    """
    # Ensure the user is allowed by policy to get this node.
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

    # Include name and description if the node has either or both.
    if node.name:
        node_dict['Name'] = node.name
    if node.description:
        node_dict['Description'] = node.description

    return jsonify(node_dict)


@Systems.post('/redfish/v1/Systems/<node_uuid>/Actions/ComputerSystem.Reset')
def set_system_power_state(node_uuid):
    """Initiates a change in the power state of the specified node.

    Requires the user to be authenticated and to be allowed by policy to get
    the node in question. Expects a body containing a ResetType key with the
    value of the ResetType to be initiated.
    """
    # Check if the POST request body is json; if not, attempt to jsonify it.
    body = {}
    if request.is_json:
        body = request.get_json()
    else:
        try:
            body = json.loads(
                list(request.form.to_dict().keys())[0])
        except json.JSONDecodeError:
            abort(400)

    # Ensure the ResetType is specified and valid, get the corresponding
    # target Ironic power state to be sent with the RPC call.
    try:
        target_state = proxy_utils.redfish_reset_type_to_ironic_power_state(
            body['ResetType'])
    except (KeyError, ValueError):
        abort(400)
    except Exception:
        raise

    # Ensure the user is allowed by policy to access this node.
    try:
        node = proxy_utils.check_node_policy_and_retrieve(
            g.context, 'baremetal:node:set_power_state', node_uuid)
    except exception.HTTPForbidden:
        abort(403)
    except exception.NodeNotFound:
        abort(404)

    # If the node is cleaning, do not allow for it to be reset.
    if node.provision_state in (ir_states.CLEANWAIT, ir_states.CLEANING):
        abort(400)

    # Make the RPC call.
    topic = g.rpcapi.get_topic_for(node)
    g.rpcapi.change_node_power_state(g.context,
                                     node.uuid,
                                     target_state,
                                     timeout=None,
                                     topic=topic)

    return make_response(('', 204))
