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

from oslo_policy import policy as oslo_policy
from oslo_utils import uuidutils

from ironic.common import exception
from ironic.common import policy
from ironic.common import states as ir_states
from ironic import objects


IRONIC_REDFISH_POWER_STATE_MAP = {
    ir_states.POWER_ON: 'On',
    ir_states.POWER_OFF: 'Off',
    ir_states.REBOOT: 'Reset',
    ir_states.SOFT_REBOOT: 'Reset'
}


REDFISH_IRONIC_TARGET_STATE_MAP = {
    'On': ir_states.POWER_ON,
    'ForceOn': ir_states.POWER_ON,
    'ForceOff': ir_states.POWER_OFF,
    'ForceRestart': ir_states.REBOOT,
    'GracefulShutdown': ir_states.SOFT_POWER_OFF,
    'GracefulRestart': ir_states.SOFT_REBOOT
}


def ironic_to_redfish_power_state(node_power_state):
    """Converts an Ironic node power state to a Redfish System power state.

    :param: node_power_state: The power state of an Ironic node.

    :raises: ValueError if the value of node_power_state is not a valid Ironic
             node power state.
    :return: The Redfish representation of node_power_state.
    """
    if node_power_state is None:
        return 'Unknown'
    try:
        return IRONIC_REDFISH_POWER_STATE_MAP[node_power_state]
    except KeyError:
        raise ValueError('Invalid node power state "%s"' % node_power_state)


def redfish_reset_type_to_ironic_power_state(target_state):
    """Returns the target Ironic power state implied by the given ResetType.

    :param: target_state: the ResetType specified by the Redfish client

    :raises: ValueError if the ResetType is unspecified or invalid
    :return: the target Ironic power state that corresponds to the ResetType
    """
    if not target_state:
        raise ValueError('Target power state must not be None')
    try:
        return REDFISH_IRONIC_TARGET_STATE_MAP[target_state]
    except KeyError:
        raise ValueError('Invalid node power state "%s"' % target_state)


def check_list_policy(context, object_type, owner=None):
    """Check if the list policy authorizes this request on an object.

    NOTE(s_zuk): Framework-agnostic rewrite of check_list_policy() from
    ironic/api/controllers/v1/utils.py:1589

    :param: context: the RequestContext object associated with this DB query
    :param: object_type: type of object being checked
    :param: owner: owner filter for list query, if any

    :raises: HTTPForbidden if the policy forbids access.
    :return: owner that should be used for list query, if needed
    """
    cdict = context.to_policy_values()
    try:
        policy.authorize('baremetal:%s:list_all' % object_type, cdict, context)
    except (exception.HTTPForbidden, oslo_policy.InvalidScope):
        # In the event the scoped policy fails, falling back to the
        # policy governing a filtered view.
        project_owner = cdict.get('project_id')
        if (not project_owner or (owner and owner != project_owner)):
            raise
        policy.authorize('baremetal:%s:list' % object_type, cdict, context)
        return project_owner
    return owner


def check_owner_policy(context, object_type, policy_name, owner, lessee=None,
                       conceal_node=False):
    """Check if the policy authorizes this request on an object.

    NOTE(s_zuk): Framework-agnostic rewrite of check_owner_policy() from
    ironic/api/controllers/v1/utils.py:1471.

    :param: context: the RequestContext object associated with this DB query
    :param: object_type: type of object being checked
    :param: policy_name: the name of the policy to check
    :param: owner: the owner
    :param: lessee: the lessee
    :param: conceal_node: the UUID of the node IF we should conceal the
                          existence of the node with a 404 Error instead of a
                          403 Error

    :raises: HTTPForbidden if the policy forbids access.
    """
    cdict = context.to_policy_values()
    target_dict = dict(cdict)
    target_dict[object_type + '.owner'] = owner
    if lessee:
        target_dict[object_type + '.lessee'] = lessee
    try:
        policy.authorize(policy_name, target_dict, context)
    except exception.HTTPForbidden:
        if conceal_node:
            # The caller does NOT have access to the node and we've been told
            # we should return a 404 instead of HTTPForbidden.
            raise exception.NodeNotFound(node=conceal_node)
        else:
            raise


def check_node_policy_and_retrieve(context, policy_name, node_ident,
                                   with_suffix=False):
    """Check if the specified policy authorizes this request on a node.

    NOTE(s_zuk): Framework-agnostic rewrite of check_node_policy_and_retrieve()
    from ironic/api/controllers/v1/utils.py:1501, will only get node by UUID.

    :param: context: the RequestContext object associated with this DB query
    :param: policy_name: Name of the policy to check.
    :param: node_ident: the UUID of a node.
    :param: with_suffix: whether the RPC node should include the suffix

    :raises: HTTPForbidden if the policy forbids access.
    :raises: NodeNotFound if the node is not found.
    :return: RPC node identified by node_ident
    """
    conceal_node = False
    try:
        rpc_node = get_rpc_node_by_uuid(context, node_ident)
    except exception.NodeNotFound:
        # NOTE(s_zuk): The _get_with_suffix() helper function called by the
        # Pecan version of this function checks the value of 'HAS_JSON_SUFFIX'
        # within the request environment. Here, we will instead leave it up to
        # the caller of this function to set the value of with_suffix to avoid
        # making any assumptions about the environment.
        if with_suffix:
            rpc_node = get_rpc_node_by_uuid(context, node_ident + '.json')
        else:
            raise

    # Project scoped users should get a 404 where as system scoped users should
    # get a 403.
    cdict = context.to_policy_values()
    if cdict.get('project_id', False):
        conceal_node = node_ident
    try:
        # Always check the ability to see the node BEFORE doing anything else.
        check_owner_policy(context, 'node', 'baremetal:node:get',
                           rpc_node['owner'], rpc_node['lessee'],
                           conceal_node=conceal_node)
    except exception.NotAuthorized:
        raise exception.NodeNotFound(node=node_ident)

    # If we reach here, we can see the node and we have access to view it.
    check_owner_policy(context, 'node', policy_name, rpc_node['owner'],
                       rpc_node['lessee'], conceal_node=False)
    return rpc_node


def get_rpc_node_by_uuid(context, node_ident):
    """Get the RPC node from the node uuid.

    NOTE(s_zuk): Framework-agnostic rewrite of get_rpc_node() from
    ironic/api/controllers/v1/utils.py:519, does not allow for getting node by
    name, only UUID.

    :param: context: the RequestContext object associated with this DB query
    :param: node_ident: the UUID of a node.

    :returns: The RPC Node.
    :raises: InvalidUuidOrName if the uuid provided is not valid.
    :raises: NodeNotFound if the node is not found.
    """
    # Check to see if the node_ident is a valid UUID.  If it is, treat it
    # as a UUID.
    if uuidutils.is_uuid_like(node_ident):
        return objects.Node.get_by_uuid(context, node_ident)

    # Ensure we raise the same exception as we did for the Juno release.
    raise exception.NodeNotFound(node=node_ident)
