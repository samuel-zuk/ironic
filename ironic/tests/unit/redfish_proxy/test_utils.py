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

from oslo_policy import policy as oslo_policy

from ironic.common import exception
import ironic.common.states as ir_states
from ironic.objects.node import Node
from ironic.redfish_proxy import utils
from ironic.tests import base
from ironic.tests.unit.redfish_proxy.utils import FAKE_CREDS
from ironic.tests.unit.redfish_proxy.utils import FakeContext
from ironic.tests.unit.redfish_proxy.utils import FakeNode


class RedfishProxyUtilTests(base.TestCase):
    """Tests asserting Redfish proxy utility functions work."""

    def test_ironic_to_redfish_power_state(self):
        """Ensure valid Ironic states translate properly."""
        for state, expected in ((ir_states.POWER_ON, 'On'),
                                (ir_states.POWER_OFF, 'Off'),
                                (ir_states.REBOOT, 'Reset'),
                                (ir_states.SOFT_REBOOT, 'Reset'),
                                (None, 'Unknown')):
            self.assertEqual(utils.ironic_to_redfish_power_state(state),
                             expected)

    def test_ironic_to_redfish_power_state_invalid(self):
        """Ensure invalid Ironic states are handled properly."""
        for state in ('power of', 1234, 'Reset', [ir_states.POWER_ON]):
            e = self.assertRaises(ValueError,
                                  utils.ironic_to_redfish_power_state,
                                  state)
            self.assertIn(str(state), str(e))

    def test_redfish_reset_to_ironic_power_state(self):
        """Ensure valid Redfish ResetType values translate properly."""
        for state, expected in (('On', ir_states.POWER_ON),
                                ('ForceOn', ir_states.POWER_ON),
                                ('ForceOff', ir_states.POWER_OFF),
                                ('ForceRestart', ir_states.REBOOT),
                                ('GracefulShutdown', ir_states.SOFT_POWER_OFF),
                                ('GracefulRestart', ir_states.SOFT_REBOOT)):
            result = utils.redfish_reset_type_to_ironic_power_state(state)
            self.assertEqual(result, expected)

    def test_redfish_reset_to_ironic_power_state_invalid(self):
        """Ensure invalid ResetType values are handled properly."""
        for state in ('ForceOf', 12345, None, ['On']):
            e = self.assertRaises(
                exception.InvalidRedfishResetType,
                utils.redfish_reset_type_to_ironic_power_state,
                state)
            self.assertIn(str(state), str(e))

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_list_policy_authorized(self, mock_authorize):
        """Ensure list policy checks work when user is authorized."""
        mock_authorize.return_value = None
        ctx = FakeContext()

        self.assertEqual(
            utils.check_list_policy(ctx, 'node',
                                    FAKE_CREDS['NODE_PROJECT_ID']),
            FAKE_CREDS['NODE_PROJECT_ID'])
        mock_authorize.assert_called_once_with(
            'baremetal:node:list_all', ctx.cdict, ctx)

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_list_policy_project_authorized(self, mock_authorize):
        """Ensure list policy checks work when project is authorized."""
        # Test w/ both of the ways the initial policy check can fail
        for exc in (exception.HTTPForbidden(resource='node'),
                    oslo_policy.InvalidScope('node:get', 'root', 'none')):
            mock_authorize.side_effect = [exc, None]
            ctx = FakeContext()

            self.assertEqual(
                utils.check_list_policy(ctx, 'node',
                                        FAKE_CREDS['NODE_PROJECT_ID']),
                FAKE_CREDS['NODE_PROJECT_ID'])
            calls = [mock.call('baremetal:node:list_all', ctx.cdict, ctx),
                     mock.call('baremetal:node:list', ctx.cdict, ctx)]
            mock_authorize.assert_has_calls(calls)
            mock_authorize.reset_mock()

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_list_policy_project_unauthorized(self, mock_authorize):
        """Ensure list policy checks fail if user and project unauthorized."""
        # Test w/ both of the ways the policy check can fail
        for exc in (exception.HTTPForbidden(resource='node'),
                    oslo_policy.InvalidScope('node:get', 'root', 'none')):
            mock_authorize.side_effect = [exc, exc]
            ctx = FakeContext()

            self.assertRaises(type(exc),
                              utils.check_list_policy,
                              ctx, 'node', FAKE_CREDS['NODE_PROJECT_ID'])
            calls = [mock.call('baremetal:node:list_all', ctx.cdict, ctx),
                     mock.call('baremetal:node:list', ctx.cdict, ctx)]
            mock_authorize.assert_has_calls(calls)
            mock_authorize.reset_mock()

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_list_policy_owner_not_project_owner(self, mock_authorize):
        """Ensure list policy checks fail if user is not project owner."""
        # Test w/ both of the ways the policy check can fail
        for exc in (exception.HTTPForbidden(resource='node'),
                    oslo_policy.InvalidScope('node:get', 'root', 'none')):
            mock_authorize.side_effect = exc
            ctx = FakeContext()

            self.assertRaises(type(exc),
                              utils.check_list_policy,
                              ctx, 'node', 'foobar')
            mock_authorize.assert_called_once_with('baremetal:node:list_all',
                                                   ctx.cdict, ctx)
            mock_authorize.reset_mock()

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_owner_policy_authorized(self, mock_authorize):
        """Ensure owner policy checks work when user is authorized."""
        mock_authorize.return_value = None
        ctx = FakeContext()

        utils.check_owner_policy(ctx, 'node', 'baremetal:node:get',
                                 FAKE_CREDS['NODE_PROJECT_ID'])
        target_dict = ctx.cdict
        target_dict['node.owner'] = FAKE_CREDS['NODE_PROJECT_ID']
        mock_authorize.assert_called_once_with('baremetal:node:get',
                                               target_dict, ctx)

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_owner_policy_unauthorized(self, mock_authorize):
        """Ensure owner policy checks fail when user is unauthorized."""
        mock_authorize.side_effect = exception.HTTPForbidden(resource='node')
        ctx = FakeContext()

        self.assertRaises(exception.HTTPForbidden,
                          utils.check_owner_policy,
                          ctx, 'node', 'baremetal:node:get',
                          FAKE_CREDS['NODE_PROJECT_ID'])
        target_dict = ctx.cdict
        target_dict['node.owner'] = FAKE_CREDS['NODE_PROJECT_ID']
        mock_authorize.assert_called_once_with('baremetal:node:get',
                                               target_dict, ctx)

    @mock.patch('ironic.common.policy.authorize', autospec=True)
    def test_check_owner_policy_conceal(self, mock_authorize):
        """Ensure failing owner policy checks conceal nodes when specified."""
        mock_authorize.side_effect = exception.HTTPForbidden(resource='node')
        ctx = FakeContext()

        e = self.assertRaises(exception.NodeNotFound,
                              utils.check_owner_policy,
                              ctx, 'node', 'baremetal:node:get',
                              FAKE_CREDS['NODE_PROJECT_ID'],
                              conceal_node=FAKE_CREDS['NODE_UUID'])
        self.assertIn(FAKE_CREDS['NODE_UUID'], str(e))
        target_dict = ctx.cdict
        target_dict['node.owner'] = FAKE_CREDS['NODE_PROJECT_ID']
        mock_authorize.assert_called_once_with('baremetal:node:get',
                                               target_dict, ctx)

    @mock.patch.object(Node, 'get_by_uuid', autospec=True)
    def test_get_rpc_node_by_uuid(self, mock_node_get):
        """Ensure valid nodes can be retrieved by UUID."""
        mock_node_get.return_value = 'this is a node'
        ctx = FakeContext()

        self.assertEqual(
            utils.get_rpc_node_by_uuid(ctx, FAKE_CREDS['NODE_UUID']),
            'this is a node')
        mock_node_get.assert_called_once_with(ctx, FAKE_CREDS['NODE_UUID'])

    @mock.patch.object(Node, 'get_by_uuid', autospec=True)
    def test_get_rpc_node_by_uuid_invalid_uuid(self, mock_node_get):
        """Ensure node queries fail when specifying an invalid UUID."""
        mock_node_get.return_value = 'this is a node'
        ctx = FakeContext()

        e = self.assertRaises(exception.InvalidUUID,
                              utils.get_rpc_node_by_uuid,
                              ctx, 'this is not a valid UUID')
        self.assertIn('this is not a valid UUID', str(e))
        mock_node_get.assert_not_called()

    @mock.patch.object(Node, 'get_by_uuid', autospec=True)
    def test_get_rpc_node_by_uuid_not_found(self, mock_node_get):
        """Ensure node queries fail when node is not found."""
        mock_node_get.return_value = None
        ctx = FakeContext()

        e = self.assertRaises(exception.NodeNotFound,
                              utils.get_rpc_node_by_uuid,
                              ctx, FAKE_CREDS['APP_CRED_ID'])
        self.assertIn(FAKE_CREDS['APP_CRED_ID'], str(e))
        mock_node_get.assert_called_once_with(ctx, FAKE_CREDS['APP_CRED_ID'])

    @mock.patch('ironic.redfish_proxy.utils.check_owner_policy', autospec=True)
    @mock.patch('ironic.redfish_proxy.utils.get_rpc_node_by_uuid',
                autospec=True)
    def test_check_node_policy_retrieve_authorized(self, mock_get_node,
                                                   mock_check_policy):
        """Ensure we can retrieve nodes when user is authorized."""
        fake_node = FakeNode()
        mock_get_node.return_value = fake_node
        mock_check_policy.return_value = None
        ctx = FakeContext()

        self.assertEqual(
            utils.check_node_policy_and_retrieve(ctx, 'baremetal:node:list',
                                                 FAKE_CREDS['NODE_UUID']),
            fake_node)
        mock_get_node.assert_called_once_with(ctx, FAKE_CREDS['NODE_UUID'])
        calls = [mock.call(ctx, 'node', 'baremetal:node:get',
                           FAKE_CREDS['NODE_PROJECT_ID'], None,
                           conceal_node=FAKE_CREDS['NODE_UUID']),
                 mock.call(ctx, 'node', 'baremetal:node:list',
                           FAKE_CREDS['NODE_PROJECT_ID'], None,
                           conceal_node=False)]
        mock_check_policy.assert_has_calls(calls)

    @mock.patch('ironic.redfish_proxy.utils.check_owner_policy', autospec=True)
    @mock.patch('ironic.redfish_proxy.utils.get_rpc_node_by_uuid',
                autospec=True)
    def test_check_node_policy_retrieve_node_not_visible(self, mock_get_node,
                                                         mock_check_policy):
        """Ensure node retrieve fails if project-scoped user can't see node."""
        mock_get_node.return_value = FakeNode()
        mock_check_policy.side_effect = exception.NotAuthorized()
        ctx = FakeContext()

        e = self.assertRaises(exception.NodeNotFound,
                              utils.check_node_policy_and_retrieve,
                              ctx, 'baremetal:node:list',
                              FAKE_CREDS['NODE_UUID'])
        mock_get_node.assert_called_with(ctx, FAKE_CREDS['NODE_UUID'])
        mock_check_policy.assert_called_once_with(
            ctx, 'node', 'baremetal:node:get', FAKE_CREDS['NODE_PROJECT_ID'],
            None, conceal_node=FAKE_CREDS['NODE_UUID'])
        self.assertIn(FAKE_CREDS['NODE_UUID'], str(e))

    @mock.patch('ironic.redfish_proxy.utils.check_owner_policy', autospec=True)
    @mock.patch('ironic.redfish_proxy.utils.get_rpc_node_by_uuid',
                autospec=True)
    def test_check_node_policy_retrieve_unauthorized(self, mock_get_node,
                                                     mock_check_policy):
        """Ensure node retrieve fails if check on specified policy fails."""
        mock_get_node.return_value = FakeNode()
        mock_check_policy.side_effect = [
            None, exception.HTTPForbidden(resource='node')]
        ctx = FakeContext()

        self.assertRaises(exception.HTTPForbidden,
                          utils.check_node_policy_and_retrieve,
                          ctx, 'baremetal:node:list',
                          FAKE_CREDS['NODE_UUID'])
        mock_get_node.assert_called_with(ctx, FAKE_CREDS['NODE_UUID'])
        calls = [mock.call(ctx, 'node', 'baremetal:node:get',
                           FAKE_CREDS['NODE_PROJECT_ID'], None,
                           conceal_node=FAKE_CREDS['NODE_UUID']),
                 mock.call(ctx, 'node', 'baremetal:node:list',
                           FAKE_CREDS['NODE_PROJECT_ID'], None,
                           conceal_node=False)]
        mock_check_policy.assert_has_calls(calls)

    @mock.patch('ironic.redfish_proxy.utils.check_owner_policy', autospec=True)
    @mock.patch('ironic.redfish_proxy.utils.get_rpc_node_by_uuid',
                autospec=True)
    def test_check_node_policy_retrieve_node_not_found(self, mock_get_node,
                                                       mock_check_policy):
        """Ensure node retrieve fails if the node is not found."""
        mock_get_node.side_effect = exception.NodeNotFound(node='foobar')
        mock_check_policy.return_value = None
        ctx = FakeContext()

        e = self.assertRaises(exception.NodeNotFound,
                              utils.check_node_policy_and_retrieve,
                              ctx, 'baremetal:node:list', 'foobar')
        mock_get_node.assert_called_with(ctx, 'foobar')
        mock_check_policy.assert_not_called()
        self.assertIn('foobar', str(e))
