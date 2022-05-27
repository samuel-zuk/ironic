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
from uuid import uuid4 as generate_uuid

from oslo_policy.policy import InvalidScope

import ironic.common.exception as ir_exceptions
import ironic.common.states as ir_states
from ironic.conf import CONF
from ironic.objects.node import Node
import ironic.redfish_proxy.utils as proxy_utils
from ironic.tests.unit.redfish_proxy import base
from ironic.tests.unit.redfish_proxy import utils
from ironic.tests.unit.redfish_proxy.utils import FAKE_CREDS


class RedfishProxySystemsTests(base.RedfishProxyTestCase):
    """Tests asserting that systems-related functions work as intended."""
    def _set_cfg_opts(self):
        """Set authentication strategy to "noauth" for these tests."""
        super(RedfishProxySystemsTests, self)._set_cfg_opts()
        CONF.set_override('auth_strategy', 'noauth')

    @mock.patch.object(Node, 'list', autospec=True)
    @mock.patch.object(proxy_utils, 'check_list_policy', autospec=True)
    def test_get_systems(self, mock_list_policy, mock_node_list):
        """Tests that requests to return a list of nodes resolve correctly."""
        mock_list_policy.return_value = utils.FAKE_CREDS['NODE_PROJECT']
        mock_node_list.return_value = [utils.FakeNode()]

        resp = self.http_get('/redfish/v1/Systems')
        self.assertEqual(resp.status_code, 200)
        mock_list_policy.assert_called_once()
        mock_node_list.assert_called_once()
        self.assertIn({'filters': {'project': FAKE_CREDS['NODE_PROJECT']},
                       'fields': ['uuid']},
                      mock_node_list.call_args)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        for x in 'Name', 'Members':
            self.assertIsNotNone(resp_body[x])
        self.assertEqual(resp_body['@odata.type'],
                         '#ComputerSystemCollection.ComputerSystemCollection')
        self.assertEqual(resp_body['@odata.id'], '/redfish/v1/Systems')
        self.assertEqual(resp_body['Members@odata.count'],
                         len(resp_body['Members']))
        node_url = '/redfish/v1/Systems/%s' % FAKE_CREDS['NODE_UUID']
        self.assertIn({'@odata.id': node_url}, resp_body['Members'])

    @mock.patch.object(Node, 'list', autospec=True)
    @mock.patch.object(proxy_utils, 'check_list_policy', autospec=True)
    def test_get_multiple_systems(self, mock_list_policy, mock_node_list):
        """Tests list functionality with multiple nodes."""
        mock_list_policy.return_value = utils.FAKE_CREDS['NODE_PROJECT']
        many_uuids = [str(generate_uuid()) for i in range(0, 10)]
        many_nodes = [utils.FakeNode(uuid) for uuid in many_uuids]
        mock_node_list.return_value = many_nodes

        resp = self.http_get('/redfish/v1/Systems')
        self.assertEqual(resp.status_code, 200)
        mock_list_policy.assert_called_once()
        mock_node_list.assert_called_once()
        self.assertIn({'filters': {'project': FAKE_CREDS['NODE_PROJECT']},
                       'fields': ['uuid']},
                      mock_node_list.call_args)

        resp_body = resp.get_json()
        self.assertIsNotNone(resp_body)
        self.assertIsNotNone(resp_body['Members'])
        self.assertEqual(resp_body['Members@odata.count'], 10)
        self.assertEqual(resp_body['Members@odata.count'],
                         len(resp_body['Members']))
        for uuid in many_uuids:
            self.assertIn({'@odata.id': '/redfish/v1/Systems/%s' % uuid},
                          resp_body['Members'])

    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_get_system_by_uuid(self, mock_node_policy_retrieve):
        """Tests that requests for a specific node's info resolve correctly."""
        node_name = 'FakeNode'
        node_desc = 'Fake Ironic Node'
        fake_node = utils.FakeNode(power_state=ir_states.POWER_ON,
                                   name=node_name, desc=node_desc)
        mock_node_policy_retrieve.return_value = fake_node

        resp = self.http_get('/redfish/v1/Systems/%s' %
                             FAKE_CREDS['NODE_UUID'])
        self.assertEqual(resp.status_code, 200)
        mock_node_policy_retrieve.assert_called_once()
        for arg in ('baremetal:node:get', FAKE_CREDS['NODE_UUID']):
            self.assertIn(arg, mock_node_policy_retrieve.call_args.args)

        # Giving some expressions var names to make the test code less gross
        resp_body = resp.get_json()
        state = proxy_utils.ironic_to_redfish_power_state(ir_states.POWER_ON)
        reset_types = list(proxy_utils.REDFISH_IRONIC_TARGET_STATE_MAP.keys())
        resp_actions = resp_body['Actions']['#ComputerSystem.Reset']
        resp_allowable_vals = resp_actions['ResetType@Redfish.AllowableValues']

        self.assertIsNotNone(resp_body)
        self.assertEqual(resp_body['@odata.type'],
                         '#ComputerSystem.v1.0.0.ComputerSystem')
        self.assertEqual(resp_body['@odata.id'],
                         '/redfish/v1/Systems/%s' % FAKE_CREDS['NODE_UUID'])
        for x in ('Id', 'UUID'):
            self.assertEqual(resp_body[x], FAKE_CREDS['NODE_UUID'])
        self.assertEqual(resp_body['Name'], node_name)
        self.assertEqual(resp_body['Description'], node_desc)
        self.assertEqual(resp_body['PowerState'], state)
        self.assertIsNotNone(resp_body['Actions']['#ComputerSystem.Reset'])
        self.assertEqual(resp_actions['target'],
                         '/redfish/v1/Systems/%s/Actions/'
                         'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'])
        self.assertCountEqual(resp_allowable_vals, reset_types)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state(self, mock_node_policy_retrieve, mock_rpcapi):
        """Tests that requests to change node power state resolve correctly."""
        fake_node = utils.FakeNode()
        mock_node_policy_retrieve.return_value = fake_node
        # This ensures method calls on the mock RPCAPI object are of the form
        # Mock.method() instead of Mock().method(), which breaks assertions.
        mock_rpcapi.return_value = mock_rpcapi
        mock_rpcapi.get_topic_for.return_value = 'test'

        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data={'ResetType': 'ForceOff'})
        self.assertEqual(resp.status_code, 204)

        mock_rpcapi.get_topic_for.assert_called_once_with(fake_node)
        mock_rpcapi.change_node_power_state.assert_called_once()
        rpc_calls = mock_rpcapi.change_node_power_state.call_args
        self.assertIn({'timeout': None, 'topic': 'test'}, rpc_calls)
        s = proxy_utils.redfish_reset_type_to_ironic_power_state('ForceOff')
        for arg in (FAKE_CREDS['NODE_UUID'], s):
            self.assertIn(arg, rpc_calls.args)

    @mock.patch.object(Node, 'list', autospec=True)
    @mock.patch.object(proxy_utils, 'check_list_policy', autospec=True)
    def test_get_systems_unauthorized(self, mock_list_policy, mock_node_list):
        """Tests that listing nodes fails when user lacks permissions."""
        mock_list_policy.side_effect = ir_exceptions.HTTPForbidden()
        mock_node_list.return_value = [utils.FakeNode()]

        resp = self.http_get('/redfish/v1/Systems')
        mock_list_policy.assert_called_once()
        mock_node_list.assert_not_called()
        self.assertEqual(resp.status_code, 403)

    @mock.patch.object(Node, 'list', autospec=True)
    @mock.patch.object(proxy_utils, 'check_list_policy', autospec=True)
    def test_get_systems_invalid_scope(self, mock_list_policy, mock_node_list):
        """Tests that listing nodes fails when user is improperly scoped."""
        mock_list_policy.side_effect = InvalidScope('node:get', 'user', 'none')
        mock_node_list.return_value = [utils.FakeNode()]
        resp = self.http_get('/redfish/v1/Systems')

        mock_list_policy.assert_called_once()
        mock_node_list.assert_not_called()
        self.assertEqual(resp.status_code, 403)

    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_get_system_invalid_uuid(self, mock_node_policy_retrieve):
        """Tests that node info queries fail when the given UUID is invalid."""
        mock_node_policy_retrieve.side_effect = ir_exceptions.NodeNotFound()
        resp = self.http_get('/redfish/v1/Systems/foo-bar')

        mock_node_policy_retrieve.assert_called_once()
        self.assertEqual(resp.status_code, 404)

    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_get_system_unauthorized(self, mock_node_policy_retrieve):
        """Tests that node info queries fail when user lacks permissions."""
        mock_node_policy_retrieve.side_effect = ir_exceptions.HTTPForbidden()
        resp = self.http_get('/redfish/v1/Systems/%s' %
                             FAKE_CREDS['NODE_UUID'])

        mock_node_policy_retrieve.assert_called_once()
        self.assertEqual(resp.status_code, 403)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_unauthorized(self, mock_node_policy_retrieve,
                                             mock_rpcapi):
        """Tests that power state requests fail when user lacks permissions."""
        mock_node_policy_retrieve.side_effect = ir_exceptions.HTTPForbidden()
        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data={'ResetType': 'ForceOff'})

        mock_node_policy_retrieve.assert_called_once()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 403)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_invalid_uuid(self, mock_node_policy_retrieve,
                                             mock_rpcapi):
        """Tests that power state requests for an invalid node fail."""
        mock_node_policy_retrieve.side_effect = ir_exceptions.NodeNotFound()
        resp = self.http_post('/redfish/v1/Systems/foo-bar/Actions/'
                              'ComputerSystem.Reset',
                              data={'ResetType': 'ForceOff'})

        mock_node_policy_retrieve.assert_called_once()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 404)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_invalid_state(self, mock_node_policy_retrieve,
                                              mock_rpcapi):
        """Tests that power state requests fail with an invalid state."""
        mock_node_policy_retrieve.return_value = utils.FakeNode()
        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data={'ResetType': 'DoABackflip'})

        mock_node_policy_retrieve.assert_not_called()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 400)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_empty_request(self, mock_node_policy_retrieve,
                                              mock_rpcapi):
        """Tests that power state requests fail with no state specified."""
        mock_node_policy_retrieve.return_value = utils.FakeNode()
        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data={})

        mock_node_policy_retrieve.assert_not_called()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 400)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_bad_mimetype(self, mock_node_policy_retrieve,
                                             mock_rpcapi):
        """Tests that power state requests fail when request is not JSON."""
        mock_node_policy_retrieve.return_value = utils.FakeNode()
        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data='ResetType: ForceOff', is_json=False)

        mock_node_policy_retrieve.assert_not_called()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 400)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_node_cleaning(self, mock_node_policy_retrieve,
                                              mock_rpcapi):
        """Tests that power state requests fail when node is cleaning."""
        fake_node = utils.FakeNode(provision_state=ir_states.CLEANING)
        mock_node_policy_retrieve.return_value = fake_node
        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data={'ResetType': 'ForceOff'})

        mock_node_policy_retrieve.assert_called_once()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 400)

    @mock.patch('ironic.conductor.rpcapi.ConductorAPI', autospec=True)
    @mock.patch.object(proxy_utils, 'check_node_policy_and_retrieve',
                       autospec=True)
    def test_change_power_state_node_cleanwait(self, mock_node_policy_retrieve,
                                               mock_rpcapi):
        """Tests that power state requests fail when node waiting for clean."""
        fake_node = utils.FakeNode(provision_state=ir_states.CLEANWAIT)
        mock_node_policy_retrieve.return_value = fake_node
        resp = self.http_post('/redfish/v1/Systems/%s/Actions/'
                              'ComputerSystem.Reset' % FAKE_CREDS['NODE_UUID'],
                              data={'ResetType': 'ForceOff'})

        mock_node_policy_retrieve.assert_called_once()
        mock_rpcapi.change_node_power_state.assert_not_called()
        self.assertEqual(resp.status_code, 400)
