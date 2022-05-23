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

import ironic.common.exception as ir_exceptions
from ironic.conf import CONF
from ironic.tests.unit.redfish_proxy import base
from ironic.tests.unit.redfish_proxy import utils


class RedfishProxySystemsTests(base.RedfishProxyTestCase):
    """Tests asserting that systems-related functions work as intended."""
    def setUp(self):
        super(RedfishProxySystemsTests, self).setUp(defer_client_init=True)

    def _set_cfg_opts(self):
        """Set authentication strategy to "noauth" for these tests."""
        super(RedfishProxySystemsTests, self)._set_cfg_opts()
        CONF.set_override('auth_strategy', 'noauth')

    def mock_policy_helper(self, mock, orig_func, should_fail=False,
                           fail_with=None, fake_node=None):
        if orig_func == 'check_list_policy':
            if should_fail:
                mock.side_effect = ir_exceptions.HTTPForbidden()
            else:
                mock.return_value = utils.FAKE_CREDS['NODE_OWNER']
        elif orig_func == 'check_node_policy_and_retrieve':
            if should_fail:
                if fail_with == 403:
                    mock.side_effect = ir_exceptions.HTTPForbidden()
                elif fail_with == 404:
                    mock.side_effect = ir_exceptions.NodeNotFound()
                else:
                    mock.side_effect = ir_exceptions.NodeNotFound()
            else:
                if fake_node:
                    mock.return_value = fake_node
                else:
                    mock.return_value = utils.FakeNode()
         
    @mock.patch('ironic.redfish_proxy.utils.check_list_policy')
    def test_get_systems(self, mock_list_policy):
        self.mock_policy_helper(mock_list_policy, 'check_list_policy')
        pass
