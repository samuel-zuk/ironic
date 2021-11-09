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

from ironic.common import exception
from ironic.common import policy


def check_list_policy(context, object_type, owner=None):
    # NOTE(s_zuk): Framework-agnostic rewrite of check_list_policy() from
    #              ironic/api/controllers/v1/utils.py:1589
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
