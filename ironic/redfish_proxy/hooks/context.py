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

import re

from flask import current_app
from flask import g
from flask import request

from ironic.api.hooks import policy_deprecation_check
from ironic.common import context

INBOUND_HEADER = 'X-Openstack-Request-Id'
GLOBAL_REQ_ID = 'openstack.global_request_id'
ID_FORMAT = (r'^req-[a-f0-9]{8}-[a-f0-9]{4}-'
             r'[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')


def _prepare_context():
    is_public_api = request.environ.get('is_public_api', False)

    # set the global_request_id if we have an inbound request id
    gr_id = request.headers.get(INBOUND_HEADER, "")
    if re.match(ID_FORMAT, gr_id):
        request.environ[GLOBAL_REQ_ID] = gr_id

    ctx = context.RequestContext.from_environ(request.environ,
                                              is_public_api=is_public_api)

    # Do not pass any token with context for noauth or http_basic mode
    if current_app.config['auth_strategy'] != 'keystone':
        ctx.auth_token = None

    policy_deprecation_check()

    g.context = ctx


def _verify_context(resp):
    if g.context == {}:
        # An incorrect url path will not create RequestContext
        return resp
    # NOTE(lintan): RequestContext will generate a request_id if no one
    # passing outside, so it always contain a request_id.
    resp.headers['Openstack-Request-Id'] = g.context.request_id
    return resp


def register():
    current_app.before_request(_prepare_context)
    current_app.after_request(_verify_context)
