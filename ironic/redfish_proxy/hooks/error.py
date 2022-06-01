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

from http.client import responses as http_responses
import json

from flask import current_app
from flask import make_response
import keystoneauth1.exceptions as ks_exception
from oslo_policy.policy import InvalidScope
from werkzeug.exceptions import HTTPException

from ironic.common import exception as ir_exception


def register():
    """Register the error handlers on the Flask application."""
    exception_handlers = (
        (HTTPException, http_generic),
        (InvalidScope, invalid_scope),
        (ir_exception.HTTPForbidden, ironic_forbidden),
        (ir_exception.InvalidRedfishResetType, invalid_redfish_reset_type),
        (ir_exception.InvalidStateRequested, node_state_conflict),
        (ir_exception.InvalidUUID, invalid_uuid),
        (ir_exception.MissingRequestField, missing_request_field),
        (ir_exception.MissingToken, missing_token),
        (ir_exception.NodeLocked, node_locked),
        (ir_exception.NodeNotFound, node_not_found),
        (ir_exception.NoFreeConductorWorker, no_free_conductor_worker),
        (ir_exception.RequestNotJSON, request_not_json),
        (ir_exception.SessionNotFound, session_not_found),
        (ks_exception.NotFound, keystone_not_found),
        (ks_exception.Unauthorized, keystone_unauthorized),
    )

    for exc_handler in exception_handlers:
        current_app.register_error_handler(*exc_handler)


def _mk_fmt_resp(code, message, title=None):
    """Return a formatted Flask/Werkzeug response from provided details."""
    if not title:
        title = http_responses[code]
    return make_response(json.dumps({'error': {'code': code,
                                               'title': title,
                                               'message': message}}),
                         code, {'Content-Type': 'application/json'})


def http_generic(e):
    """Format Werkzeug HTTP error exceptions as JSON responses."""
    resp = e.get_response()
    resp.data = json.dumps({
        'error': {
            'code': e.code,
            'title': e.name,
            'message': e.description
        }
    })
    resp.content_type = 'application/json'
    return resp


def session_not_found(e):
    """Return a detailed error when a user accesses an invalid Session."""
    return _mk_fmt_resp(code=404, message=str(e))


def missing_request_field(e):
    """Return a detailed error when a user submits incomplete request body."""
    return _mk_fmt_resp(code=400, message=str(e))


def missing_token(e):
    """Return a detailed error when a user does not provide an auth token."""
    return _mk_fmt_resp(code=401, message=str(e))


def request_not_json(e):
    """Return a detailed error when a user's request is not in JSON form."""
    return _mk_fmt_resp(code=400, message=str(e))


def node_state_conflict(e):
    """Return a detailed error when an action conflicts with node state."""
    return _mk_fmt_resp(code=409, message=str(e))


def node_not_found(e):
    """Return a detailed error when accessing invalid Ironic nodes."""
    return _mk_fmt_resp(code=404, message=str(e))


def invalid_uuid(e):
    """Return a detailed error when provided node UUID is not a valid UUID."""
    return _mk_fmt_resp(code=400, message=str(e))


def invalid_redfish_reset_type(e):
    """Return a detailed error when provided an invalid ResetType."""
    return _mk_fmt_resp(code=400, message=str(e))


def invalid_scope(e):
    """Return a detailed error when user scope is invalid."""
    return _mk_fmt_resp(code=403, message=str(e))


def keystone_unauthorized(e):
    """Return a detailed error when provided Keystone creds are invalid."""
    # keystone unauthorized is a 401 error, here we reformat it to a 403
    # forbidden error as per spec
    return _mk_fmt_resp(code=403,
                        message='You don\'t have the permission to access '
                                'the requested resource. It is either '
                                'read-protected or not readable by the '
                                'server. (HTTP 403) (Request-ID: %s)' %
                                e.request_id)


def keystone_not_found(e):
    """Return a detailed error when accessing invalid Keystone resources."""
    return _mk_fmt_resp(code=404, message=e.message)


def ironic_forbidden(e):
    """Return a detailed error from Ironic HTTP Forbidden errors."""
    return _mk_fmt_resp(code=403, message=str(e))


def no_free_conductor_worker(e):
    """Return a detailed error from the RPCAPI when this error is raised."""
    return _mk_fmt_resp(code=503, message=str(e))


def node_locked(e):
    """Return a detailed error when a node is locked."""
    return _mk_fmt_resp(code=409, message=str(e))
