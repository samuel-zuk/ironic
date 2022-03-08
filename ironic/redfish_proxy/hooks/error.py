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

from flask import current_app
from flask import make_response
from werkzeug.exceptions import HTTPException

from ironic.common import exception as ironic_exception


def register():
    """Register the error handlers on the Flask application."""
    current_app.register_error_handler(HTTPException, http_generic)
    current_app.register_error_handler(ironic_exception.SessionNotFound,
                                       session_not_found)
    current_app.register_error_handler(ironic_exception.MissingCredential,
                                       missing_credential)


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
    body = json.dumps({
        'error': {
            'code': 404,
            'title': 'Not Found',
            'message': str(e)
        }
    })

    headers = {'Content-Type': 'application/json'}

    return make_response(body, 404, headers)


def missing_credential(e):
    """Return a detailed error when a user submits incomplete login creds."""
    body = json.dumps({
        'error': {
            'code': 400,
            'title': 'Bad Request',
            'message': str(e)
        }
    })

    headers = {'Content-Type': 'application/json'}

    return make_response(body, 400, headers)
