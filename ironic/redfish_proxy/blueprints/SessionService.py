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
from flask import current_app
from flask import jsonify
from flask import make_response
from flask import request
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneauth1 import token_endpoint

from ironic.common import exception


SessionService = Blueprint('SessionService', __name__)


@SessionService.get('/redfish/v1/SessionService')
def session_service_info():
    """Return details about the emulated Redfish SessionService."""
    return jsonify({
        '@odata.type': '#SessionService.v1_0_0.SessionService',
        'Id': 'KeystoneAuthProxy',
        'Name': 'Redfish Proxy for Keystone Authentication',
        'Status': {
            'State': 'Enabled',
            'Health': 'OK'
        },
        'ServiceEnabled': True,
        'SessionTimeout': 3600,
        'Sessions': {
            '@odata.id': '/redfish/v1/SessionService/Sessions'
        },
        '@odata.id': '/redfish/v1/SessionService'
    })


@SessionService.get('/redfish/v1/SessionService/Sessions')
def session_collection_info():
    """Return a Redfish SessionCollection containing the active Session.

    Will use the currently active X-Auth-Token to determine the corresponding
    Session's URI, returning this as the sole Collection member. The identifier
    to be used shall be the Keystone token's audit ID.
    """
    auth_url = current_app.config['keystone_authtoken']['auth_url']
    auth_token = request.headers['X-Auth-Token']

    # Query the identity service to get the token's audit ID.
    auth = token_endpoint.Token(endpoint=auth_url, token=auth_token)
    sess = session.Session(auth=auth)
    token_info = sess.get(auth_url + '/auth/tokens',
                          headers={'X-Subject-Token': auth_token}).json()
    token_id = token_info['token']['audit_ids'][0]

    return jsonify({
        '@odata.type': '#SessionCollection.SessionCollection',
        'Name': 'Redfish Proxy Session Collection',
        'Members@odata.count': 1,
        'Members': [
            {'@odata.id': '/redfish/v1/SessionService/Sessions/%s' % token_id}
        ],
        '@odata.id': '/redfish/v1/SessionService/Sessions'
    })


@SessionService.post('/redfish/v1/SessionService/Sessions')
def session_auth():
    """Attempt to create a new Session from a Keystone application credential.

    Handles POST requests and expects a body containing a UserName key with
    the value of the app cred's UUID, and a Password key with the value of the
    app cred's secret. Will return basic info about the newly created Session
    in the response body and the token itself in the X-Auth-Token response
    header field.
    """
    body = {}
    auth_url = current_app.config['keystone_authtoken']['auth_url']

    # Check if the POST request body is json; if not, attempt to jsonify it.
    if request.is_json:
        body = request.get_json()
    else:
        try:
            body = json.loads(
                list(request.form.to_dict().keys())[0])
        except json.JSONDecodeError:
            abort(400)

    # Ensure that both required fields are present.
    for field in ('UserName', 'Password'):
        if field not in body.keys():
            raise exception.MissingCredential(field_name=field)

    # Use the provided credentials to attempt to fetch a new token.
    auth = v3.application_credential.ApplicationCredential(
        auth_url=auth_url,
        application_credential_id=body['UserName'],
        application_credential_secret=body['Password']
    )
    sess = session.Session(auth=auth)
    auth_token = sess.get_token()

    # Query the Identity service to get the audit ID of the new token.
    token_info = sess.get(auth_url + '/auth/tokens',
                          headers={'X-Subject-Token': auth_token}).json()
    token_id = token_info['token']['audit_ids'][0]

    # Note: Flask response syntax here = (response, status, headers)
    return (
        jsonify({
            '@odata.type': '#Session.1.0.0.Session',
            '@odata.id': '/redfish/v1/SessionService/Sessions/%s' % token_id,
            'Id': token_id,
            'Name': 'User Session %s' % token_id,
            'UserName': body['UserName']
        }),
        201,
        {
            'Location': '/redfish/v1/SessionService/Sessions/%s' % token_id,
            'X-Auth-Token': auth_token
        }
    )


@SessionService.get('/redfish/v1/SessionService/Sessions/<sess_id>')
def session_info(sess_id):
    """Returns information about the currently active Session.

    Currently, this will only return information if the session ID being
    queried matches that of the token used for authentication, which is
    required.
    """
    auth_url = current_app.config['keystone_authtoken']['auth_url']
    auth_token = request.headers['X-Auth-Token']

    # Query the identity service to get the token's audit ID, check to make
    # sure that it matches with the session id in the URL.
    auth = token_endpoint.Token(endpoint=auth_url, token=auth_token)
    sess = session.Session(auth=auth)
    token_info = sess.get(auth_url + '/auth/tokens',
                          headers={'X-Subject-Token': auth_token}).json()

    token_id = token_info['token']['audit_ids'][0]
    app_cred_id = token_info['token']['application_credential']['id']

    if token_id != sess_id:
        raise exception.SessionNotFound(sess_id=sess_id)

    return jsonify({
        '@odata.id': '/redfish/v1/SessionService/Sessions/%s' % token_id,
        '@odata.type': '#Session.1.0.0.Session',
        'Id': token_id,
        'Name': 'User Session %s' % token_id,
        'UserName': app_cred_id
    })


@SessionService.delete('/redfish/v1/SessionService/Sessions/<sess_id>')
def end_session(sess_id):
    """Ends the specified Session, revoking the Keystone auth token.

    Will only succeed if the specified session ID matches that of the token
    being used for authentication, which is required. Note that this does not
    revoke the application credential; it revokes the auth token that was
    previously created using said credential.
    """
    auth_url = current_app.config['keystone_authtoken']['auth_url']
    auth_token = request.headers['X-Auth-Token']

    # Query the identity service to get the token's audit ID, check to make
    # sure that it matches with the session id in the URL.
    auth = token_endpoint.Token(endpoint=auth_url, token=auth_token)
    sess = session.Session(auth=auth)
    token_info = sess.get(auth_url + '/auth/tokens',
                          headers={'X-Subject-Token': auth_token}).json()
    token_id = token_info['token']['audit_ids'][0]

    if token_id != sess_id:
        raise exception.SessionNotFound(sess_id=sess_id)

    req = sess.delete(auth_url + '/auth/tokens',
                      headers={'X-Subject-Token': auth_token})

    # If we do not get a 2xx status code, something went wrong.
    if req.status_code // 100 != 2:
        abort(500)
    else:
        return make_response(('', 204))
