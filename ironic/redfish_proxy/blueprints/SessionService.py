import json

from flask import Blueprint, current_app, request, abort, jsonify
from keystoneauth1.identity.v3 import application_credential
from keystoneauth1 import session, access

from ironic.redfish_proxy.decorators.auth import is_public_api


SessionService = Blueprint('SessionService', __name__)

@SessionService.get('/redfish/v1/SessionService')
def session_service_info():
    return jsonify({
        '@odata.type': '#SessionService.v1_0_0.SessionService',
        'Id': 'KeystoneAuthProxy',
        'Name': 'Redfish Proxy for Keystone Authentication',
        'Status': {
            'State': 'Enabled',
            'Health': 'OK'
        },
        'ServiceEnabled': True,
        'SessionTimeout': 86400,
        'Sessions': {
            '@odata.id': '/redfish/v1/SessionService/Sessions'
        },
        '@odata.id': '/redfish/v1/SessionService'
    })

@SessionService.post('/redfish/v1/SessionService/Sessions')
@is_public_api
def session_auth():
    body = {}
    auth_url = current_app.config['keystone_uri']

    if request.content_type == 'application/json':
        body = request.to_json()
    else:
        try:
            body = json.loads(
                list(request.form.to_dict().keys())[0])
        except json.JSONDecodeError:
            abort(400)

    for field in ('UserName', 'Password'):
        if field not in body.keys():
            abort(400)

    auth = application_credential.ApplicationCredential(
        auth_url=auth_url,
        application_credential_id=body['UserName'],
        application_credential_secret=body['Password']
    )
    sess = session.Session(auth=auth)
    token = sess.get_token()
    token_info = json.loads(sess.get(auth_url + '/auth/tokens',
                                     headers={'X-Subject-Token': token}).text)
    token_id = token_info['token']['audit_ids'][0]

    return (
        jsonify({
            '@odata.type': '#Session.1.0.0.Session',
            '@odata.id': ('/redfish/v1/SessionService/Sessions/%s' % token_id),
            'Id': token_id,
            'Name': ('User Session %s' % token_id),
            'UserName': body['UserName']
        }),
        {
            'Location': ('/redfish/v1/SessionService/Sessions/%s' % token_id),
            'X-Auth-Token': token
        })
