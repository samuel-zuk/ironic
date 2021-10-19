from flask import Blueprint

from ironic.redfish_proxy.decorators.auth import is_public_api


root = Blueprint('root', __name__)


@root.get('/redfish')
@is_public_api
def response():
    return { 'v1': '/redfish/v1/' }
