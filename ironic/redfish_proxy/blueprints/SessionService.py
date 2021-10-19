from flask import Blueprint


SessionService = Blueprint('SessionService', __name__)


@SessionService.get('/redfish/v1/SessionService')
def response():
    return 'it\'s a session.'
