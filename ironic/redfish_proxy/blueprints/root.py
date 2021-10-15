from flask import Blueprint


root = Blueprint('root', __name__)


@root.get('/redfish')
def response():
    return { 'v1': '/redfish/v1/' }
