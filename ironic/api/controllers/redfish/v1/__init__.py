import pecan
from webob import exc
from http import client as http_client

from ironic import api
from ironic.api import method

class Controller(object):
    _v1 = {
        "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
        "Id": "IronicProxy",
        "Name": "Ironic Redfish Proxy",
        "RedfishVersion": "1.0.0",
        "Links": {
            "Sessions": {
                "@odata.id": "/redfish/v1/SessionService/Sessions"
            }
        },
        "Systems": {
            "@odata.id": "/redfish/v1/Systems"
        },
        "SessionService": {
            "@odata.id": "/redfish/v1/SessionService"
        },
        "@odata.id": "/redfish/v1/"
    }

    @method.expose()
    def index(self):
        if api.request.method != "GET":
            pecan.abort(http_client.METHOD_NOT_ALLOWED)
        return self._v1
