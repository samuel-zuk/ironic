import pecan
from webob import exc
from http import client as http_client

import ironic.conf
from ironic import api
from ironic.api import method
from ironic.api.controllers.redfish.v1 import SessionService
from ironic.api.controllers.redfish.v1 import Systems

CONF = ironic.conf.CONF

def v1():
    v1 = {
        "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
        "Id": "IronicProxy",
        "Name": "Ironic Redfish Proxy",
        "RedfishVersion": "1.0.0",
        "Links": {},
        "Systems": {
            "@odata.id": "/redfish/v1/Systems"
        },
        "SessionService": {
            "@odata.id": "/redfish/v1/SessionService"
        },
        "@odata.id": "/redfish/v1/"
    }

    if CONF.auth_strategy == "keystone":
        v1["Links"] = {
            "Sessions": {
                "@odata.id": "/redfish/v1/SessionService/Sessions"
            }
        }

    return v1


class Controller(object):
    _subcontroller_map = {
        "SessionService": SessionService.SessionsController(),
        "Systems": Systems.SystemsController()
    }

    @method.expose()
    def index(self):
        if api.request.method != "GET":
            pecan.abort(http_client.METHOD_NOT_ALLOWED)

        return v1()
