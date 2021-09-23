import pecan
from http import client as http_client

from ironic import api
from ironic.api import method
from ironic.api.controllers.redfish import v1

class Controller(object):
    _service_root = {
        "v1": "/redfish/v1/"
    }

    v1 = v1.Controller()

    @method.expose()
    def index(self):
        if api.request.method != "GET":
            pecan.abort(http_client.METHOD_NOT_ALLOWED)
        return self._service_root
