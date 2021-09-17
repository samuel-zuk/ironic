import pecan
from http import client as http_client

from ironic import api
from ironic.api import method

class Controller(pecan.rest.RestController):
    _service_root = {
        "v1": "/redfish/v1/"
    }

    @method.expose()
    def index(self, *remainder):
        if api.request.method != "GET":
            pecan.abort(http_client.METHOD_NOT_ALLOWED)
        return self._service_root
