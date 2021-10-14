import pecan

import ironic.conf
from ironic import api
from ironic.api import method

CONF = ironic.conf.CONF

class SessionsController(object):
    @method.expose()
    def index(self):
        return "it's a session"
