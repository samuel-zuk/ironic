from ironic.conductor import rpcapi

from flask import current_app
from flask import g

def _attach_rpcapi():
    g.rpcapi = rpcapi.ConductorAPI() 

def register():
    current_app.before_request(_attach_rpcapi)
