import pecan
from webob import exc

from ironic.api import method
from ironic.api.controllers import link

def v1():
    v1 = {
        'id': 'v1',
        'links': [
            link.make_link('self', api.request.public_url,
                           'v1', '', bookmark=True)
        ],
        
    {
