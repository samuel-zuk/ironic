from functools import wraps
from flask import current_app, request

def is_public_api(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if current_app.config['auth_strategy'] in ['keystone', 'basic_auth']:
            request.environ.update({'is_public_api': True})
            print("===== UPDATING REQUEST CONTEXT =====")

        return func(*args, **kwargs)
    return decorated
