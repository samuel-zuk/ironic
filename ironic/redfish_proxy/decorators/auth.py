# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from functools import wraps

from flask import current_app
from flask import request


def is_public_api(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if current_app.config['auth_strategy'] in ['keystone', 'basic_auth']:
            request.environ.update({'is_public_api': True})

        return func(*args, **kwargs)
    return decorated
