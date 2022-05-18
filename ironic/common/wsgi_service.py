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

import socket

from ironic_lib import utils as il_utils
from oslo_concurrency import processutils
from oslo_service import service
from oslo_service import wsgi

from ironic.common import exception
from ironic.common.i18n import _
from ironic.conf import CONF


_MAX_DEFAULT_WORKERS = 4


class WSGIService(service.ServiceBase):
    """Provides ability to launch WSGI apps using oslo_service."""

    def __init__(self, name, app, conf_section):
        """Initialize, but do not start the WSGI server.

        :param name: The name of the WSGI server given to the loader.
        :param app: The app to be ran inside the WSGI server.
        :param conf_section: The name of the configuration section containing
            the options that specify how this server should be run.
        :returns: None
        """
        app_conf = CONF[conf_section]

        self.name = name
        self.app = app
        self.workers = (
            app_conf.api_workers
            # NOTE(dtantsur): each worker takes a substantial amount of memory,
            # so we don't want to end up with dozens of them.
            or min(processutils.get_worker_count(), _MAX_DEFAULT_WORKERS)
        )
        if self.workers and self.workers < 1:
            raise exception.ConfigInvalid(
                _("api_workers value of %d is invalid, "
                  "must be greater than 0.") % self.workers)

        if ('unix_socket' in app_conf.keys() and app_conf.unix_socket):
            il_utils.unlink_without_raise(app_conf.unix_socket)
            self.server = wsgi.Server(CONF, name, self.app,
                                      socket_family=socket.AF_UNIX,
                                      socket_file=app_conf.unix_socket,
                                      socket_mode=app_conf.unix_socket_mode,
                                      use_ssl=app_conf.enable_ssl_api)
        else:
            self.server = wsgi.Server(CONF, name, self.app,
                                      host=app_conf.host_ip,
                                      port=app_conf.port,
                                      use_ssl=app_conf.enable_ssl_api)

    def start(self):
        """Start serving this service using loaded configuration.

        :returns: None
        """
        self.server.start()

    def stop(self):
        """Stop serving this API.

        :returns: None
        """
        self.server.stop()
        if CONF.api.unix_socket:
            il_utils.unlink_without_raise(CONF.unix_socket)

    def wait(self):
        """Wait for the service to stop serving this API.

        :returns: None
        """
        self.server.wait()

    def reset(self):
        """Reset server greenpool size to default.

        :returns: None
        """
        self.server.reset()
