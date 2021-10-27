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

import sys

from oslo_config import cfg
from oslo_log import log
try:
    from oslo_reports import guru_meditation_report as gmr
    from oslo_reports import opts as gmr_opts
except ImportError:
    gmr = None

from ironic.common import profiler
from ironic.common import service as ironic_service
from ironic.common import wsgi_service
from ironic.redfish_proxy import app
from ironic import version

CONF = cfg.CONF

LOG = log.getLogger(__name__)


def main():
    ironic_service.prepare_service(sys.argv)

    if not CONF.redfish_proxy.enabled:
        raise RuntimeError('The Ironic Redfish proxy service is currently '
                           'disabled and must be enabled in ironic.conf.')

    if gmr is not None:
        gmr_opts.set_defaults(CONF)
        gmr.TextGuruMeditation.setup_autorun(version)
    else:
        LOG.debug('Guru meditation reporting is disabled '
                  'because oslo.reports is not installed')

    profiler.setup('ironic_redfish_proxy', CONF.host)

    launcher = ironic_service.process_launcher()
    server = wsgi_service.WSGIService('ironic_redfish_proxy',
                                      app.RedfishProxyApplication(),
                                      'redfish_proxy')
    launcher.launch_service(server, workers=server.workers)
    launcher.wait()


if __name__ == '__main__':
    sys.exit(main())
