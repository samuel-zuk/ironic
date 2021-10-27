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

from oslo_config import cfg

from ironic.common.i18n import _


opts = [
    cfg.BoolOpt('enabled',
                default=False,
                help=_('Enable the proxying of Redfish-style requests to the '
                       'Ironic system.')),
    cfg.HostAddressOpt('host_ip',
                       default='0.0.0.0',
                       help=_('The IP address or hostname on which the Ironic '
                              'Redfish proxy listens.')),
    cfg.PortOpt('port',
                default=1312,
                help=_('The TCP port on which the Ironic Redfish proxy '
                       'listens.')),
    cfg.IntOpt('api_workers',
               help=_('Number of workers for OpenStack Ironic Redfish proxy '
                      'service. The default is equal to the number of CPUs '
                      'available, but not more than 4. One worker is used if '
                      'the CPU number cannot be detected.')),
    cfg.BoolOpt('enable_ssl_api',
                default=False,
                help=_("Enable the Ironic Redfish proxy API to service "
                       "requests via HTTPS instead of HTTP. If there is a "
                       "front-end service performing HTTPS offloading from "
                       "the service, this option should be False; note, you "
                       "will want to enable proxy headers parsing with "
                       "[oslo_middleware]enable_proxy_headers_parsing "
                       "option or configure [api]public_endpoint option "
                       "to set URLs in responses to the SSL terminated one.")),
]


def register_opts(conf):
    conf.register_opts(opts, group='redfish_proxy')
