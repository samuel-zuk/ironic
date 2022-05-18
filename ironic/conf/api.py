# Copyright 2016 Intel Corporation
# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_config import types as cfg_types

from ironic.common.i18n import _


class Octal(cfg_types.Integer):

    def __call__(self, value):
        if isinstance(value, int):
            return value
        else:
            return int(str(value), 8)


opts = [
    cfg.HostAddressOpt('host_ip',
                       default='0.0.0.0',
                       help=_('The IP address or hostname on which ironic-api '
                              'listens.')),
    cfg.PortOpt('port',
                default=6385,
                help=_('The TCP port on which ironic-api listens.')),
    cfg.StrOpt('unix_socket',
               help=_('Unix socket to listen on. Disables host_ip and port.')),
    cfg.Opt('unix_socket_mode', type=Octal(),
            help=_('File mode (an octal number) of the unix socket to '
                   'listen on. Ignored if unix_socket is not set.')),
    cfg.IntOpt('max_limit',
               default=1000,
               mutable=True,
               help=_('The maximum number of items returned in a single '
                      'response from a collection resource.')),
    cfg.StrOpt('public_endpoint',
               mutable=True,
               help=_("Public URL to use when building the links to the API "
                      "resources (for example, \"https://ironic.rocks:6384\")."
                      " If None the links will be built using the request's "
                      "host URL. If the API is operating behind a proxy, you "
                      "will want to change this to represent the proxy's URL. "
                      "Defaults to None. "
                      "Ignored when proxy headers parsing is enabled via "
                      "[oslo_middleware]enable_proxy_headers_parsing option.")
               ),
    cfg.IntOpt('api_workers',
               help=_('Number of workers for OpenStack Ironic API service. '
                      'The default is equal to the number of CPUs available, '
                      'but not more than 4. One worker is used if the CPU '
                      'number cannot be detected.')),
    cfg.BoolOpt('enable_ssl_api',
                default=False,
                help=_("Enable the integrated stand-alone API to service "
                       "requests via HTTPS instead of HTTP. If there is a "
                       "front-end service performing HTTPS offloading from "
                       "the service, this option should be False; note, you "
                       "will want to enable proxy headers parsing with "
                       "[oslo_middleware]enable_proxy_headers_parsing "
                       "option or configure [api]public_endpoint option "
                       "to set URLs in responses to the SSL terminated one.")),
    cfg.BoolOpt('restrict_lookup',
                default=True,
                mutable=True,
                help=_('Whether to restrict the lookup API to only nodes '
                       'in certain states.')),
    cfg.IntOpt('ramdisk_heartbeat_timeout',
               default=300,
               mutable=True,
               help=_('Maximum interval (in seconds) for agent heartbeats.')),
    cfg.StrOpt(
        'network_data_schema',
        default='$pybasedir/api/controllers/v1/network-data-schema.json',
        help=_("Schema for network data used by this deployment.")),
]

opt_group = cfg.OptGroup(name='api',
                         title='Options for the ironic-api service')


def register_opts(conf):
    conf.register_group(opt_group)
    conf.register_opts(opts, group=opt_group)
