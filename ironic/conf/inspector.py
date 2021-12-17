# Copyright 2016 Intel Corporation

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
from ironic.conf import auth

opts = [
    cfg.IntOpt('status_check_period', default=60,
               help=_('period (in seconds) to check status of nodes '
                      'on inspection')),
    cfg.StrOpt('extra_kernel_params', default='',
               help=_('extra kernel parameters to pass to the inspection '
                      'ramdisk when boot is managed by ironic (not '
                      'ironic-inspector). Pairs key=value separated by '
                      'spaces.')),
    cfg.BoolOpt('power_off', default=True,
                help=_('whether to power off a node after inspection '
                       'finishes. Ignored for nodes that have fast '
                       'track mode enabled.')),
    cfg.StrOpt('callback_endpoint_override',
               help=_('endpoint to use as a callback for posting back '
                      'introspection data when boot is managed by ironic. '
                      'Standard keystoneauth options are used by default.')),
    cfg.BoolOpt('require_managed_boot', default=False,
                help=_('require that the in-band inspection boot is fully '
                       'managed by ironic. Set this to True if your '
                       'installation of ironic-inspector does not have a '
                       'separate PXE boot environment.')),
]


def register_opts(conf):
    conf.register_opts(opts, group='inspector')
    auth.register_auth_opts(conf, 'inspector',
                            service_type='baremetal-introspection')


def list_opts():
    return auth.add_auth_opts(opts, service_type='baremetal-introspection')
