from oslo_config import cfg

from ironic.common.i18n import _

opts = [
    cfg.BoolOpt('enabled',
                default=False,
                mutable=True,
                help=_('Enable the proxying of Redfish-style requests to '
                       'the Ironic system.'))
]

def register_opts(conf):
    conf.register_opts(opts, group='redfish_proxy')
