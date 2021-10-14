import sys

from oslo_log import log
from oslo_config import cfg
from oslo_service import service
try:
    from oslo_reports import guru_meditation_report as gmr
    from oslo_reports import opts as gmr_opts
except ImportError:
    gmr = None

from ironic.common import profiler
from ironic.common import service as ironic_service
from ironic.redfish_proxy import app

CONF = cfg.CONF

LOG = log.getLogger(__name__)


def main():
    """
    ironic_service.prepare_service(sys.argv)

    if gmr is not None:
        gmr_opts.set_defaults(CONF)
        gmr.TextGuruMeditation.setup_autorun(version)
    else:
        LOG.debug('Guru meditation reporting is disabled '
                  'because oslo.reports is not installed')

    profiler.setup('ironic_redfish_proxy', CONF.host)

    launcher = ironic_service.process_launcher()

    print("test")
    """
    for x in "healthcheck", "audit":
        print(CONF[x].enabled)


if __name__ == '__main__':
    sys.exit(main())
