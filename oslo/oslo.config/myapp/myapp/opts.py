#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "Wilson Lan"

import sys

from oslo_config import cfg
from oslo_log import log as logging
from _i18n import _, _LI, _LW, _LE, _LC


CONF = cfg.CONF

opts1 = [
    cfg.StrOpt("name", 
               default="myapp",
               deprecated_name="app_name",
               help="The application name."),
    cfg.StrOpt("version", 
               default="1.0",
               deprecated_name="app_version",
               help="The application version."),
]

opts2 = [
    cfg.StrOpt("host", 
               default="localhost",
               help="The host address."),
    cfg.IntOpt("port", 
               default=9000,
               deprecated_for_removal=True,
               help="The port number."),
]

server_group = cfg.OptGroup(name="server_group",
                            title="server group options",
                            help="server group help text")

myapp_group = cfg.OptGroup(name="myapp",
                           title="myapp group options",
                           help="myapp group help text")

CONF.register_group(server_group)
CONF.register_opts(opts1, group="DEFAULT")
CONF.register_opts(opts2, group=server_group)

LOG = logging.getLogger(__name__)
logging.register_options(CONF)
logging.setup(CONF, __name__)

def list_opts():
    return [("DEFAULT", opts1), (server_group, opts2)]

def print_opts():
    CONF(default_config_files=["/etc/myapp.conf"])

    LOG.info(_LI(CONF.DEFAULT.name))
    LOG.info(_LI(CONF.DEFAULT.version))
    LOG.info(_LI(CONF.server_group.host))
    LOG.info(_LI(CONF.server_group.port))
