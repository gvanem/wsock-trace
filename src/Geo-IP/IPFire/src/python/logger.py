#!/usr/bin/python3
###############################################################################
#                                                                             #
# libloc - A library to determine the location of someone on the Internet     #
#                                                                             #
# Copyright (C) 2020 IPFire Development Team <info@ipfire.org>                #
#                                                                             #
# This library is free software; you can redistribute it and/or               #
# modify it under the terms of the GNU Lesser General Public                  #
# License as published by the Free Software Foundation; either                #
# version 2.1 of the License, or (at your option) any later version.          #
#                                                                             #
# This library is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU           #
# Lesser General Public License for more details.                             #
#                                                                             #
###############################################################################

import sys
import logging
import logging.handlers

# Initialise root logger
log = logging.getLogger("location")
log.setLevel(logging.INFO)

# Log to console
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
log.addHandler(handler)

# Log to 'stdout' on Windows and to syslog otherwise
if sys.platform == "win32":
  handler = logging.StreamHandler(sys.stdout)
else:
  handler = logging.handlers.SysLogHandler(address="/dev/log",
                facility=logging.handlers.SysLogHandler.LOG_DAEMON)

handler.setLevel(logging.INFO)
log.addHandler(handler)

# Format syslog messages
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)

def set_level(level):
	"""
		Sets the log level for the root logger
	"""
	log.setLevel(level)
