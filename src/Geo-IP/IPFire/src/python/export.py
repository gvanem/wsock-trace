#!/usr/bin/python3
###############################################################################
#                                                                             #
# libloc - A library to determine the location of someone on the Internet     #
#                                                                             #
# Copyright (C) 2020-2021 IPFire Development Team <info@ipfire.org>           #
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

import io
import ipaddress
import logging
import os
import socket

import _location

# Initialise logging
log = logging.getLogger("location.export")
log.propagate = 1

FLAGS = {
	_location.NETWORK_FLAG_ANONYMOUS_PROXY    : "A1",
	_location.NETWORK_FLAG_SATELLITE_PROVIDER : "A2",
	_location.NETWORK_FLAG_ANYCAST            : "A3",
	_location.NETWORK_FLAG_DROP               : "XD",
}

class OutputWriter(object):
	suffix = "networks"
	mode = "w"

	def __init__(self, f, prefix=None):
		self.f, self.prefix = f, prefix

		# Immediately write the header
		self._write_header()

	@classmethod
	def open(cls, filename, **kwargs):
		"""
			Convenience function to open a file
		"""
		f = open(filename, cls.mode)

		return cls(f, **kwargs)

	def __repr__(self):
		return "<%s f=%s>" % (self.__class__.__name__, self.f)

	def _write_header(self):
		"""
			The header of the file
		"""
		pass

	def _write_footer(self):
		"""
			The footer of the file
		"""
		pass

	def write(self, network):
		self.f.write("%s\n" % network)

	def finish(self):
		"""
			Called when all data has been written
		"""
		self._write_footer()

		# Close the file
		self.f.close()


class IpsetOutputWriter(OutputWriter):
	"""
		For ipset
	"""
	suffix = "ipset"

	def _write_header(self):
		self.f.write("create %s hash:net family inet hashsize 1024 maxelem 65536 -exist\n" % self.prefix)
		self.f.write("flush %s\n" % self.prefix)

	def write(self, network):
		self.f.write("add %s %s\n" % (self.prefix, network))


class NftablesOutputWriter(OutputWriter):
	"""
		For nftables
	"""
	suffix = "set"

	def _write_header(self):
		self.f.write("define %s = {\n" % self.prefix)

	def _write_footer(self):
		self.f.write("}\n")

	def write(self, network):
		self.f.write("	%s,\n" % network)


class XTGeoIPOutputWriter(OutputWriter):
	"""
		Formats the output in that way, that it can be loaded by
		the xt_geoip kernel module from xtables-addons.
	"""
	suffix = "iv"
	mode = "wb"

	def write(self, network):
		self.f.write(network._first_address)
		self.f.write(network._last_address)


formats = {
	"ipset"    : IpsetOutputWriter,
	"list"     : OutputWriter,
	"nftables" : NftablesOutputWriter,
	"xt_geoip" : XTGeoIPOutputWriter,
}

class Exporter(object):
	def __init__(self, db, writer):
		self.db, self.writer = db, writer

	def export(self, directory, families, countries, asns):
		for family in families:
			log.debug("Exporting family %s" % family)

			writers = {}

			# Create writers for countries
			for country_code in countries:
				filename = self._make_filename(
					directory, prefix=country_code, suffix=self.writer.suffix, family=family,
				)

				writers[country_code] = self.writer.open(filename, prefix="CC_%s" % country_code)

			# Create writers for ASNs
			for asn in asns:
				filename = self._make_filename(
					directory, "AS%s" % asn, suffix=self.writer.suffix, family=family,
				)

				writers[asn] = self.writer.open(filename, prefix="AS%s" % asn)

			# Filter countries from special country codes
			country_codes = [
				country_code for country_code in countries if not country_code in FLAGS.values()
			]

			# Get all networks that match the family
			networks = self.db.search_networks(family=family,
				country_codes=country_codes, asns=asns, flatten=True)

			# Walk through all networks
			for network in networks:
				# Write matching countries
				try:
					writers[network.country_code].write(network)
				except KeyError:
					pass

				# Write matching ASNs
				try:
					writers[network.asn].write(network)
				except KeyError:
					pass

				# Handle flags
				for flag in FLAGS:
					if network.has_flag(flag):
						# Fetch the "fake" country code
						country = FLAGS[flag]

						try:
							writers[country].write(network)
						except KeyError:
							pass

			# Write everything to the filesystem
			for writer in writers.values():
				writer.finish()

	def _make_filename(self, directory, prefix, suffix, family):
		filename = "%s.%s%s" % (
			prefix, suffix, "6" if family == socket.AF_INET6 else "4"
		)

		return os.path.join(directory, filename)
