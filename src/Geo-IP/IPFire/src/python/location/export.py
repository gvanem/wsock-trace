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
import math
import os
import socket
import sys

from .i18n import _
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

	def __init__(self, name, family=None, directory=None, f=None):
		self.name = name
		self.family = family
		self.directory = directory

		# Tag
		self.tag = self._make_tag()

		# Open output file
		if f:
			self.f = f
		elif self.directory:
			self.f = open(self.filename, self.mode)
		elif "b" in self.mode:
			self.f = io.BytesIO()
		else:
			self.f = io.StringIO()

		# Call any custom initialization
		self.init()

		# Immediately write the header
		self._write_header()

	def init(self):
		"""
			To be overwritten by anything that inherits from this
		"""
		pass

	def __repr__(self):
		return "<%s %s f=%s>" % (self.__class__.__name__, self, self.f)

	def _make_tag(self):
		families = {
			socket.AF_INET6 : "6",
			socket.AF_INET  : "4",
		}

		return "%sv%s" % (self.name, families.get(self.family, "?"))

	@property
	def filename(self):
		if self.directory:
			return os.path.join(self.directory, "%s.%s" % (self.tag, self.suffix))

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

		# Flush all output
		self.f.flush()

	def print(self):
		"""
			Prints the entire output line by line
		"""
		if isinstance(self.f, io.BytesIO):
			raise TypeError(_("Won't write binary output to stdout"))

		# Go back to the beginning
		self.f.seek(0)

		# Iterate over everything line by line
		for line in self.f:
			sys.stdout.write(line)


class IpsetOutputWriter(OutputWriter):
	"""
		For ipset
	"""
	suffix = "ipset"

	# The value is being used if we don't know any better
	DEFAULT_HASHSIZE = 64

	# We aim for this many networks in a bucket on average. This allows us to choose
	# how much memory we want to sacrifice to gain better performance. The lower the
	# factor, the faster a lookup will be, but it will use more memory.
	# We will aim for only using three quarters of all buckets to avoid any searches
	# through the linked lists.
	HASHSIZE_FACTOR = 0.75

	def init(self):
		# Count all networks
		self.networks = 0

		# Check that family is being set
		if not self.family:
			raise ValueError("%s requires family being set" % self.__class__.__name__)

	@property
	def hashsize(self):
		"""
			Calculates an optimized hashsize
		"""
		# Return the default value if we don't know the size of the set
		if not self.networks:
			return self.DEFAULT_HASHSIZE

		# Find the nearest power of two that is larger than the number of networks
		# divided by the hashsize factor.
		exponent = math.log(self.networks / self.HASHSIZE_FACTOR, 2)

		# Return the size of the hash (the minimum is 64)
		return max(2 ** math.ceil(exponent), 64)

	def _write_header(self):
		# This must have a fixed size, because we will write the header again in the end
		self.f.write("create %s hash:net family inet%s" % (
			self.tag,
			"6" if self.family == socket.AF_INET6 else ""
		))
		self.f.write(" hashsize %8d maxelem 1048576 -exist\n" % self.hashsize)
		self.f.write("flush %s\n" % self.tag)

	def write(self, network):
		self.f.write("add %s %s\n" % (self.tag, network))

		# Increment network counter
		self.networks += 1

	def _write_footer(self):
		# Jump back to the beginning of the file
		try:
			self.f.seek(0)

		# If the output stream isn't seekable, we won't try writing the header again
		except io.UnsupportedOperation:
			return

		# Rewrite the header with better configuration
		self._write_header()


class NftablesOutputWriter(OutputWriter):
	"""
		For nftables
	"""
	suffix = "set"

	def _write_header(self):
		self.f.write("define %s = {\n" % self.tag)

	def _write_footer(self):
		self.f.write("}\n")

	def write(self, network):
		self.f.write("	%s,\n" % network)


class XTGeoIPOutputWriter(OutputWriter):
	"""
		Formats the output in that way, that it can be loaded by
		the xt_geoip kernel module from xtables-addons.
	"""
	mode = "wb"

	@property
	def tag(self):
		return self.name

	@property
	def suffix(self):
		return "iv%s" % ("6" if self.family == socket.AF_INET6 else "4")

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
				writers[country_code] = self.writer(country_code, family=family, directory=directory)

			# Create writers for ASNs
			for asn in asns:
				writers[asn] = self.writer("AS%s" % asn, family=family, directory=directory)

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

			# Print to stdout
			if not directory:
				for writer in writers.values():
					writer.print()
