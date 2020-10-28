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

import io
import ipaddress
import logging
import os
import socket

import _location

# Initialise logging
log = logging.getLogger("location.export")
log.propagate = 1

flags = {
	_location.NETWORK_FLAG_ANONYMOUS_PROXY    : "A1",
	_location.NETWORK_FLAG_SATELLITE_PROVIDER : "A2",
	_location.NETWORK_FLAG_ANYCAST            : "A3",
}

class OutputWriter(object):
	suffix = "networks"
	mode = "w"

	def __init__(self, db, f, prefix=None, flatten=True):
		self.db, self.f, self.prefix, self.flatten = db, f, prefix, flatten

		# The previously written network
		self._last_network = None

		# Immediately write the header
		self._write_header()

	@classmethod
	def open(cls, db, filename, **kwargs):
		"""
			Convenience function to open a file
		"""
		f = open(filename, cls.mode)

		return cls(db, f, **kwargs)

	def __repr__(self):
		return "<%s f=%s>" % (self.__class__.__name__, self.f)

	def _flatten(self, network):
		"""
			Checks if the given network needs to be written to file,
			or if it is a subnet of the previously written network.
		"""
		if self._last_network and network.is_subnet_of(self._last_network):
			return True

		# Remember this network for the next call
		self._last_network = network
		return False

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

	def _write_network(self, network):
		self.f.write("%s\n" % network)

	def write(self, network, subnets):
		if self.flatten and self._flatten(network):
			log.debug("Skipping writing network %s (last one was %s)" % (network, self._last_network))
			return

		# Convert network into a Python object
		_network = ipaddress.ip_network("%s" % network)

		# Write the network when it has no subnets
		if not subnets:
			log.debug("Writing %s to %s" % (_network, self.f))
			return self._write_network(_network)

		# Convert subnets into Python objects
		_subnets = [ipaddress.ip_network("%s" % subnet) for subnet in subnets]

		# Split the network into smaller bits so that
		# we can accomodate for any gaps in it later
		to_check = set()
		for _subnet in _subnets:
			to_check.update(
				_network.address_exclude(_subnet)
			)

		# Clear the list of all subnets
		subnets = []

		# Check if all subnets to not overlap with anything else
		while to_check:
			subnet_to_check = to_check.pop()

			for _subnet in _subnets:
				# Drop this subnet if it equals one of the subnets
				# or if it is subnet of one of them
				if subnet_to_check == _subnet or subnet_to_check.subnet_of(_subnet):
					break

				# Break it down if it overlaps
				if subnet_to_check.overlaps(_subnet):
					to_check.update(
						subnet_to_check.address_exclude(_subnet)
					)
					break

			# Add the subnet again as it passed the check
			else:
				subnets.append(subnet_to_check)

		# Write all networks as compact as possible
		for network in ipaddress.collapse_addresses(subnets):
			log.debug("Writing %s to %s" % (network, self.f))
			self._write_network(network)

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
		self.f.write("create %s hash:net family inet hashsize 1024 maxelem 65536\n" % self.prefix)

	def _write_network(self, network):
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

	def _write_network(self, network):
		self.f.write("	%s,\n" % network)


class XTGeoIPOutputWriter(OutputWriter):
	"""
		Formats the output in that way, that it can be loaded by
		the xt_geoip kernel module from xtables-addons.
	"""
	suffix = "iv"
	mode = "wb"

	def _write_network(self, network):
		for address in (network.network_address, network.broadcast_address):
			# Convert this into a string of bits
			bytes = socket.inet_pton(
				socket.AF_INET6 if network.version == 6 else socket.AF_INET, "%s" % address,
			)

			self.f.write(bytes)


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

				writers[country_code] = self.writer.open(self.db, filename, prefix="CC_%s" % country_code)

			# Create writers for ASNs
			for asn in asns:
				filename = self._make_filename(
					directory, "AS%s" % asn, suffix=self.writer.suffix, family=family,
				)

				writers[asn] = self.writer.open(self.db, filename, prefix="AS%s" % asn)

			# Get all networks that match the family
			networks = self.db.search_networks(family=family)

			# Create a stack with all networks in order where we can put items back
			# again and retrieve them in the next iteration.
			networks = BufferedStack(networks)

			# Walk through all networks
			for network in networks:
				# Collect all networks which are a subnet of network
				subnets = []
				for subnet in networks:
					# If the next subnet was not a subnet, we have to push
					# it back on the stack and break this loop
					if not subnet.is_subnet_of(network):
						networks.push(subnet)
						break

					subnets.append(subnet)

				# Write matching countries
				if network.country_code and network.country_code in writers:
					# Mismatching subnets
					gaps = [
						subnet for subnet in subnets if not network.country_code == subnet.country_code
					]

					writers[network.country_code].write(network, gaps)

				# Write matching ASNs
				if network.asn and network.asn in writers:
					# Mismatching subnets
					gaps = [
						subnet for subnet in subnets if not network.asn == subnet.asn
					]

					writers[network.asn].write(network, gaps)

				# Handle flags
				for flag in flags:
					if network.has_flag(flag):
						# Fetch the "fake" country code
						country = flags[flag]

						if not country in writers:
							continue

						gaps = [
							subnet for subnet in subnets
								if not subnet.has_flag(flag)
						]

						writers[country].write(network, gaps)

				# Push all subnets back onto the stack
				for subnet in reversed(subnets):
					networks.push(subnet)

			# Write everything to the filesystem
			for writer in writers.values():
				writer.finish()

	def _make_filename(self, directory, prefix, suffix, family):
		filename = "%s.%s%s" % (
			prefix, suffix, "6" if family == socket.AF_INET6 else "4"
		)

		return os.path.join(directory, filename)


class BufferedStack(object):
	"""
		This class takes an iterator and when being iterated
		over it returns objects from that iterator for as long
		as there are any.

		It additionally has a function to put an item back on
		the back so that it will be returned again at the next
		iteration.
	"""
	def __init__(self, iterator):
		self.iterator = iterator
		self.stack = []

	def __iter__(self):
		return self

	def __next__(self):
		if self.stack:
			return self.stack.pop(0)

		return next(self.iterator)

	def push(self, elem):
		"""
			Takes an element and puts it on the stack
		"""
		self.stack.insert(0, elem)
