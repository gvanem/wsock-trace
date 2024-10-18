#!/usr/bin/python3
###############################################################################
#                                                                             #
# libloc - A library to determine the location of someone on the Internet     #
#                                                                             #
# Copyright (C) 2024 IPFire Development Team <info@ipfire.org>                #
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

import location
import os
import tempfile
import unittest

class Test(unittest.TestCase):
	def setUp(self):
		# Show even very large diffs
		self.maxDiff = None

	def __test(self, inputs, outputs=None):
		"""
			Takes a list of networks that are written to the database and
			compares the result with the second argument.
		"""
		if outputs is None:
			outputs = [network for network, cc, asn in inputs]

		with tempfile.NamedTemporaryFile() as f:
			w = location.Writer()

			# Add all inputs
			for network, cc, asn in inputs:
				n = w.add_network(network)

				# Add CC
				if cc:
					n.country_code = cc

				# Add ASN
				if asn:
					n.asn = asn

			# Write file
			w.write(f.name)

			# Re-open the database
			db = location.Database(f.name)

			# Check if the output matches what we expect
			self.assertCountEqual(
				outputs, ["%s" % network for network in db.networks],
			)

	def test_dudup_simple(self):
		"""
			Creates a couple of redundant networks and expects fewer being written
		"""
		self.__test(
			(
				("10.0.0.0/8", None, None),
				("10.0.0.0/16", None, None),
				("10.0.0.0/24", None, None),
			),

			# Everything should be put into the /8 subnet
			("10.0.0.0/8",),
		)

	def test_dedup_noop(self):
		"""
			Nothing should be changed here
		"""
		networks = (
			("10.0.0.0/8", None, None),
			("20.0.0.0/8", None, None),
			("30.0.0.0/8", None, None),
			("40.0.0.0/8", None, None),
			("50.0.0.0/8", None, None),
			("60.0.0.0/8", None, None),
			("70.0.0.0/8", None, None),
			("80.0.0.0/8", None, None),
			("90.0.0.0/8", None, None),
		)

		# The input should match the output
		self.__test(networks)

	def test_dedup_with_properties(self):
		"""
			A more complicated deduplication test where properties have been set
		"""
		# Nothing should change here because of different countries
		self.__test(
			(
				("10.0.0.0/8",  "DE", None),
				("10.0.0.0/16", "AT", None),
				("10.0.0.0/24", "DE", None),
			),
		)

		# Nothing should change here because of different ASNs
		self.__test(
			(
				("10.0.0.0/8",  None, 1000),
				("10.0.0.0/16", None, 2000),
				("10.0.0.0/24", None, 1000),
			),
		)

		# Everything can be merged again
		self.__test(
			(
				("10.0.0.0/8",  "DE", 1000),
				("10.0.0.0/16", "DE", 1000),
				("10.0.0.0/24", "DE", 1000),
			),
			("10.0.0.0/8",),
		)

	def test_merge(self):
		"""
			Checks whether the merging algorithm works
		"""
		self.__test(
			(
				("10.0.0.0/9",   None, None),
				("10.128.0.0/9", None, None),
			),
			("10.0.0.0/8",),
		)

	def test_bug13236(self):
		self.__test(
			(
				("209.38.0.0/16",   "US", None),
				("209.38.1.0/24",   "US", 14061),
				("209.38.160.0/22", "US", 14061),
				("209.38.164.0/22", "US", 14061),
				("209.38.168.0/22", "US", 14061),
				("209.38.172.0/22", "US", 14061),
				("209.38.176.0/20", "US", 14061),
				("209.38.192.0/19", "US", 14061),
				("209.38.224.0/19", "US", 14061),
			),
			(
				"209.38.0.0/16",
				"209.38.1.0/24",
				"209.38.160.0/19",
				"209.38.192.0/18",
			),
		)


if __name__ == "__main__":
	unittest.main()
