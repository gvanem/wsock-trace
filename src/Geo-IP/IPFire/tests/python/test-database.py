#!/usr/bin/python3
###############################################################################
#                                                                             #
# libloc - A library to determine the location of someone on the Internet     #
#                                                                             #
# Copyright (C) 2022 IPFire Development Team <info@ipfire.org>                #
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

import errno
import location
import os
import socket
import tempfile
import unittest

TEST_DATA_DIR = os.environ["TEST_DATA_DIR"]

class Test(unittest.TestCase):
	def setUp(self):
		path = os.path.join(TEST_DATA_DIR, "database.db")

		# Load the database
		self.db = location.Database(path)

	def test_metadata(self):
		"""
			Check if any metadata matches what we expected
		"""
		# Vendor
		self.assertEqual(self.db.vendor, "IPFire Project")

		# Description
		self.assertEqual(self.db.description,
			"This database has been obtained from https://location.ipfire.org/\n\nFind the full license terms at https://creativecommons.org/licenses/by-sa/4.0/")

		# License
		self.assertEqual(self.db.license, "CC BY-SA 4.0")

		# Created At
		self.assertIsInstance(self.db.created_at, int)

	def test_fetch_network(self):
		"""
			Try fetching some results that should exist
		"""
		n = self.db.lookup("81.3.27.38")
		self.assertIsInstance(n, location.Network)

		n = self.db.lookup("1.1.1.1")
		self.assertIsInstance(n, location.Network)

		n = self.db.lookup("8.8.8.8")
		self.assertIsInstance(n, location.Network)

	def test_fetch_network_nonexistant(self):
		"""
			Try to fetch something that should not exist
		"""
		n = self.db.lookup("255.255.255.255")
		self.assertIsNone(n)

	def test_fetch_network_invalid(self):
		"""
			Feed some invalid inputs into the lookup function
		"""
		with self.assertRaises(ValueError):
			self.db.lookup("XXX")

		with self.assertRaises(ValueError):
			self.db.lookup("455.455.455.455")

	def test_verify(self):
		"""
			Verify the database
		"""
		# Path to the signature file
		path = os.path.join(TEST_DATA_DIR, "signing-key.pem")

		# Try to verify with an invalid signature
		with self.assertRaises(TypeError):
			self.db.verify(None)

		# Perform verification with the correct key
		with open(path, "r") as f:
			self.assertTrue(self.db.verify(f))

		# Perform verification with invalid keys
		with open("/dev/null", "r") as f:
			self.assertFalse(self.db.verify(f))

		with open("/dev/urandom", "r") as f:
			self.assertFalse(self.db.verify(f))

	def test_search_as(self):
		"""
			Try to fetch an AS
		"""
		# Fetch an existing AS
		self.assertIsInstance(self.db.get_as(204867), location.AS)

		# Fetch a non-existing AS
		self.assertIsNone(self.db.get_as(0))

		# Fetch an AS with a number that is out of range
		with self.assertRaises(OverflowError):
			self.db.get_as(2**32 + 1)

		with self.assertRaises(OverflowError):
			self.db.get_as(-1)

		# A large AS number is just not in the database
		self.assertIsNone(self.db.get_as(2**32 - 1))

	def test_get_country(self):
		"""
			Try fetching a country
		"""
		# Fetch an existing country
		self.assertIsInstance(self.db.get_country("DE"), location.Country)

		# Fetch a non-existing country
		self.assertIsNone(self.db.get_country("AA"))

		# Fetch a country with an invalid country code
		with self.assertRaises(ValueError):
			self.db.get_country("XXX")

	def test_errors(self):
		"""
			Errors of the library have to become exceptions that say what went wrong
		"""
		# A file that does not exist
		with self.assertRaises(FileNotFoundError):
			location.Database("/does/not/exist")

		# A file that is not a database
		with self.assertRaises(OSError) as e:
			location.Database(__file__)

		self.assertEqual(e.exception.errno, errno.ENOMSG)

		# An empty file
		with tempfile.NamedTemporaryFile() as f:
			with self.assertRaises(OSError) as e:
				location.Database(f.name)

			self.assertEqual(e.exception.errno, errno.ENODATA)

		# Invalid input
		with self.assertRaises(ValueError):
			self.db.lookup("not an IP address")

		with self.assertRaises(ValueError):
			self.db.lookup("192.0.2.1/abc")

		with self.assertRaises(ValueError):
			location.Network("192.0.2.0/33")

		with self.assertRaises(ValueError):
			location.Country("XXX")

		# The writer must refuse what it cannot add instead of crashing
		writer = location.Writer()

		with self.assertRaises(ValueError):
			writer.add_network("not a network")

		with self.assertRaises(ValueError):
			writer.add_country("XXX")

		writer.add_network("192.0.2.0/24")

		with self.assertRaises(IndexError):
			writer.add_network("192.0.2.0/24")

		# A key that is not a key
		with open(__file__) as f:
			with self.assertRaises(ValueError):
				location.Writer(f)

			self.assertFalse(self.db.verify(f))

			# The file must still be open
			self.assertFalse(f.closed)
			f.seek(0)

	def test_reload(self):
		"""
			A database must notice when its file has been replaced
		"""
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, "database.db")

			def write(network, country_code):
				writer = location.Writer()
				writer.vendor = country_code

				n = writer.add_network(network)
				n.country_code = country_code

				# Replace the database like the updater does
				writer.write("%s.tmp" % path)
				os.rename("%s.tmp" % path, path)

			write("192.0.2.0/24", "DE")

			db = location.Database(path)
			self.assertEqual(db.lookup("192.0.2.1").country_code, "DE")

			# Nothing has changed
			self.assertFalse(db.reload())

			# Something that is being used while the database is being replaced
			networks = iter(db.networks)

			write("198.51.100.0/24", "FR")

			# We keep using what we have until we are told to look
			self.assertEqual(db.lookup("192.0.2.1").country_code, "DE")

			self.assertTrue(db.reload())

			self.assertIsNone(db.lookup("192.0.2.1"))
			self.assertEqual(db.lookup("198.51.100.1").country_code, "FR")
			self.assertEqual(db.vendor, "FR")

			# The enumerator finishes with the old database
			self.assertEqual([str(n) for n in networks], ["192.0.2.0/24"])

			# If the database is gone, we carry on with what we have
			os.unlink(path)

			with self.assertRaises(FileNotFoundError):
				db.reload()

			self.assertEqual(db.lookup("198.51.100.1").country_code, "FR")

	def test_list_bogons(self):
		"""
			Generate a list of bogons
		"""
		# Fetch all bogons
		bogons = self.db.list_bogons()

		# We should have received an enumerator full of networks
		self.assertIsInstance(bogons, location.DatabaseEnumerator)
		for bogon in bogons:
			self.assertIsInstance(bogon, location.Network)

			# Nothing in a bogon can be in a country
			for address in (bogon.first_address, bogon.last_address):
				network = self.db.lookup(address)

				if network:
					self.assertFalse(network.country_code,
						"%s is a bogon, but %s is in %s" % (bogon, network, network.country_code))

	def test_repr(self):
		self.assertEqual(repr(self.db),
			"<Database %s>" % os.path.join(TEST_DATA_DIR, "database.db"))

	def test_lookup(self):
		"""
			Looks up an address and checks what we got
		"""
		n = self.db.lookup("2001:678:b28::1")

		self.assertEqual(str(n), "2001:678:b28::/48")
		self.assertEqual(n.asn, 204867)

	def test_ases(self):
		"""
			Walks through all ASes
		"""
		ases = list(self.db.ases)

		self.assertTrue(ases)

		for a in ases:
			self.assertIsInstance(a, location.AS)

		# They are sorted and every number exists once
		numbers = [a.number for a in ases]
		self.assertEqual(numbers, sorted(set(numbers)))

		# One of them is ours
		self.assertIn(204867, numbers)

	def test_search_as_by_name(self):
		"""
			Searches for ASes by their name
		"""
		ases = list(self.db.search_as("Lightning Wire"))

		self.assertEqual([a.number for a in ases], [204867])

		# The search does not care about case
		self.assertEqual([a.number for a in self.db.search_as("lightning wire")], [204867])

		# Every result contains what we searched for
		for a in self.db.search_as("Telecom"):
			self.assertIn("telecom", a.name.lower())

		# Nothing should be called like this
		self.assertEqual(list(self.db.search_as("This AS does not exist")), [])

	def test_countries(self):
		"""
			Walks through all countries
		"""
		countries = list(self.db.countries)

		for c in countries:
			self.assertIsInstance(c, location.Country)

		codes = [c.code for c in countries]
		self.assertIn("DE", codes)

		# Every country exists once
		self.assertEqual(len(codes), len(set(codes)))

	def test_search_networks(self):
		"""
			Searches for networks
		"""
		# By AS
		networks = list(self.db.search_networks(asns=[204867]))

		self.assertEqual([str(n) for n in networks], ["2001:678:b28::/48"])

		# By AS and family
		self.assertEqual(list(self.db.search_networks(asns=[204867], family=socket.AF_INET)), [])

		# By country
		networks = list(self.db.search_networks(country_codes=["VA"]))

		self.assertTrue(networks)
		for n in networks:
			self.assertEqual(n.country_code, "VA")

		# By more than one country
		networks = list(self.db.search_networks(country_codes=["VA", "SM"]))

		self.assertEqual({n.country_code for n in networks}, {"VA", "SM"})

		# By flag
		networks = list(self.db.search_networks(flags=location.NETWORK_FLAG_ANYCAST))

		self.assertTrue(networks)
		for n in networks:
			self.assertTrue(n.has_flag(location.NETWORK_FLAG_ANYCAST))

		# By family
		for family in (socket.AF_INET, socket.AF_INET6):
			with self.subTest(family=family):
				for n in self.db.search_networks(country_codes=["VA"], family=family):
					self.assertEqual(n.family, family)

	def test_search_networks_flattened(self):
		"""
			Flattened networks must not overlap and cover the same addresses
		"""
		networks = list(self.db.search_networks(country_codes=["VA"]))
		flattened = list(self.db.search_networks(country_codes=["VA"], flatten=True))

		# Flattening only splits networks
		self.assertGreaterEqual(len(flattened), len(networks))

		for n in flattened:
			self.assertEqual(n.country_code, "VA")

			# Each of them is in one of the networks that we found before
			self.assertTrue(any(n.is_subnet_of(network) for network in networks),
				"%s is not part of any network" % n)

		# None of them overlap
		flattened.sort()

		for n1, n2 in zip(flattened, flattened[1:]):
			self.assertFalse(n2.is_subnet_of(n1), "%s overlaps with %s" % (n2, n1))

	def test_search_networks_invalid(self):
		"""
			Searches with invalid arguments must fail
		"""
		with self.assertRaises(ValueError):
			self.db.search_networks(country_codes=["XYZ"])

		with self.assertRaises(TypeError):
			self.db.search_networks(country_codes=[1])

		for asn in (-1, 2**32):
			with self.subTest(asn=asn):
				with self.assertRaises(OverflowError):
					self.db.search_networks(asns=[asn])

		with self.assertRaises(TypeError):
			self.db.search_networks(asns=["204867"])


if __name__ == "__main__":
	unittest.main()
