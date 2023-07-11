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

import location
import os
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


if __name__ == "__main__":
	unittest.main()
