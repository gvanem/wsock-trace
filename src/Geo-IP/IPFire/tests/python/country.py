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
import unittest

class Test(unittest.TestCase):
	def test_properties(self):
		c = location.Country("DE")

		# The code should be DE
		self.assertEqual(c.code, "DE")

		# All other attributes should return None
		self.assertIsNone(c.name)
		self.assertIsNone(c.continent_code)

		# Set a name and read it back
		c.name = "Germany"
		self.assertEqual(c.name, "Germany")

		# Set a continent code and read it back
		c.continent_code = "EU"
		self.assertEqual(c.continent_code, "EU")

	def test_country_cmp(self):
		"""
			Performs some comparison tests
		"""
		c1 = location.Country("DE")
		c2 = location.Country("DE")

		# c1 and c2 should be equal
		self.assertEqual(c1, c2)

		# We cannot compare against strings for example
		self.assertNotEqual(c1, "DE")

		c3 = location.Country("AT")

		# c1 and c3 should not be equal
		self.assertNotEqual(c1, c3)

		# c3 comes before c1 (alphabetically)
		self.assertGreater(c1, c3)
		self.assertLess(c3, c1)

	def test_country_hash(self):
		"""
			Tests if the hash function works
		"""
		c = location.Country("DE")

		self.assertTrue(hash(c))

if __name__ == "__main__":
	unittest.main()
