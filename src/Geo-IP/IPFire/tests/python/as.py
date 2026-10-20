#!/usr/bin/python3
###############################################################################
#                                                                             #
# libloc - A library to determine the location of someone on the Internet     #
#                                                                             #
# Copyright (C) 2026 IPFire Development Team <info@ipfire.org>                #
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
		a = location.AS(64496)

		self.assertEqual(a.number, 64496)

		# An AS does not have a name at first
		self.assertIsNone(a.name)
		self.assertEqual(repr(a), "<AS 64496>")
		self.assertEqual(str(a), "AS64496")

		# Set a name and read it back
		a.name = "Example"
		self.assertEqual(a.name, "Example")
		self.assertEqual(repr(a), "<AS 64496 (Example)>")
		self.assertEqual(str(a), "AS64496 - Example")

		with self.assertRaises(TypeError):
			a.name = b"Example"

		# Remove the name again
		a.name = None
		self.assertIsNone(a.name)

		a.name = "Example"
		del a.name
		self.assertIsNone(a.name)

	def test_number(self):
		# The largest AS number there is
		a = location.AS(2**32 - 1)

		self.assertEqual(a.number, 2**32 - 1)
		self.assertEqual(repr(a), "<AS 4294967295>")
		self.assertEqual(str(a), "AS4294967295")

		for number in (-1, 2**32):
			with self.subTest(number=number):
				with self.assertRaises(OverflowError):
					location.AS(number)

		with self.assertRaises(TypeError):
			location.AS("64496")

	def test_compare(self):
		a1 = location.AS(64496)
		a2 = location.AS(64496)
		a3 = location.AS(64497)

		self.assertEqual(a1, a2)
		self.assertNotEqual(a1, a3)

		self.assertLess(a1, a3)
		self.assertGreater(a3, a1)

		# An AS is not a number
		self.assertNotEqual(a1, 64496)

	def test_hash(self):
		a1 = location.AS(64496)
		a2 = location.AS(64496)

		# Equal ASes must have the same hash, so that they can be in a set
		self.assertEqual(hash(a1), hash(a2))
		self.assertEqual(len({a1, a2, location.AS(64497)}), 2)

		# This becomes -1 where Py_hash_t has 32 bits
		hash(location.AS(2**32 - 1))


if __name__ == "__main__":
	unittest.main()
