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
import socket
import unittest

class Test(unittest.TestCase):
	def test_ipv4(self):
		n = location.Network("192.0.2.0/24")

		self.assertEqual(str(n), "192.0.2.0/24")
		self.assertEqual(repr(n), "<location.Network 192.0.2.0/24>")
		self.assertEqual(n.family, socket.AF_INET)

		# Addresses
		self.assertEqual(n.first_address, "192.0.2.0")
		self.assertEqual(n.last_address, "192.0.2.255")
		self.assertEqual(n._first_address, bytes((192, 0, 2, 0)))
		self.assertEqual(n._last_address, bytes((192, 0, 2, 255)))

	def test_ipv6(self):
		n = location.Network("2001:db8::/32")

		self.assertEqual(str(n), "2001:db8::/32")
		self.assertEqual(n.family, socket.AF_INET6)

		self.assertEqual(n.first_address, "2001:db8::")
		self.assertEqual(n.last_address, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
		self.assertEqual(len(n._first_address), 16)

	def test_invalid(self):
		for network in ("nonsense", "192.0.2.0/33", "2001:db8::/129", ""):
			with self.subTest(network=network):
				with self.assertRaises(ValueError):
					location.Network(network)

	def test_host_bits(self):
		"""
			Bits beyond the prefix are being removed
		"""
		n = location.Network("192.0.2.1/24")

		self.assertEqual(str(n), "192.0.2.0/24")

	def test_country_code(self):
		n = location.Network("192.0.2.0/24")

		# Networks don't have a country code at first
		self.assertEqual(n.country_code, "")

		n.country_code = "DE"
		self.assertEqual(n.country_code, "DE")

		# Invalid country codes are rejected and don't change anything
		with self.assertRaises(ValueError):
			n.country_code = "XYZ"

		self.assertEqual(n.country_code, "DE")

		with self.assertRaises(TypeError):
			n.country_code = 1

		# Remove the country code again
		n.country_code = None
		self.assertEqual(n.country_code, "")

		n.country_code = "DE"
		del n.country_code
		self.assertEqual(n.country_code, "")

	def test_asn(self):
		n = location.Network("192.0.2.0/24")

		# Networks don't have an ASN at first
		self.assertIsNone(n.asn)

		n.asn = 64496
		self.assertEqual(n.asn, 64496)

		# The largest AS number there is
		n.asn = 2**32 - 1
		self.assertEqual(n.asn, 2**32 - 1)

		# AS0 is reserved, and everything else must fit into 32 bits
		for asn in (0, -1, 2**32):
			with self.subTest(asn=asn):
				with self.assertRaises(ValueError):
					n.asn = asn

		with self.assertRaises(TypeError):
			n.asn = "64496"

		# Remove the ASN again
		n.asn = None
		self.assertIsNone(n.asn)

		n.asn = 64496
		del n.asn
		self.assertIsNone(n.asn)

	def test_flags(self):
		n = location.Network("192.0.2.0/24")

		flags = (
			location.NETWORK_FLAG_ANONYMOUS_PROXY,
			location.NETWORK_FLAG_SATELLITE_PROVIDER,
			location.NETWORK_FLAG_ANYCAST,
			location.NETWORK_FLAG_DROP,
		)

		# No flags are set at first
		for flag in flags:
			self.assertFalse(n.has_flag(flag))

		# Set one flag
		n.set_flag(location.NETWORK_FLAG_ANYCAST)

		for flag in flags:
			self.assertEqual(n.has_flag(flag), flag == location.NETWORK_FLAG_ANYCAST)

	def test_compare(self):
		n1 = location.Network("192.0.2.0/24")
		n2 = location.Network("192.0.2.0/24")
		n3 = location.Network("192.0.3.0/24")

		self.assertEqual(n1, n2)
		self.assertNotEqual(n1, n3)

		self.assertLess(n1, n3)
		self.assertGreater(n3, n1)

		# A network is not a string
		self.assertNotEqual(n1, "192.0.2.0/24")

		# Sorting puts the networks in order
		self.assertEqual(sorted([n3, n1]), [n1, n3])

	def test_is_subnet_of(self):
		n = location.Network("192.0.2.0/24")
		supernet = location.Network("192.0.0.0/16")

		self.assertTrue(n.is_subnet_of(supernet))
		self.assertFalse(supernet.is_subnet_of(n))

		# A network is a subnet of itself
		self.assertTrue(n.is_subnet_of(n))

		# Unrelated networks
		self.assertFalse(n.is_subnet_of(location.Network("198.51.100.0/24")))
		self.assertFalse(n.is_subnet_of(location.Network("2001:db8::/32")))

	def test_subnets(self):
		n = location.Network("192.0.2.0/24")

		self.assertEqual(
			[str(subnet) for subnet in n.subnets],
			["192.0.2.0/25", "192.0.2.128/25"],
		)

		n = location.Network("2001:db8::/127")

		self.assertEqual(
			[str(subnet) for subnet in n.subnets],
			["2001:db8::/128", "2001:db8::1/128"],
		)

		# A single address cannot be split
		for network in ("192.0.2.1/32", "2001:db8::1/128"):
			with self.subTest(network=network):
				with self.assertRaises(ValueError):
					location.Network(network).subnets

	def test_exclude(self):
		n = location.Network("192.0.2.0/24")

		# Remove the first quarter
		subnets = n.exclude(location.Network("192.0.2.0/26"))

		self.assertEqual(
			sorted(str(subnet) for subnet in subnets),
			["192.0.2.128/25", "192.0.2.64/26"],
		)

		# Nothing is left if we remove the network itself
		self.assertEqual(n.exclude(n), [])

		# Nothing is left if we remove a larger network
		self.assertEqual(n.exclude(location.Network("192.0.0.0/16")), [])

		# Removing something that is somewhere else leaves the network as it is
		self.assertEqual(n.exclude(location.Network("198.51.100.0/24")), [n])
		self.assertEqual(n.exclude(location.Network("2001:db8::/32")), [n])

		# The type is being checked
		with self.assertRaises(TypeError):
			n.exclude("192.0.2.0/26")

	def test_reverse_pointer(self):
		n = location.Network("192.0.2.0/24")

		self.assertEqual(n.reverse_pointer(), "*.2.0.192.in-addr.arpa.")
		self.assertEqual(n.reverse_pointer("example.org."), "*.2.0.192.example.org.")

		n = location.Network("2001:db8::/32")

		self.assertEqual(n.reverse_pointer(), "*.8.b.d.0.1.0.0.2.ip6.arpa.")

		# Single addresses don't have a wildcard
		n = location.Network("192.0.2.1/32")

		self.assertEqual(n.reverse_pointer(), "1.2.0.192.in-addr.arpa.")

		# Networks that don't end on a boundary don't have a reverse pointer
		self.assertIsNone(location.Network("2001:db8::/33").reverse_pointer())
		self.assertIsNone(location.Network("192.0.2.0/25").reverse_pointer())


if __name__ == "__main__":
	unittest.main()
