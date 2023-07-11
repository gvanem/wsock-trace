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

	def test_list_networks(self):
		"""
			Lists all available networks
		"""
		for network in self.db.networks:
			print(network)

	def test_list_networks_flattened(self):
		"""
			Lists all networks but flattened
		"""
		for i, network in enumerate(self.db.networks_flattened):
			# Break after the first 1000 iterations
			if i >= 1000:
				break

			print(network)


if __name__ == "__main__":
	unittest.main()
