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
import os
import sys
import tempfile
import threading
import unittest

TEST_DATA_DIR = os.environ["TEST_DATA_DIR"]

class LookupThread(threading.Thread):
	"""
		Looks up addresses until it is being stopped, and counts how many
	"""
	def __init__(self, db):
		super().__init__()

		self.db = db
		self.lookups = 0
		self.stopped = threading.Event()

	def run(self):
		while not self.stopped.is_set():
			self.db.lookup("81.3.27.38")
			self.lookups += 1

	def stop(self):
		self.stopped.set()
		self.join()


class Test(unittest.TestCase):
	def setUp(self):
		self.db = location.Database(os.path.join(TEST_DATA_DIR, "database.db"))

		# Switch threads often, so that the lookup thread only gets very little done
		# before a function that holds the GIL takes it back
		self.switch_interval = sys.getswitchinterval()
		sys.setswitchinterval(0.0001)

		# Create a writer with enough networks that writing takes a moment
		self.writer = location.Writer()

		for i in range(20000):
			network = self.writer.add_network("10.%s.%s.0/24" % (i // 256, i % 256))
			network.country_code = "DE"

		fd, self.path = tempfile.mkstemp()
		os.close(fd)

	def tearDown(self):
		sys.setswitchinterval(self.switch_interval)

		os.unlink(self.path)

	def run_alongside_lookups(self, fn):
		"""
			Calls fn while another thread looks up addresses,
			and returns how many lookups it managed in the meantime
		"""
		thread = LookupThread(self.db)
		thread.start()

		try:
			# Wait until the thread is running
			while not thread.lookups:
				pass

			before = thread.lookups
			fn()
			after = thread.lookups

		finally:
			thread.stop()

		return after - before

	def test_write(self):
		"""
			Other threads can run while the database is being written
		"""
		lookups = self.run_alongside_lookups(lambda: self.writer.write(self.path))

		self.assertGreater(lookups, 1000)

		# The database must have been written
		db = location.Database(self.path)
		self.assertEqual(db.lookup("10.0.0.1").country_code, "DE")

	def test_verify(self):
		"""
			Other threads can run while the database is being verified
		"""
		with open(os.path.join(TEST_DATA_DIR, "signing-key.pem")) as f:
			result = []

			lookups = self.run_alongside_lookups(lambda: result.append(self.db.verify(f)))

		self.assertGreater(lookups, 1000)
		self.assertEqual(result, [True])

	def test_writer_is_busy(self):
		"""
			The writer cannot be changed while it is writing
		"""
		thread = threading.Thread(target=self.writer.write, args=(self.path,))
		thread.start()

		errors = { "add_as" : 0, "vendor" : 0, "write" : 0 }

		# Try changing the writer until it has finished
		i = 0
		while thread.is_alive():
			i += 1

			try:
				self.writer.add_as(i)
			except RuntimeError:
				errors["add_as"] += 1
			else:
				continue

			# While it is busy, nothing else may be changed, and it cannot write again.
			# The other thread might have finished in the meantime, so these are only
			# being counted.
			try:
				self.writer.vendor = "Somebody"
			except RuntimeError:
				errors["vendor"] += 1

			try:
				self.writer.write(self.path)
			except RuntimeError:
				errors["write"] += 1

		thread.join()

		for operation, count in errors.items():
			with self.subTest(operation=operation):
				self.assertGreater(count, 0)

		# It can be changed again after it has finished
		self.writer.add_as(64512)
		self.writer.vendor = "Somebody"


if __name__ == "__main__":
	unittest.main()
