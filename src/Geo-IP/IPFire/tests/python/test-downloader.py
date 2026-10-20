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

import os
import socket
import threading
import unittest

import location
import location.downloader

class FakeProxy(object):
	"""
		A proxy that does not forward anything. It only remembers the first
		line of every request it receives, which is all we want to know.
	"""
	def __init__(self):
		self.requests = []

		# Listen on any port that is free
		self.socket = socket.socket()
		self.socket.bind(("127.0.0.1", 0))
		self.socket.listen(8)

		self.port = self.socket.getsockname()[1]

		self.thread = threading.Thread(target=self.run, daemon=True)
		self.thread.start()

	@property
	def url(self):
		return "http://127.0.0.1:%s" % self.port

	def run(self):
		while True:
			try:
				conn, address = self.socket.accept()
			except OSError:
				break

			with conn:
				request = conn.recv(4096).decode(errors="replace")

				# We only want to know what is being asked for, and not how.
				# Python sends CONNECT as HTTP/1.0 until version 3.11 and
				# as HTTP/1.1 after that.
				method, target, *rest = request.split("\r\n")[0].split(" ")

				self.requests.append("%s %s" % (method, target))

				# We could not reach anything
				conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")

	def close(self):
		self.socket.close()


class Test(unittest.TestCase):
	def setUp(self):
		self.proxy = FakeProxy()

		# Remember the environment
		self.environ = dict(os.environ)

		# Remove any proxies that might be configured where the tests run
		for key in list(os.environ):
			if key.lower().endswith("_proxy"):
				del os.environ[key]

	def tearDown(self):
		self.proxy.close()

		# Restore the environment
		os.environ.clear()
		os.environ.update(self.environ)

	def request(self, url, **kwargs):
		"""
			Sends a request which is going to fail, and returns
			whatever the proxy has been asked for (if anything)
		"""
		downloader = location.downloader.Downloader()

		req = downloader._make_request(url, **kwargs)

		del self.proxy.requests[:]

		try:
			downloader._send_request(req, timeout=10)
		except Exception:
			pass

		return list(self.proxy.requests)

	def test_https(self):
		"""
			HTTPS needs a tunnel to port 443
		"""
		os.environ["https_proxy"] = os.environ["http_proxy"] = self.proxy.url

		requests = self.request("https://location.example.org/databases/1/location.db.xz")

		self.assertEqual(requests, ["CONNECT location.example.org:443"])

	def test_https_port(self):
		"""
			The tunnel has to go to the port that is part of the URL
		"""
		os.environ["https_proxy"] = os.environ["http_proxy"] = self.proxy.url

		requests = self.request("https://location.example.org:8443/file")

		self.assertEqual(requests, ["CONNECT location.example.org:8443"])

	def test_http(self):
		"""
			HTTP is being requested from the proxy with the entire URL
		"""
		os.environ["https_proxy"] = os.environ["http_proxy"] = self.proxy.url

		requests = self.request("http://location.example.org/file")

		self.assertEqual(requests, ["GET http://location.example.org/file"])

	def test_no_proxy(self):
		"""
			Hosts that are excluded must not be requested from the proxy
		"""
		os.environ["https_proxy"] = os.environ["http_proxy"] = self.proxy.url
		os.environ["no_proxy"] = "example.org"

		requests = self.request("http://location.example.org/file")

		self.assertEqual(requests, [])

	def test_headers(self):
		"""
			We tell everyone who we are, unless the caller wants to be somebody else
		"""
		downloader = location.downloader.Downloader()

		req = downloader._make_request("https://location.example.org/")
		self.assertEqual(req.get_header("User-agent"), "location/%s" % location.__version__)

		headers = { "User-Agent" : "test/1.0", "Accept" : "text/plain" }

		req = downloader._make_request("https://location.example.org/", headers=headers)
		self.assertEqual(req.get_header("User-agent"), "test/1.0")
		self.assertEqual(req.get_header("Accept"), "text/plain")

		# What we have been passed must not have been changed
		self.assertEqual(headers, { "User-Agent" : "test/1.0", "Accept" : "text/plain" })

		# And the next request is us again
		req = downloader._make_request("https://location.example.org/")
		self.assertEqual(req.get_header("User-agent"), "location/%s" % location.__version__)


if __name__ == "__main__":
	unittest.main()
