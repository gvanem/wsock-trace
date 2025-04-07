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

import sys
import gzip
import logging
import lzma
import os
import random
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from _location import Database, DATABASE_VERSION_LATEST, __version__

DATABASE_FILENAME = "location.db.xz"
MIRRORS = (
	"https://location.ipfire.org/databases/",
)

# Initialise logging
log = logging.getLogger("location.downloader")
log.propagate = 1

class Downloader(object):
	def __init__(self, version=DATABASE_VERSION_LATEST, mirrors=None):
		self.version = version

		# Set mirrors or use defaults
		self.mirrors = list(mirrors or MIRRORS)

		# Randomize mirrors
		random.shuffle(self.mirrors)

		# Get proxies from environment
		self.proxies = self._get_proxies()

	def _get_proxies(self):
		proxies = {}

		for protocol in ("https", "http"):
			proxy = os.environ.get("%s_proxy" % protocol, None)

			if proxy:
				proxies[protocol] = proxy

		return proxies

	def _make_request(self, url, baseurl=None, headers={}):
		if baseurl:
			url = urllib.parse.urljoin(baseurl, url)

		req = urllib.request.Request(url, method="GET")

		# Update headers
		headers.update({
			"User-Agent" : "location/%s" % __version__,
		})

		# Set headers
		for header in headers:
			req.add_header(header, headers[header])

		# Set proxies
		for protocol in self.proxies:
			req.set_proxy(self.proxies[protocol], protocol)

		return req

	def _send_request(self, req, **kwargs):
		# Log request headers
		log.debug("HTTP %s Request to %s" % (req.method, req.host))
		log.debug("	URL: %s" % req.full_url)
		log.debug("	Headers:")
		for k, v in req.header_items():
			log.debug("		%s: %s" % (k, v))

		try:
			res = urllib.request.urlopen(req, **kwargs)

		except urllib.error.HTTPError as e:
			# Log response headers
			log.debug("HTTP Response: %s" % e.code)
			log.debug("	Headers:")
			for header in e.headers:
				log.debug("		%s: %s" % (header, e.headers[header]))

			# Raise all other errors
			raise e

		# Log response headers
		log.debug("HTTP Response: %s" % res.code)
		log.debug("	Headers:")
		for k, v in res.getheaders():
			log.debug("		%s: %s" % (k, v))

		return res

	def download(self, public_key, timestamp=None, tmpdir=None, **kwargs):
		url = "%s/%s" % (self.version, DATABASE_FILENAME)

		headers = {}
		if timestamp:
			headers["If-Modified-Since"] = time.strftime(
				"%a, %d %b %Y %H:%M:%S GMT", time.gmtime(timestamp),
			)

		t = tempfile.NamedTemporaryFile(dir=tmpdir, delete=False)
		with t:
			# Try all mirrors
			for mirror in self.mirrors:
				# Prepare HTTP request
				req = self._make_request(url, baseurl=mirror, headers=headers)

				try:
					with self._send_request(req) as res:
						decompressor = lzma.LZMADecompressor()
						print("Decompressing file: '%s'" % t.name)

						# Read all data
						while True:
							buf = res.read(1024)
							if not buf:
								break

							# Decompress data
							buf = decompressor.decompress(buf)
							if buf:
								t.write(buf)

					# Write all data to disk
					t.flush()

				# Catch decompression errors
				except lzma.LZMAError as e:
					print("Could not decompress downloaded file: '%s', e: %s" % (t.name, e))
					continue

				except urllib.error.HTTPError as e:
					# The file on the server was too old
					if e.code == 304:
						print("%s is serving an outdated database. Trying next mirror..." % mirror)

					# Log any other HTTP errors
					else:
						print("%s reported: %s" % (mirror, e))

					# Throw away any downloaded content and try again
					# print("(1): truncating '%s'" % t.name)
					t.truncate()

				else:
					# Check if the downloaded database is recent
					if not self._check_database(t, public_key, timestamp):
						print("Downloaded database is outdated. Trying next mirror...")

						# Throw away the data and try again
						# print("(2): truncating '%s'" % t.name)
						t.truncate()
						continue

					# Make the file readable for everyone. On 'win32' this would create a read-only file.
					if sys.platform != "win32":
						os.chmod(t.name, stat.S_IRUSR|stat.S_IRGRP|stat.S_IROTH)

					# Return temporary file
					return t

		# Delete the temporary file after unsuccessful downloads
		print("deleting '%s'" % t.name)
		os.unlink(t.name)

		raise FileNotFoundError(url)

	def _check_database(self, f, public_key, timestamp=None):
		"""
			Checks the downloaded database if it can be opened,
			verified and if it is recent enough
		"""
		print("Opening downloaded database at %s" % f.name)

		db = Database(f.name)

		# Database is not recent
		if timestamp and db.created_at < timestamp:
			return False

		log.info("Downloaded new database from %s" % (time.strftime(
			"%a, %d %b %Y %H:%M:%S GMT", time.gmtime(db.created_at),
		)))

		# Verify the database
		print("verifying '%s' agains public_key: '%s'" % (f.name, public_key))

		with open(public_key, "r") as f:
			if not db.verify(f):
				print("Could not verify database")
				return False

		return True

	def retrieve(self, url, timeout=None, **kwargs):
		"""
			This method will fetch the content at the given URL
			and will return a file-object to a temporary file.

			If the content was compressed, it will be decompressed on the fly.
		"""
		# Open a temporary file to buffer the downloaded content
		t = tempfile.SpooledTemporaryFile(max_size=100 * 1024 * 1024)

		# Create a new request
		req = self._make_request(url, **kwargs)

		# Send request
		res = self._send_request(req, timeout=timeout)

		# Write the payload to the temporary file
		with res as f:
			while True:
				buf = f.read(65536)
				if not buf:
					break

				t.write(buf)

		# Rewind the temporary file
		t.seek(0)

		gzip_compressed = False

		# Fetch the content type
		content_type = res.headers.get("Content-Type")

		# Decompress any gzipped response on the fly
		if content_type in ("application/x-gzip", "application/gzip"):
			gzip_compressed = True

		# Check for the gzip magic in case web servers send a different MIME type
		elif t.read(2) == b"\x1f\x8b":
			gzip_compressed = True

		# Reset again
		t.seek(0)

		# Decompress the temporary file
		if gzip_compressed:
			log.debug("Gzip compression detected")

			t = gzip.GzipFile(fileobj=t, mode="rb")

		# Return the temporary file handle
		return t
