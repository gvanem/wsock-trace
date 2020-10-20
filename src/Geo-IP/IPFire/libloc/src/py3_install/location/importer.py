#!/usr/bin/python3
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

import gzip
import logging
import urllib.request

# Initialise logging
log = logging.getLogger("location.importer")
log.propagate = 1

WHOIS_SOURCES = (
	# African Network Information Centre
	"https://ftp.afrinic.net/pub/pub/dbase/afrinic.db.gz",

	# Asia Pacific Network Information Centre
	#"https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz",
	#"https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz",
	#"https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz",
	#"https://ftp.apnic.net/apnic/whois/apnic.db.route.gz",
	"https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz",
	"https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz",

	# American Registry for Internet Numbers
	# XXX there is nothing useful for us in here
	#"https://ftp.arin.net/pub/rr/arin.db",

	# Latin America and Caribbean Network Information Centre
	# XXX ???

	# Réseaux IP Européens
	#"https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz",
	#"https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz",
	#"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz",
	#"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz",
	"https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz",
	"https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz",
)

EXTENDED_SOURCES = (
	# African Network Information Centre
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",

	# Asia Pacific Network Information Centre
	"https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-extended-latest",

	# American Registry for Internet Numbers
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",

	# Latin America and Caribbean Network Information Centre
	"http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",

	# Réseaux IP Européens
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
)

class Downloader(object):
	def __init__(self):
		self.proxy = None

	def set_proxy(self, url):
		"""
			Sets a HTTP proxy that is used to perform all requests
		"""
		log.info("Using proxy %s" % url)
		self.proxy = url

	def request(self, url, data=None, return_blocks=False):
		req = urllib.request.Request(url, data=data)

		# Configure proxy
		if self.proxy:
			req.set_proxy(self.proxy, "http")

		return DownloaderContext(self, req, return_blocks=return_blocks)


class DownloaderContext(object):
	def __init__(self, downloader, request, return_blocks=False):
		self.downloader = downloader
		self.request = request

		# Should we return one block or a single line?
		self.return_blocks = return_blocks

		# Save the response object
		self.response = None

	def __enter__(self):
		log.info("Retrieving %s..." % self.request.full_url)

		# Send request
		self.response = urllib.request.urlopen(self.request)

		# Log the response headers
		log.debug("Response Headers:")
		for header in self.headers:
			log.debug("	%s: %s" % (header, self.get_header(header)))

		return self

	def __exit__(self, type, value, traceback):
		pass

	def __iter__(self):
		"""
			Makes the object iterable by going through each block
		"""
		if self.return_blocks:
			return iterate_over_blocks(self.body)

		return iterate_over_lines(self.body)

	@property
	def headers(self):
		if self.response:
			return self.response.headers

	def get_header(self, name):
		if self.headers:
			return self.headers.get(name)

	@property
	def body(self):
		"""
			Returns a file-like object with the decoded content
			of the response.
		"""
		content_type = self.get_header("Content-Type")

		# Decompress any gzipped response on the fly
		if content_type in ("application/x-gzip", "application/gzip"):
			return gzip.GzipFile(fileobj=self.response, mode="rb")

		# Return the response by default
		return self.response


def read_blocks(f):
	for block in iterate_over_blocks(f):
		type = None
		data = {}

		for i, line in enumerate(block):
			key, value = line.split(":", 1)

			# The key of the first line defines the type
			if i == 0:
				type = key

			# Store value
			data[key] = value.strip()

		yield type, data

def iterate_over_blocks(f, charsets=("utf-8", "latin1")):
	block = []

	for line in f:
		# Convert to string
		for charset in charsets:
			try:
				line = line.decode(charset)
			except UnicodeDecodeError:
				continue
			else:
				break

		# Skip commented lines
		if line.startswith("#") or line.startswith("%"):
			continue

		# Strip line-endings
		line = line.rstrip()

		# Remove any comments at the end of line
		line, hash, comment = line.partition("#")

		if comment:
			# Strip any whitespace before the comment
			line = line.rstrip()

			# If the line is now empty, we move on
			if not line:
				continue

		if line:
			block.append(line)
			continue

		# End the block on an empty line
		if block:
			yield block

		# Reset the block
		block = []

	# Return the last block
	if block:
		yield block


def iterate_over_lines(f):
	for line in f:
		# Decode the line
		line = line.decode()

		# Strip the ending
		yield line.rstrip()
