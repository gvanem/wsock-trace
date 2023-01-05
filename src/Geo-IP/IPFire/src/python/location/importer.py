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
import tempfile
import urllib.request

# Initialise logging
log = logging.getLogger("location.importer")
log.propagate = 1

WHOIS_SOURCES = {
	# African Network Information Centre
	"AFRINIC": [
		"https://ftp.afrinic.net/pub/pub/dbase/afrinic.db.gz"
		],

	# Asia Pacific Network Information Centre
	"APNIC": [
		"https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz",
		"https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz",
		#"https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz",
		#"https://ftp.apnic.net/apnic/whois/apnic.db.route.gz",
		"https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz",
		"https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz"
		],

	# American Registry for Internet Numbers
	# XXX there is nothing useful for us in here
	# ARIN: [
	#	"https://ftp.arin.net/pub/rr/arin.db"
	# ],

	# Japan Network Information Center
	"JPNIC": [
		"https://ftp.nic.ad.jp/jpirr/jpirr.db.gz"
		],

	# Latin America and Caribbean Network Information Centre
	"LACNIC": [
		"https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz"
		],

	# Réseaux IP Européens
	"RIPE": [
		"https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz",
		"https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz",
		#"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz",
		#"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz",
		"https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz",
		"https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz"
		],
}

EXTENDED_SOURCES = {
	# African Network Information Centre
	# "ARIN": [
	#	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
	# ],

	# Asia Pacific Network Information Centre
	# "APNIC": [
	#	"https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-extended-latest"
	# ],

	# American Registry for Internet Numbers
	"ARIN": [
		"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
		],

	# Latin America and Caribbean Network Information Centre
	"LACNIC": [
		"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"
		],

	# Réseaux IP Européens
	# "RIPE": [
	#	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
	# ],
}

# List all sources
SOURCES = set(WHOIS_SOURCES|EXTENDED_SOURCES)

class Downloader(object):
	def __init__(self):
		self.proxy = None

	def set_proxy(self, url):
		"""
			Sets a HTTP proxy that is used to perform all requests
		"""
		log.info("Using proxy %s" % url)
		self.proxy = url

	def retrieve(self, url, data=None):
		"""
			This method will fetch the content at the given URL
			and will return a file-object to a temporary file.

			If the content was compressed, it will be decompressed on the fly.
		"""
		# Open a temporary file to buffer the downloaded content
		t = tempfile.SpooledTemporaryFile(max_size=100 * 1024 * 1024)

		# Create a new request
		req = urllib.request.Request(url, data=data)

		# Configure proxy
		if self.proxy:
			req.set_proxy(self.proxy, "http")

		log.info("Retrieving %s..." % req.full_url)

		# Send request
		res = urllib.request.urlopen(req)

		# Log the response headers
		log.debug("Response Headers:")
		for header in res.headers:
			log.debug("	%s: %s" % (header, res.headers[header]))

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

	def request_blocks(self, url, data=None):
		"""
			This method will fetch the data from the URL and return an
			iterator for each block in the data.
		"""
		# Download the data first
		t = self.retrieve(url, data=data)

		# Then, split it into blocks
		return iterate_over_blocks(t)

	def request_lines(self, url, data=None):
		"""
			This method will fetch the data from the URL and return an
			iterator for each line in the data.
		"""
		# Download the data first
		t = self.retrieve(url, data=data)

		# Then, split it into lines
		return iterate_over_lines(t)


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
		# Skip commented lines
		if line.startswith(b"#") or line.startswith(b"%"):
			continue

		# Convert to string
		for charset in charsets:
			try:
				line = line.decode(charset)
			except UnicodeDecodeError:
				continue
			else:
				break

		# Remove any comments at the end of line
		line, hash, comment = line.partition("#")

		# Strip any whitespace at the end of the line
		line = line.rstrip()

		# If we cut off some comment and the line is empty, we can skip it
		if comment and not line:
			continue

		# If the line has some content, keep collecting it
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
