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

import argparse
import ipaddress
import logging
import math
import re
import socket
import sys
import telnetlib

# Load our location module
import location
import location.database
import location.importer
from location.i18n import _

# Initialise logging
log = logging.getLogger("location.importer")
log.propagate = 1

class CLI(object):
	def parse_cli(self):
		parser = argparse.ArgumentParser(
			description=_("Location Importer Command Line Interface"),
		)
		subparsers = parser.add_subparsers()

		# Global configuration flags
		parser.add_argument("--debug", action="store_true",
			help=_("Enable debug output"))
		parser.add_argument("--quiet", action="store_true",
			help=_("Enable quiet mode"))

		# version
		parser.add_argument("--version", action="version",
			version="%(prog)s 0.9.4")

		# Database
		parser.add_argument("--database-host", required=True,
			help=_("Database Hostname"), metavar=_("HOST"))
		parser.add_argument("--database-name", required=True,
			help=_("Database Name"), metavar=_("NAME"))
		parser.add_argument("--database-username", required=True,
			help=_("Database Username"), metavar=_("USERNAME"))
		parser.add_argument("--database-password", required=True,
			help=_("Database Password"), metavar=_("PASSWORD"))

		# Write Database
		write = subparsers.add_parser("write", help=_("Write database to file"))
		write.set_defaults(func=self.handle_write)
		write.add_argument("file", nargs=1, help=_("Database File"))
		write.add_argument("--signing-key", nargs="?", type=open, help=_("Signing Key"))
		write.add_argument("--backup-signing-key", nargs="?", type=open, help=_("Backup Signing Key"))
		write.add_argument("--vendor", nargs="?", help=_("Sets the vendor"))
		write.add_argument("--description", nargs="?", help=_("Sets a description"))
		write.add_argument("--license", nargs="?", help=_("Sets the license"))
		write.add_argument("--version", type=int, help=_("Database Format Version"))

		# Update WHOIS
		update_whois = subparsers.add_parser("update-whois", help=_("Update WHOIS Information"))
		update_whois.set_defaults(func=self.handle_update_whois)

		# Update announcements
		update_announcements = subparsers.add_parser("update-announcements",
			help=_("Update BGP Annoucements"))
		update_announcements.set_defaults(func=self.handle_update_announcements)
		update_announcements.add_argument("server", nargs=1,
			help=_("Route Server to connect to"), metavar=_("SERVER"))

		# Update overrides
		update_overrides = subparsers.add_parser("update-overrides",
			help=_("Update overrides"),
		)
		update_overrides.add_argument(
			"files", nargs="+", help=_("Files to import"),
		)
		update_overrides.set_defaults(func=self.handle_update_overrides)

		# Import countries
		import_countries = subparsers.add_parser("import-countries",
			help=_("Import countries"),
		)
		import_countries.add_argument("file", nargs=1, type=argparse.FileType("r"),
			help=_("File to import"))
		import_countries.set_defaults(func=self.handle_import_countries)

		args = parser.parse_args()

		# Configure logging
		if args.debug:
			location.logger.set_level(logging.DEBUG)
		elif args.quiet:
			location.logger.set_level(logging.WARNING)

		# Print usage if no action was given
		if not "func" in args:
			parser.print_usage()
			sys.exit(2)

		return args

	def run(self):
		# Parse command line arguments
		args = self.parse_cli()

		# Initialise database
		self.db = self._setup_database(args)

		# Call function
		ret = args.func(args)

		# Return with exit code
		if ret:
			sys.exit(ret)

		# Otherwise just exit
		sys.exit(0)

	def _setup_database(self, ns):
		"""
			Initialise the database
		"""
		# Connect to database
		db = location.database.Connection(
			host=ns.database_host, database=ns.database_name,
			user=ns.database_username, password=ns.database_password,
		)

		with db.transaction():
			db.execute("""
				-- announcements
				CREATE TABLE IF NOT EXISTS announcements(network inet, autnum bigint,
					first_seen_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
					last_seen_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP);
				CREATE UNIQUE INDEX IF NOT EXISTS announcements_networks ON announcements(network);
				CREATE INDEX IF NOT EXISTS announcements_family ON announcements(family(network));

				-- autnums
				CREATE TABLE IF NOT EXISTS autnums(number bigint, name text NOT NULL);
				CREATE UNIQUE INDEX IF NOT EXISTS autnums_number ON autnums(number);

				-- countries
				CREATE TABLE IF NOT EXISTS countries(
					country_code text NOT NULL, name text NOT NULL, continent_code text NOT NULL);
				CREATE UNIQUE INDEX IF NOT EXISTS countries_country_code ON countries(country_code);

				-- networks
				CREATE TABLE IF NOT EXISTS networks(network inet, country text);
				CREATE UNIQUE INDEX IF NOT EXISTS networks_network ON networks(network);
				CREATE INDEX IF NOT EXISTS networks_search ON networks USING GIST(network inet_ops);

				-- overrides
				CREATE TABLE IF NOT EXISTS autnum_overrides(
					number bigint NOT NULL,
					name text,
					country text,
					is_anonymous_proxy boolean,
					is_satellite_provider boolean,
					is_anycast boolean
				);
				CREATE UNIQUE INDEX IF NOT EXISTS autnum_overrides_number
					ON autnum_overrides(number);

				CREATE TABLE IF NOT EXISTS network_overrides(
					network inet NOT NULL,
					country text,
					is_anonymous_proxy boolean,
					is_satellite_provider boolean,
					is_anycast boolean
				);
				CREATE UNIQUE INDEX IF NOT EXISTS network_overrides_network
					ON network_overrides(network);
			""")

		return db

	def handle_write(self, ns):
		"""
			Compiles a database in libloc format out of what is in the database
		"""
		# Allocate a writer
		writer = location.Writer(ns.signing_key, ns.backup_signing_key)

		# Set all metadata
		if ns.vendor:
			writer.vendor = ns.vendor

		if ns.description:
			writer.description = ns.description

		if ns.license:
			writer.license = ns.license

		# Add all Autonomous Systems
		log.info("Writing Autonomous Systems...")

		# Select all ASes with a name
		rows = self.db.query("""
			SELECT
				autnums.number AS number,
				COALESCE(
					(SELECT overrides.name FROM autnum_overrides overrides
						WHERE overrides.number = autnums.number),
					autnums.name
				) AS name
				FROM autnums
				WHERE name <> %s ORDER BY number
			""", "")

		for row in rows:
			a = writer.add_as(row.number)
			a.name = row.name

		# Add all networks
		log.info("Writing networks...")

		# Select all known networks
		rows = self.db.query("""
			-- Get a (sorted) list of all known networks
			WITH known_networks AS (
					SELECT network FROM announcements
				UNION
					SELECT network FROM networks
				UNION
					SELECT network FROM network_overrides
				ORDER BY network
			)

			-- Return a list of those networks enriched with all
			-- other information that we store in the database
			SELECT
				DISTINCT ON (known_networks.network)
				known_networks.network AS network,
				announcements.autnum AS autnum,

				-- Country
				COALESCE(
					(
						SELECT country FROM network_overrides overrides
							WHERE announcements.network <<= overrides.network
							ORDER BY masklen(overrides.network) DESC
							LIMIT 1
					),
					(
						SELECT country FROM autnum_overrides overrides
							WHERE announcements.autnum = overrides.number
					),
					networks.country
				) AS country,

				-- Flags
				COALESCE(
					(
						SELECT is_anonymous_proxy FROM network_overrides overrides
							WHERE announcements.network <<= overrides.network
							ORDER BY masklen(overrides.network) DESC
							LIMIT 1
					),
					(
						SELECT is_anonymous_proxy FROM autnum_overrides overrides
							WHERE announcements.autnum = overrides.number
					),
					FALSE
				) AS is_anonymous_proxy,
				COALESCE(
					(
						SELECT is_satellite_provider FROM network_overrides overrides
							WHERE announcements.network <<= overrides.network
							ORDER BY masklen(overrides.network) DESC
							LIMIT 1
					),
					(
						SELECT is_satellite_provider FROM autnum_overrides overrides
							WHERE announcements.autnum = overrides.number
					),
					FALSE
				) AS is_satellite_provider,
				COALESCE(
					(
						SELECT is_anycast FROM network_overrides overrides
							WHERE announcements.network <<= overrides.network
							ORDER BY masklen(overrides.network) DESC
							LIMIT 1
					),
					(
						SELECT is_anycast FROM autnum_overrides overrides
							WHERE announcements.autnum = overrides.number
					),
					FALSE
				) AS is_anycast,

				-- Must be part of returned values for ORDER BY clause
				masklen(announcements.network) AS sort_a,
				masklen(networks.network) AS sort_b
			FROM known_networks
				LEFT JOIN announcements ON known_networks.network <<= announcements.network
				LEFT JOIN networks ON known_networks.network <<= networks.network
			ORDER BY known_networks.network, sort_a DESC, sort_b DESC
		""")

		for row in rows:
			network = writer.add_network(row.network)

			# Save country
			if row.country:
				network.country_code = row.country

			# Save ASN
			if row.autnum:
				network.asn = row.autnum

			# Set flags
			if row.is_anonymous_proxy:
				network.set_flag(location.NETWORK_FLAG_ANONYMOUS_PROXY)

			if row.is_satellite_provider:
				network.set_flag(location.NETWORK_FLAG_SATELLITE_PROVIDER)

			if row.is_anycast:
				network.set_flag(location.NETWORK_FLAG_ANYCAST)

		# Add all countries
		log.info("Writing countries...")
		rows = self.db.query("SELECT * FROM countries ORDER BY country_code")

		for row in rows:
			c = writer.add_country(row.country_code)
			c.continent_code = row.continent_code
			c.name = row.name

		# Write everything to file
		log.info("Writing database to file...")
		for file in ns.file:
			writer.write(file)

	def handle_update_whois(self, ns):
		downloader = location.importer.Downloader()

		# Download all sources
		with self.db.transaction():
			# Create some temporary tables to store parsed data
			self.db.execute("""
				CREATE TEMPORARY TABLE _autnums(number integer, organization text)
					ON COMMIT DROP;
				CREATE UNIQUE INDEX _autnums_number ON _autnums(number);

				CREATE TEMPORARY TABLE _organizations(handle text, name text NOT NULL)
					ON COMMIT DROP;
				CREATE UNIQUE INDEX _organizations_handle ON _organizations(handle);
			""")

			for source in location.importer.WHOIS_SOURCES:
				with downloader.request(source, return_blocks=True) as f:
					for block in f:
						self._parse_block(block)

			self.db.execute("""
				INSERT INTO autnums(number, name)
					SELECT _autnums.number, _organizations.name FROM _autnums
						JOIN _organizations ON _autnums.organization = _organizations.handle
				ON CONFLICT (number) DO UPDATE SET name = excluded.name;
			""")

		# Download all extended sources
		for source in location.importer.EXTENDED_SOURCES:
			with self.db.transaction():
				# Download data
				with downloader.request(source) as f:
					for line in f:
						self._parse_line(line)

	def _parse_block(self, block):
		# Get first line to find out what type of block this is
		line = block[0]

		# aut-num
		if line.startswith("aut-num:"):
			return self._parse_autnum_block(block)

		# organisation
		elif line.startswith("organisation:"):
			return self._parse_org_block(block)

	def _parse_autnum_block(self, block):
		autnum = {}
		for line in block:
			# Split line
			key, val = split_line(line)

			if key == "aut-num":
				m = re.match(r"^(AS|as)(\d+)", val)
				if m:
					autnum["asn"] = m.group(2)

			elif key == "org":
				autnum[key] = val

		# Skip empty objects
		if not autnum:
			return

		# Insert into database
		self.db.execute("INSERT INTO _autnums(number, organization) \
			VALUES(%s, %s) ON CONFLICT (number) DO UPDATE SET \
				organization = excluded.organization",
			autnum.get("asn"), autnum.get("org"),
		)

	def _parse_org_block(self, block):
		org = {}
		for line in block:
			# Split line
			key, val = split_line(line)

			if key in ("organisation", "org-name"):
				org[key] = val

		# Skip empty objects
		if not org:
			return

		self.db.execute("INSERT INTO _organizations(handle, name) \
			VALUES(%s, %s) ON CONFLICT (handle) DO \
			UPDATE SET name = excluded.name",
			org.get("organisation"), org.get("org-name"),
		)

	def _parse_line(self, line):
		# Skip version line
		if line.startswith("2"):
			return

		# Skip comments
		if line.startswith("#"):
			return

		try:
			registry, country_code, type, line = line.split("|", 3)
		except:
			log.warning("Could not parse line: %s" % line)
			return

		# Skip any lines that are for stats only
		if country_code == "*":
			return

		if type in ("ipv6", "ipv4"):
			return self._parse_ip_line(country_code, type, line)

	def _parse_ip_line(self, country, type, line):
		try:
			address, prefix, date, status, organization = line.split("|")
		except ValueError:
			organization = None

			# Try parsing the line without organization
			try:
				address, prefix, date, status = line.split("|")
			except ValueError:
				log.warning("Unhandled line format: %s" % line)
				return

		# Skip anything that isn't properly assigned
		if not status in ("assigned", "allocated"):
			return

		# Cast prefix into an integer
		try:
			prefix = int(prefix)
		except:
			log.warning("Invalid prefix: %s" % prefix)
			return

		# Fix prefix length for IPv4
		if type == "ipv4":
			prefix = 32 - int(math.log(prefix, 2))

		# Try to parse the address
		try:
			network = ipaddress.ip_network("%s/%s" % (address, prefix), strict=False)
		except ValueError:
			log.warning("Invalid IP address: %s" % address)
			return

		self.db.execute("INSERT INTO networks(network, country) \
			VALUES(%s, %s) ON CONFLICT (network) DO \
			UPDATE SET country = excluded.country",
			"%s" % network, country,
		)

	def handle_update_announcements(self, ns):
		server = ns.server[0]

		with self.db.transaction():
			if server.startswith("/"):
				self._handle_update_announcements_from_bird(server)
			else:
				self._handle_update_announcements_from_telnet(server)

			# Purge anything we never want here
			self.db.execute("""
				-- Delete default routes
				DELETE FROM announcements WHERE network = '::/0' OR network = '0.0.0.0/0';

				-- Delete anything that is not global unicast address space
				DELETE FROM announcements WHERE family(network) = 6 AND NOT network <<= '2000::/3';

				-- DELETE "current network" address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '0.0.0.0/8';

				-- DELETE local loopback address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '127.0.0.0/8';

				-- DELETE RFC 1918 address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '10.0.0.0/8';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '172.16.0.0/12';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '192.168.0.0/16';

				-- DELETE test, benchmark and documentation address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '192.0.0.0/24';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '192.0.2.0/24';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '198.18.0.0/15';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '198.51.100.0/24';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '203.0.113.0/24';

				-- DELETE CGNAT address space (RFC 6598)
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '100.64.0.0/10';

				-- DELETE link local address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '169.254.0.0/16';

				-- DELETE IPv6 to IPv4 (6to4) address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '192.88.99.0/24';

				-- DELETE multicast and reserved address space
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '224.0.0.0/4';
				DELETE FROM announcements WHERE family(network) = 4 AND network <<= '240.0.0.0/4';

				-- Delete networks that are too small to be in the global routing table
				DELETE FROM announcements WHERE family(network) = 6 AND masklen(network) > 48;
				DELETE FROM announcements WHERE family(network) = 4 AND masklen(network) > 24;

				-- Delete any non-public or reserved ASNs
				DELETE FROM announcements WHERE NOT (
					(autnum >= 1 AND autnum <= 23455)
					OR
					(autnum >= 23457 AND autnum <= 64495)
					OR
					(autnum >= 131072 AND autnum <= 4199999999)
				);

				-- Delete everything that we have not seen for 14 days
				DELETE FROM announcements WHERE last_seen_at <= CURRENT_TIMESTAMP - INTERVAL '14 days';
			""")

	def _handle_update_announcements_from_bird(self, server):
		# Pre-compile the regular expression for faster searching
		route = re.compile(b"^\s(.+?)\s+.+?\[AS(.*?).\]$")

		log.info("Requesting routing table from Bird (%s)" % server)

		# Send command to list all routes
		for line in self._bird_cmd(server, "show route"):
			m = route.match(line)
			if not m:
				log.debug("Could not parse line: %s" % line.decode())
				continue

			# Fetch the extracted network and ASN
			network, autnum = m.groups()

			# Insert it into the database
			self.db.execute("INSERT INTO announcements(network, autnum) \
				VALUES(%s, %s) ON CONFLICT (network) DO \
				UPDATE SET autnum = excluded.autnum, last_seen_at = CURRENT_TIMESTAMP",
				network.decode(), autnum.decode(),
			)

	def _handle_update_announcements_from_telnet(self, server):
		# Pre-compile regular expression for routes
		route = re.compile(b"^\*[\s\>]i([^\s]+).+?(\d+)\si\r\n", re.MULTILINE|re.DOTALL)

		with telnetlib.Telnet(server) as t:
			# Enable debug mode
			#if ns.debug:
			#	t.set_debuglevel(10)

			# Wait for console greeting
			greeting = t.read_until(b"> ", timeout=30)
			if not greeting:
				log.error("Could not get a console prompt")
				return 1

			# Disable pagination
			t.write(b"terminal length 0\n")

			# Wait for the prompt to return
			t.read_until(b"> ")

			# Fetch the routing tables
			for protocol in ("ipv6", "ipv4"):
				log.info("Requesting %s routing table" % protocol)

				# Request the full unicast routing table
				t.write(b"show bgp %s unicast\n" % protocol.encode())

				# Read entire header which ends with "Path"
				t.read_until(b"Path\r\n")

				while True:
					# Try reading a full entry
					# Those might be broken across multiple lines but ends with i
					line = t.read_until(b"i\r\n", timeout=5)
					if not line:
						break

					# Show line for debugging
					#log.debug(repr(line))

					# Try finding a route in here
					m = route.match(line)
					if m:
						network, autnum = m.groups()

						# Convert network to string
						network = network.decode()

						# Append /24 for IPv4 addresses
						if not "/" in network and not ":" in network:
							network = "%s/24" % network

						# Convert AS number to integer
						autnum = int(autnum)

						log.info("Found announcement for %s by %s" % (network, autnum))

						self.db.execute("INSERT INTO announcements(network, autnum) \
							VALUES(%s, %s) ON CONFLICT (network) DO \
							UPDATE SET autnum = excluded.autnum, last_seen_at = CURRENT_TIMESTAMP",
							network, autnum,
						)

				log.info("Finished reading the %s routing table" % protocol)

	def _bird_cmd(self, socket_path, command):
		# Connect to the socket
		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		s.connect(socket_path)

		# Allocate some buffer
		buffer = b""

		# Send the command
		s.send(b"%s\n" % command.encode())

		while True:
			# Fill up the buffer
			buffer += s.recv(4096)

			while True:
				# Search for the next newline
				pos = buffer.find(b"\n")

				# If we cannot find one, we go back and read more data
				if pos <= 0:
					break

				# Cut after the newline character
				pos += 1

				# Split the line we want and keep the rest in buffer
				line, buffer = buffer[:pos], buffer[pos:]

				# Look for the end-of-output indicator
				if line == b"0000 \n":
					return

				# Otherwise return the line
				yield line

	def handle_update_overrides(self, ns):
		with self.db.transaction():
			# Drop all data that we have
			self.db.execute("""
				TRUNCATE TABLE autnum_overrides;
				TRUNCATE TABLE network_overrides;
			""")

			for file in ns.files:
				log.info("Reading %s..." % file)

				with open(file, "rb") as f:
					for type, block in location.importer.read_blocks(f):
						if type == "net":
							network = block.get("net")
							# Try to parse and normalise the network
							try:
								network = ipaddress.ip_network(network, strict=False)
							except ValueError as e:
								log.warning("Invalid IP network: %s: %s" % (network, e))
								continue

							# Prevent that we overwrite all networks
							if network.prefixlen == 0:
								log.warning("Skipping %s: You cannot overwrite default" % network)
								continue

							self.db.execute("""
								INSERT INTO network_overrides(
									network,
									country,
									is_anonymous_proxy,
									is_satellite_provider,
									is_anycast
								) VALUES (%s, %s, %s, %s, %s)
								ON CONFLICT (network) DO NOTHING""",
								"%s" % network,
								block.get("country"),
								self._parse_bool(block, "is-anonymous-proxy"),
								self._parse_bool(block, "is-satellite-provider"),
								self._parse_bool(block, "is-anycast"),
							)

						elif type == "aut-num":
							autnum = block.get("aut-num")

							# Check if AS number begins with "AS"
							if not autnum.startswith("AS"):
								log.warning("Invalid AS number: %s" % autnum)
								continue

							# Strip "AS"
							autnum = autnum[2:]

							self.db.execute("""
								INSERT INTO autnum_overrides(
									number,
									name,
									country,
									is_anonymous_proxy,
									is_satellite_provider,
									is_anycast
								) VALUES(%s, %s, %s, %s, %s, %s)
								ON CONFLICT DO NOTHING""",
								autnum,
								block.get("name"),
								block.get("country"),
								self._parse_bool(block, "is-anonymous-proxy"),
								self._parse_bool(block, "is-satellite-provider"),
								self._parse_bool(block, "is-anycast"),
							)

						else:
							log.warning("Unsupport type: %s" % type)

	@staticmethod
	def _parse_bool(block, key):
		val = block.get(key)

		# There is no point to proceed when we got None
		if val is None:
			return

		# Convert to lowercase
		val = val.lower()

		# True
		if val in ("yes", "1"):
			return True

		# False
		if val in ("no", "0"):
			return False

		# Default to None
		return None

	def handle_import_countries(self, ns):
		with self.db.transaction():
			# Drop all data that we have
			self.db.execute("TRUNCATE TABLE countries")

			for file in ns.file:
				for line in file:
					line = line.rstrip()

					# Ignore any comments
					if line.startswith("#"):
						continue

					try:
						country_code, continent_code, name = line.split(maxsplit=2)
					except:
						log.warning("Could not parse line: %s" % line)
						continue

					self.db.execute("INSERT INTO countries(country_code, name, continent_code) \
						VALUES(%s, %s, %s) ON CONFLICT DO NOTHING", country_code, name, continent_code)


def split_line(line):
	key, colon, val = line.partition(":")

	# Strip any excess space
	key = key.strip()
	val = val.strip()

	return key, val

def main():
	# Run the command line interface
	c = CLI()
	c.run()

main()