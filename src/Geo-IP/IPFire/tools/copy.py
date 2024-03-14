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

import argparse

import location
from location.i18n import _

flags = (
	location.NETWORK_FLAG_ANONYMOUS_PROXY,
	location.NETWORK_FLAG_SATELLITE_PROVIDER,
	location.NETWORK_FLAG_ANYCAST,
	location.NETWORK_FLAG_DROP,
)

def copy_all(db, writer):
	# Copy vendor
	if db.vendor:
		writer.vendor = db.vendor

	# Copy description
	if db.description:
		writer.description = db.description

	# Copy license
	if db.license:
		writer.license = db.license

	# Copy all ASes
	for old in db.ases:
		new = writer.add_as(old.number)
		new.name = old.name

	# Copy all networks
	for old in db.networks:
		new = writer.add_network("%s" % old)

		# Copy country code
		new.country_code = old.country_code

		# Copy ASN
		if old.asn:
			new.asn = old.asn

		# Copy flags
		for flag in flags:
			if old.has_flag(flag):
				new.set_flag(flag)

	# Copy countries
	for old in db.countries:
		new = writer.add_country(old.code)

		# Copy continent code
		new.continent_code = old.continent_code

		# Copy name
		new.name = old.name

def main():
	"""
		Main Function
	"""
	parser = argparse.ArgumentParser(
		description=_("Copies a location database"),
	)

	# Input File
	parser.add_argument("input-file", help=_("File to read"))

	# Output File
	parser.add_argument("output-file", help=_("File to write"))

	# Parse arguments
	args = parser.parse_args()

	input_file  = getattr(args, "input-file")
	output_file = getattr(args, "output-file")

	# Open the database
	db = location.Database(input_file)

	# Create a new writer
	writer = location.Writer()

	# Copy everything
	copy_all(db, writer)

	# Write the new file
	writer.write(output_file)

main()
