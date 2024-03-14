#!/usr/bin/lua
--[[###########################################################################
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
############################################################################--]]

luaunit = require("luaunit")

ENV_TEST_DATABASE    = os.getenv("TEST_DATABASE")
ENV_TEST_SIGNING_KEY = os.getenv("TEST_SIGNING_KEY")

function test_load()
	-- Try loading the module
	location = require("location")

	-- Print the version
	print(location.version())
end

function test_open_database()
	location = require("location")

	-- Open the database
	db = location.Database.open(ENV_TEST_DATABASE)

	-- Verify
	-- luaunit.assertIsTrue(db:verify(ENV_TEST_SIGNING_KEY))

	-- Description
	luaunit.assertIsString(db:get_description())

	-- License
	luaunit.assertIsString(db:get_license())
	luaunit.assertEquals(db:get_license(), "CC BY-SA 4.0")

	-- Vendor
	luaunit.assertIsString(db:get_vendor())
	luaunit.assertEquals(db:get_vendor(), "IPFire Project")
end

function test_lookup()
	location = require("location")

	-- Open the database
	db = location.Database.open(ENV_TEST_DATABASE)

	-- Perform a lookup
	network1 = db:lookup("81.3.27.32")

	luaunit.assertEquals(network1:get_family(), 2) -- AF_INET
	luaunit.assertEquals(network1:get_country_code(), "DE")
	luaunit.assertEquals(network1:get_asn(), 24679)

	-- Lookup something else
	network2 = db:lookup("8.8.8.8")
	luaunit.assertIsTrue(network2:has_flag(location.NETWORK_FLAG_ANYCAST))
	luaunit.assertIsFalse(network2:has_flag(location.NETWORK_FLAG_DROP))
end

function test_network()
	location = require("location")

	n1 = location.Network.new("10.0.0.0/8")

	-- The ASN should be nul
	luaunit.assertNil(n1:get_asn())

	-- The family should be IPv4
	luaunit.assertEquals(n1:get_family(), 2) -- AF_INET

	-- The country code should be empty
	luaunit.assertNil(n1:get_country_code())
end

function test_as()
	location = require("location")

	-- Create a new AS
	as = location.AS.new(12345)
	luaunit.assertEquals(as:get_number(), 12345)
	luaunit.assertNil(as:get_name())

	-- Reset
	as = nil
end

function test_fetch_as()
	location = require("location")

	-- Open the database
	db = location.Database.open(ENV_TEST_DATABASE)

	-- Fetch an AS
	as = db:get_as(0)

	-- This should not exist
	luaunit.assertNil(as)

	-- Fetch something that exists
	as = db:get_as(204867)
	luaunit.assertEquals(as:get_number(), 204867)
	luaunit.assertEquals(as:get_name(), "Lightning Wire Labs GmbH")
end

function test_country()
	location = require("location")

	c1 = location.Country.new("DE")
	luaunit.assertEquals(c1:get_code(), "DE")
	luaunit.assertNil(c1:get_name())
	luaunit.assertNil(c1:get_continent_code())

	c2 = location.Country.new("GB")
	luaunit.assertNotEquals(c1, c2)

	c1 = nil
	c2 = nil
end

function test_fetch_country()
	location = require("location")

	-- Open the database
	db = location.Database.open(ENV_TEST_DATABASE)

	-- Fetch an invalid country
	c = db:get_country("XX")
	luaunit.assertNil(c)

	-- Fetch something that exists
	c = db:get_country("DE")
	luaunit.assertEquals(c:get_code(), "DE")
	luaunit.assertEquals(c:get_name(), "Germany")
end

-- This test is not very deterministic but should help to test the GC methods
function test_gc()
	print("GC: " .. collectgarbage("collect"))
end

os.exit(luaunit.LuaUnit.run())
