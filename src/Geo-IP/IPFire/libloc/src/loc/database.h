/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#ifndef LIBLOC_DATABASE_H
#define LIBLOC_DATABASE_H

#include <stdio.h>
#include <stdint.h>

#include <loc/libloc.h>
#include <loc/network.h>
#include <loc/as.h>
#include <loc/country.h>

struct loc_database;
int loc_database_new(struct loc_ctx* ctx, struct loc_database** database, FILE* f);
struct loc_database* loc_database_ref(struct loc_database* db);
struct loc_database* loc_database_unref(struct loc_database* db);

int loc_database_verify(struct loc_database* db, FILE* f);

time_t loc_database_created_at(struct loc_database* db);
const char* loc_database_get_vendor(struct loc_database* db);
const char* loc_database_get_description(struct loc_database* db);
const char* loc_database_get_license(struct loc_database* db);

int loc_database_get_as(struct loc_database* db, struct loc_as** as, uint32_t number);
size_t loc_database_count_as(struct loc_database* db);

int loc_database_lookup(struct loc_database* db,
		struct in6_addr* address, struct loc_network** network);
int loc_database_lookup_from_string(struct loc_database* db,
		const char* string, struct loc_network** network);

int loc_database_get_country(struct loc_database* db,
		struct loc_country** country, const char* code);

enum loc_database_enumerator_mode {
	LOC_DB_ENUMERATE_NETWORKS  = 1,
	LOC_DB_ENUMERATE_ASES      = 2,
	LOC_DB_ENUMERATE_COUNTRIES = 3,
};

struct loc_database_enumerator;
int loc_database_enumerator_new(struct loc_database_enumerator** enumerator,
	struct loc_database* db, enum loc_database_enumerator_mode mode);
struct loc_database_enumerator* loc_database_enumerator_ref(struct loc_database_enumerator* enumerator);
struct loc_database_enumerator* loc_database_enumerator_unref(struct loc_database_enumerator* enumerator);

int loc_database_enumerator_set_string(struct loc_database_enumerator* enumerator, const char* string);
int loc_database_enumerator_set_country_code(struct loc_database_enumerator* enumerator, const char* country_code);
int loc_database_enumerator_set_asn(struct loc_database_enumerator* enumerator, unsigned int asn);
int loc_database_enumerator_set_flag(struct loc_database_enumerator* enumerator, enum loc_network_flags flag);
int loc_database_enumerator_set_family(struct loc_database_enumerator* enumerator, int family);
int loc_database_enumerator_next_as(
	struct loc_database_enumerator* enumerator, struct loc_as** as);
int loc_database_enumerator_next_network(
	struct loc_database_enumerator* enumerator, struct loc_network** network);
int loc_database_enumerator_next_country(
	struct loc_database_enumerator* enumerator, struct loc_country** country);

#endif
