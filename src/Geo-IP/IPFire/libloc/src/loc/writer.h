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

#ifndef LIBLOC_WRITER_H
#define LIBLOC_WRITER_H

#include <stdio.h>

#include <loc/libloc.h>
#include <loc/as.h>
#include <loc/country.h>
#include <loc/database.h>
#include <loc/network.h>

struct loc_writer;

int loc_writer_new(struct loc_ctx* ctx, struct loc_writer** writer,
    FILE* fkey1, FILE* fkey2);

struct loc_writer* loc_writer_ref(struct loc_writer* writer);
struct loc_writer* loc_writer_unref(struct loc_writer* writer);

const char* loc_writer_get_vendor(struct loc_writer* writer);
int loc_writer_set_vendor(struct loc_writer* writer, const char* vendor);
const char* loc_writer_get_description(struct loc_writer* writer);
int loc_writer_set_description(struct loc_writer* writer, const char* description);
const char* loc_writer_get_license(struct loc_writer* writer);
int loc_writer_set_license(struct loc_writer* writer, const char* license);

int loc_writer_add_as(struct loc_writer* writer, struct loc_as** as, uint32_t number);
int loc_writer_add_network(struct loc_writer* writer, struct loc_network** network, const char* string);
int loc_writer_add_country(struct loc_writer* writer, struct loc_country** country, const char* country_code);

int loc_writer_write(struct loc_writer* writer, FILE* f, enum loc_database_version);

#endif
