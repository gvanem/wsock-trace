/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2022 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <stddef.h>

#include <libloc/libloc.h>
#include <libloc/address.h>

#define LOC_ADDRESS_BUFFERS				6
#define LOC_ADDRESS_BUFFER_LENGTH		INET6_ADDRSTRLEN

static char __loc_address_buffers[LOC_ADDRESS_BUFFERS][LOC_ADDRESS_BUFFER_LENGTH + 1];
static int  __loc_address_buffer_idx = 0;

static const char* __loc_address6_str(const struct in6_addr* address, char* buffer, size_t length) {
	return inet_ntop(AF_INET6, address, buffer, length);
}

static const char* __loc_address4_str(const struct in6_addr* address, char* buffer, size_t length) {
	struct in_addr address4 = {
		.s_addr = IN6_DWORD(address, 3),
	};

	return inet_ntop(AF_INET, &address4, buffer, length);
}

const char* loc_address_str(const struct in6_addr* address) {
	if (!address)
		return NULL;

	// Select buffer
	char* buffer = __loc_address_buffers[__loc_address_buffer_idx++];

	// Prevent index from overflow
	__loc_address_buffer_idx %= LOC_ADDRESS_BUFFERS;

	if (IN6_IS_ADDR_V4MAPPED(address))
		return __loc_address4_str(address, buffer, LOC_ADDRESS_BUFFER_LENGTH);
	else
		return __loc_address6_str(address, buffer, LOC_ADDRESS_BUFFER_LENGTH);
}
