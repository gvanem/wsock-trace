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

static void loc_address_from_address4(struct in6_addr* address,
		const struct in_addr* address4) {
	IN6_DWORD(address, 0) = 0;
	IN6_DWORD(address, 1) = 0;
	IN6_DWORD(address, 2) = htonl(0xffff);
	IN6_DWORD(address, 3) = address4->s_addr;
}

int loc_address_parse(struct in6_addr* address, unsigned int* prefix, const char* string) {
	char buffer[INET6_ADDRSTRLEN + 4];
	int r;

	if (!address || !string) {
		errno = EINVAL;
		return 1;
	}

	// Copy the string into the buffer
	r = snprintf(buffer, sizeof(buffer) - 1, "%s", string);
	if (r < 0)
		return 1;

	// Find /
	char* p = strchr(buffer, '/');
	if (p) {
		// Terminate the IP address
		*p++ = '\0';
	}

	int family = AF_UNSPEC;

	// Try parsing as an IPv6 address
	r = inet_pton(AF_INET6, buffer, address);
	switch (r) {
		// This is not a valid IPv6 address
		case 0:
			break;

		// This is a valid IPv6 address
		case 1:
			family = AF_INET6;
			break;

		// Unexpected error
		default:
			return 1;
	}

	// Try parsing as an IPv4 address
	if (!family) {
		struct in_addr address4;

		r = inet_pton(AF_INET, buffer, &address4);
		switch (r) {
			// This was not a valid IPv4 address
			case 0:
				break;

			// This was a valid IPv4 address
			case 1:
				family = AF_INET;

				// Copy the result
				loc_address_from_address4(address, &address4);
				break;

			// Unexpected error
			default:
				return 1;
		}
	}

	// Invalid input
	if (family == AF_UNSPEC) {
		errno = EINVAL;
		return 1;
	}

	// Did the user request a prefix?
	if (prefix) {
		// Set the prefix to the default value
		const unsigned int max_prefix = loc_address_family_bit_length(family);

		// Parse the actual string
		if (p) {
			*prefix = strtol(p, NULL, 10);

			// Check if prefix is within bounds
			if (*prefix > max_prefix) {
				errno = EINVAL;
				return 1;
			}

		// If the string didn't contain a prefix, we set the maximum
		} else {
			*prefix = max_prefix;
		}
	}

	return 0;
}
