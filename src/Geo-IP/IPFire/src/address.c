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

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/compat.h>

#ifdef _WIN32
  #undef  errno
  #define errno WSAGetLastError()
#endif

const char* loc_address_format(const struct in6_addr* address, char* buffer, size_t length) {
	if (!address || !buffer)
		return NULL;

	// IPv4 addresses are being formatted like IPv4 addresses
	if (IN6_IS_ADDR_V4MAPPED(address)) {
		struct in_addr address4 = {
			.s_addr = IN6_DWORD(address, 3),
		};

		return inet_ntop(AF_INET, &address4, buffer, length);
	}

	return inet_ntop(AF_INET6, address, buffer, length);
}

static void loc_address_from_address4(struct in6_addr* address,
		const struct in_addr* address4) {
	IN6_DWORD(address, 0) = 0;
	IN6_DWORD(address, 1) = 0;
	IN6_DWORD(address, 2) = htonl(0xffff);
	IN6_DWORD(address, 3) = address4->s_addr;
}

int loc_address_parse(struct in6_addr* address, unsigned int* prefix, const char* string) {
	// The longest address, a slash, and a prefix of up to three digits
	char buffer[INET6_ADDRSTRLEN + 4];
	char* end = NULL;
	int r;

	if (!address || !string)
		return -EINVAL;

	// Anything that is longer than our buffer cannot be valid
	size_t length = strnlen(string, sizeof(buffer));
	if (length >= sizeof(buffer))
		return -EINVAL;

	// Copy the string into the buffer
	memcpy(buffer, string, length + 1);

	// Find /
	char* p = strchr(buffer, '/');
	if (p) {
		// Terminate the IP address
		*p++ = '\0';
	}

	int family = AF_UNSPEC;

	// Try parsing as an IPv6 address, which always has a colon
	if (strchr(buffer, ':')) {
		r = inet_pton(AF_INET6, buffer, address);
		switch (r) {
			// This is not a valid IPv6 address
			case 0:
				break;

			// This is a valid IPv6 address (or an IPv4 address that has been mapped)
			case 1:
				family = loc_address_family(address);
				break;

			// Unexpected error
			default:
				return -errno;
		}
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
				return -errno;
		}
	}

	// Invalid input
	if (family == AF_UNSPEC)
		return -EINVAL;

	// The longest prefix that an address of this family can have
	const unsigned int max_prefix = loc_address_family_bit_length(family);

	// If the string didn't contain a prefix, we set the maximum
	unsigned long value = max_prefix;

	// Parse the prefix, even if the caller does not want to know what it is
	if (p) {
		// The prefix must be a number and nothing else
		if (!isdigit((unsigned char)*p))
			return -EINVAL;

		value = strtoul(p, &end, 10);
		if (*end)
			return -EINVAL;

		// Check if prefix is within bounds
		if (value > max_prefix)
			return -EINVAL;
	}

	// Did the user request a prefix?
	if (prefix)
		*prefix = value;

	return 0;
}
