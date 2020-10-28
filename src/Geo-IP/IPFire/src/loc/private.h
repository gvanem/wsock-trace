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

#ifndef LIBLOC_PRIVATE_H
#define LIBLOC_PRIVATE_H

#ifdef LIBLOC_PRIVATE

#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>
#include <loc/libloc.h>

#if !defined(__GNUC__) && !defined(__clang__) && !defined(__attribute__)
#define __attribute__(x)
#endif

static inline void __attribute__((always_inline, format(printf, 2, 3)))
loc_log_null(struct loc_ctx *ctx, const char *format, ...) {}

#define loc_log_cond(ctx, prio, ...) \
	do { \
		if (loc_get_log_priority(ctx) >= prio) \
			loc_log(ctx, prio, __FILE__, __LINE__, __FUNCTION__,  ## __VA_ARGS__); \
	} while (0)

#undef INFO   /* Some of these are in some Windows SDK headers too */
#undef ERROR
#undef DEBUG

#ifdef ENABLE_DEBUG
#  define DEBUG(ctx, ...) loc_log_cond(ctx, LOG_DEBUG, ## __VA_ARGS__)
#else
#  define DEBUG(ctx, ...) loc_log_null(ctx, ## __VA_ARGS__)
#endif

#define INFO(ctx, ...) loc_log_cond(ctx, LOG_INFO, ## __VA_ARGS__)
#define ERROR(ctx, ...) loc_log_cond(ctx, LOG_ERR, ## __VA_ARGS__)

#ifndef HAVE_SECURE_GETENV
#  ifdef HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    define secure_getenv getenv
#  endif
#endif

#define LOC_EXPORT __attribute__ ((visibility("default")))

void loc_log(struct loc_ctx *ctx,
	int priority, const char *file, int line, const char *fn,
	const char *format, ...) __attribute__((format(printf, 6, 7)));

static inline int in6_addr_cmp(const struct in6_addr* a1, const struct in6_addr* a2) {
	for (unsigned int i = 0; i < 16; i++) {
		if (a1->s6_addr[i] > a2->s6_addr[i])
			return 1;

		else if (a1->s6_addr[i] < a2->s6_addr[i])
			return -1;
	}

	return 0;
}

static inline int in6_addr_get_bit(const struct in6_addr* address, unsigned int i) {
	return ((address->s6_addr[i / 8] >> (7 - (i % 8))) & 1);
}

static inline void in6_addr_set_bit(struct in6_addr* address, unsigned int i, unsigned int val) {
	address->s6_addr[i / 8] ^= (-val ^ address->s6_addr[i / 8]) & (1 << (7 - (i % 8)));
}

static inline void hexdump(struct loc_ctx* ctx, const void* addr, size_t len) {
	char buffer_hex[16 * 3 + 6];
	char buffer_ascii[17];

	unsigned int i = 0;
	unsigned char* p = (unsigned char*)addr;

	DEBUG(ctx, "Dumping %zu byte(s)\n", len);

	// Process every byte in the data
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset)
		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line
			if (i != 0)
				DEBUG(ctx, "  %s %s\n", buffer_hex, buffer_ascii);

			// Output the offset.
			sprintf(buffer_hex, "%04x ", i);
		}

		// Now the hex code for the specific character
		sprintf(buffer_hex + 5 + ((i % 16) * 3), " %02x", p[i]);

		// And store a printable ASCII character for later
		if ((p[i] < 0x20) || (p[i] > 0x7e))
			buffer_ascii[i % 16] = '.';
		else
			buffer_ascii[i % 16] = p[i];

		// Terminate string
		buffer_ascii[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters
	while ((i % 16) != 0) {
		sprintf(buffer_hex + 5 + ((i % 16) * 3), "   ");
		i++;
	}

	// And print the final bit
	DEBUG(ctx, "  %s %s\n", buffer_hex, buffer_ascii);
}

#endif
#endif
