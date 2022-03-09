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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/compat.h>
#include <libloc/private.h>

#ifdef _WIN32
#include <openssl/evp.h>
#include <openssl/applink.c>
#endif

struct loc_ctx {
	int refcount;
	void (*log_fn)(struct loc_ctx* ctx,
		int priority, const char *file, int line, const char *fn,
		const char *format, va_list args);
	int log_priority;
};

void loc_log(struct loc_ctx* ctx,
		int priority, const char* file, int line, const char* fn,
		const char* format, ...) {
	va_list args;

	va_start(args, format);
	ctx->log_fn(ctx, priority, file, line, fn, format, args);
	va_end(args);
}

static void log_stderr(struct loc_ctx* ctx,
		int priority, const char* file, int line, const char* fn,
		const char* format, va_list args) {
	fprintf(stderr, "libloc: %s(): ", fn);
	vfprintf(stderr, format, args);
}

static int log_priority(const char* priority) {
	char *endptr;

	int prio = strtol(priority, &endptr, 10);

	if (endptr[0] == '\0' || isspace((int)endptr[0]))
		return prio;

	if (strncmp(priority, "err", 3) == 0)
		return LOG_ERR;

	if (strncmp(priority, "info", 4) == 0)
		return LOG_INFO;

	if (strncmp(priority, "debug", 5) == 0)
		return LOG_DEBUG;

	return 0;
}

LOC_EXPORT int loc_new(struct loc_ctx** ctx) {
	struct loc_ctx* c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->refcount = 1;
	c->log_fn = log_stderr;
	c->log_priority = LOG_ERR;

#ifdef _WIN32
	// Start Winsock if not done
	static int done = 0;
	WSADATA wsa;

	if (!done) {
		WSAStartup(MAKEWORD(2,2), &wsa);
		OpenSSL_add_all_algorithms();
		done = 1;
	}

	const char* env = NULL;
	char buf[20];
	if (GetEnvironmentVariable("LOC_LOG", buf, sizeof(buf)))
		env = buf;
#else
	const char* env = secure_getenv("LOC_LOG");
#endif
	if (env)
		loc_set_log_priority(c, log_priority(env));

	INFO(c, "ctx %p created\n", c);
	DEBUG(c, "log_priority=%d\n", c->log_priority);
	*ctx = c;

	return 0;
}

LOC_EXPORT struct loc_ctx* loc_ref(struct loc_ctx* ctx) {
	if (!ctx)
		return NULL;

	ctx->refcount++;

	return ctx;
}

LOC_EXPORT struct loc_ctx* loc_unref(struct loc_ctx* ctx) {
	if (!ctx)
		return NULL;

	if (--ctx->refcount > 0)
		return NULL;

	INFO(ctx, "context %p released\n", ctx);
	free(ctx);

	return NULL;
}

LOC_EXPORT void loc_set_log_fn(struct loc_ctx* ctx,
		void (*log_fn)(struct loc_ctx* ctx, int priority, const char* file,
		int line, const char* fn, const char* format, va_list args)) {
	ctx->log_fn = log_fn;
	INFO(ctx, "custom logging function %p registered\n", log_fn);
}

LOC_EXPORT int loc_get_log_priority(struct loc_ctx* ctx) {
	return ctx->log_priority;
}

LOC_EXPORT void loc_set_log_priority(struct loc_ctx* ctx, int priority) {
	ctx->log_priority = priority;
}

LOC_EXPORT int loc_parse_address(struct loc_ctx* ctx, const char* string, struct in6_addr* address) {
	DEBUG(ctx, "Parsing IP address %s\n", string);

	// Try parsing this as an IPv6 address
	int r = inet_pton(AF_INET6, string, address);

	// If inet_pton returns one it has been successful
	if (r == 1) {
		DEBUG(ctx, "%s is an IPv6 address\n", string);
		return 0;
	}

	// Try parsing this as an IPv4 address
	struct in_addr ipv4_address;
	r = inet_pton(AF_INET, string, &ipv4_address);
	if (r == 1) {
		DEBUG(ctx, "%s is an IPv4 address\n", string);

		// Convert to IPv6-mapped address
		IN6_DWORD(address, 0) = 0;
		IN6_DWORD(address, 1) = 0;
		IN6_DWORD(address, 2) = htonl(0xffff);
		IN6_DWORD(address, 3) = ipv4_address.s_addr;

		return 0;
	}

	DEBUG(ctx, "%s is not an valid IP address\n", string);
	return -EINVAL;
}
