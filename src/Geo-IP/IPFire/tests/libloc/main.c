/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017 IPFire Development Team <info@ipfire.org>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

#include <libloc/libloc.h>

// The log priority can be set in the environment
static int test_log_priority(const char* value, int expected) {
	struct loc_ctx* ctx = NULL;
	int r;

	setenv("LOC_LOG", value, 1);

	r = loc_new(&ctx);
	if (r)
		return r;

	if (loc_get_log_priority(ctx) != expected) {
		fprintf(stderr, "LOC_LOG=%s set the log priority to %d instead of %d\n",
			value, loc_get_log_priority(ctx), expected);
		r = -EINVAL;
	}

	loc_unref(ctx);
	unsetenv("LOC_LOG");

	return r;
}

int main(int argc, char** argv) {
	struct loc_ctx *ctx;

	int err = loc_new(&ctx);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Enable debug logging
	loc_set_log_priority(ctx, LOG_DEBUG);

	printf("version %s\n", VERSION);

	if (test_log_priority("debug", LOG_DEBUG)
			|| test_log_priority("info", LOG_INFO)
			|| test_log_priority("err", LOG_ERR)
			|| test_log_priority("7", LOG_DEBUG)
			|| test_log_priority("3", LOG_ERR))
		exit(EXIT_FAILURE);

	loc_unref(ctx);
	return EXIT_SUCCESS;
}
