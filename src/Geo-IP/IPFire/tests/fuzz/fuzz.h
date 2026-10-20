/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2026 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#ifndef LIBLOC_TESTS_FUZZ_H
#define LIBLOC_TESTS_FUZZ_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libloc/libloc.h>

/*
	Everything that the fuzzers need, and what we only want to set up once.
*/
static struct loc_ctx* fuzz_ctx = NULL;

static void fuzz_log(struct loc_ctx* ctx, void* data, int priority, const char* file,
		int line, const char* fn, const char* format, va_list args) {
	// Don't log anything, it would only slow us down
}

static inline int fuzz_setup(void) {
	int r;

	// Create a context
	r = loc_new(&fuzz_ctx);
	if (r < 0)
		return r;

	// Be quiet
	loc_set_log_callback(fuzz_ctx, fuzz_log, NULL);

	return 0;
}

// These are being called by the fuzzing engine
int LLVMFuzzerInitialize(int* argc, char*** argv);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int LLVMFuzzerInitialize(int* argc, char*** argv) {
	int r;

	r = fuzz_setup();
	if (r < 0) {
		fprintf(stderr, "Could not set up the fuzzer: %s\n", strerror(-r));
		exit(1);
	}

	return 0;
}

#endif /* LIBLOC_TESTS_FUZZ_H */
