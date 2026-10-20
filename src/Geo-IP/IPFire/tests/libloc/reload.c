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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libloc/libloc.h>
#include <libloc/database.h>
#include <libloc/network.h>
#include <libloc/writer.h>

/*
	Opens a database by its path, and replaces the file while it is being used
*/

// Where the databases of this test are
static char directory[] = "/tmp/libloc-test-reload.XXXXXX";
static char path[sizeof(directory) + 32];

/*
	Writes a database with one network to a temporary file
	and moves it to where the database is supposed to be.
*/
static int write_database_to(struct loc_ctx* ctx, const char* destination,
		const char* network, const char* country_code) {
	struct loc_writer* writer = NULL;
	struct loc_network* n = NULL;
	char tmp[sizeof(path) + 8];
	FILE* f = NULL;
	int r;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	r = loc_writer_new(ctx, &writer, NULL, NULL);
	if (r)
		return r;

	r = loc_writer_set_vendor(writer, country_code);
	if (r)
		goto ERROR;

	r = loc_writer_add_network(writer, &n, network);
	if (r)
		goto ERROR;

	r = loc_network_set_country_code(n, country_code);
	loc_network_unref(n);
	if (r)
		goto ERROR;

	f = fopen(tmp, "w+");
	if (!f) {
		r = -errno;
		goto ERROR;
	}

	r = loc_writer_write(writer, f, LOC_DATABASE_VERSION_UNSET);
	if (r)
		goto ERROR;

	fclose(f);
	f = NULL;

	// Replace the database like the updater does
	r = rename(tmp, destination);
	if (r)
		r = -errno;

ERROR:
	if (f)
		fclose(f);
	loc_writer_unref(writer);

	return r;
}

static int write_database(struct loc_ctx* ctx, const char* network, const char* country_code) {
	return write_database_to(ctx, path, network, country_code);
}

/*
	Looks up an address and checks which country it is in (NULL if it is not in the database)
*/
static int expect(struct loc_database* db, const char* address, const char* country_code) {
	struct loc_network* network = NULL;
	int r;

	r = loc_database_lookup_from_string(db, address, &network);
	if (r) {
		fprintf(stderr, "Could not look up %s: %s\n", address, strerror(-r));
		return 1;
	}

	const char* cc = NULL;

	if (network)
		cc = loc_network_get_country_code(network);

	if (!cc != !country_code || (cc && strcmp(cc, country_code) != 0)) {
		fprintf(stderr, "%s is in %s, but we expected %s\n", address, cc, country_code);
		r = 1;
	}

	if (network)
		loc_network_unref(network);

	return r;
}

static int test_open(struct loc_ctx* ctx) {
	struct loc_database* db = NULL;
	int r;

	// There is no database, yet
	r = loc_database_open(ctx, &db, path);
	if (r != -ENOENT) {
		fprintf(stderr, "Opening a database that does not exist returned %d\n", r);
		return 1;
	}

	r = loc_database_open(ctx, &db, NULL);
	if (r != -EINVAL) {
		fprintf(stderr, "Opening a database without a path returned %d\n", r);
		return 1;
	}

	// Create one
	r = write_database(ctx, "192.0.2.0/24", "DE");
	if (r) {
		fprintf(stderr, "Could not write the database: %s\n", strerror(-r));
		return 1;
	}

	r = loc_database_open(ctx, &db, path);
	if (r) {
		fprintf(stderr, "Could not open the database: %s\n", strerror(-r));
		return 1;
	}

	r = expect(db, "192.0.2.1", "DE") || expect(db, "198.51.100.1", NULL);

	loc_database_unref(db);

	return r;
}

static int test_reload(struct loc_ctx* ctx) {
	struct loc_database_enumerator* enumerator = NULL;
	struct loc_database* db = NULL;
	struct loc_network* network = NULL;
	FILE* f = NULL;
	int r;

	r = write_database(ctx, "192.0.2.0/24", "DE");
	if (r)
		return 1;

	// A database that has been opened from a file handle does not know where it is
	f = fopen(path, "r");
	if (!f)
		return 1;

	r = loc_database_new(ctx, &db, f);
	fclose(f);
	if (r)
		return 1;

	r = loc_database_reload(db);
	if (r != -ENOTSUP) {
		fprintf(stderr, "Reloading a database without a path returned %d\n", r);
		return 1;
	}

	loc_database_unref(db);

	r = loc_database_open(ctx, &db, path);
	if (r)
		return 1;

	// Nothing has changed
	r = loc_database_reload(db);
	if (r != 1) {
		fprintf(stderr, "Reloading a database that has not changed returned %d\n", r);
		return 1;
	}

	// Keep something from the old file
	const char* vendor = loc_database_get_vendor(db);

	r = loc_database_enumerator_new(&enumerator, db, LOC_DB_ENUMERATE_NETWORKS, 0);
	if (r)
		return 1;

	// Replace the database
	r = write_database(ctx, "198.51.100.0/24", "FR");
	if (r)
		return 1;

	// Nobody has told us, yet
	if (expect(db, "192.0.2.1", "DE") || expect(db, "198.51.100.1", NULL))
		return 1;

	r = loc_database_reload(db);
	if (r != 0) {
		fprintf(stderr, "Could not reload the database: %d\n", r);
		return 1;
	}

	// Now we have the new one
	if (expect(db, "192.0.2.1", NULL) || expect(db, "198.51.100.1", "FR"))
		return 1;

	// What we have got from the old file is still there
	if (!vendor || strcmp(vendor, "DE") != 0) {
		fprintf(stderr, "The vendor of the old database has changed: %s\n", vendor);
		return 1;
	}

	if (strcmp(loc_database_get_vendor(db), "FR") != 0) {
		fprintf(stderr, "The vendor of the new database is %s\n", loc_database_get_vendor(db));
		return 1;
	}

	// The enumerator still walks through the old file
	r = loc_database_enumerator_next_network(enumerator, &network);
	if (r || !network) {
		fprintf(stderr, "The enumerator did not return anything: %d\n", r);
		return 1;
	}

	if (strcmp(loc_network_str(network), "192.0.2.0/24") != 0) {
		fprintf(stderr, "The enumerator returned %s\n", loc_network_str(network));
		return 1;
	}

	loc_network_unref(network);
	loc_database_enumerator_unref(enumerator);

	// There is nothing new
	r = loc_database_reload(db);
	if (r != 1) {
		fprintf(stderr, "Reloading again returned %d\n", r);
		return 1;
	}

	// A file that everybody could have written must be refused
	r = write_database(ctx, "203.0.113.0/24", "GB");
	if (r)
		return 1;

	r = chmod(path, 0666);
	if (r)
		return 1;

	r = loc_database_reload(db);
	if (r != -EPERM) {
		fprintf(stderr, "Reloading a world-writable database returned %d\n", r);
		return 1;
	}

	if (expect(db, "198.51.100.1", "FR") || expect(db, "203.0.113.1", NULL))
		return 1;

	// It is being accepted as soon as that has been fixed
	r = chmod(path, 0644);
	if (r)
		return 1;

	r = loc_database_reload(db);
	if (r != 0) {
		fprintf(stderr, "Reloading returned %d after the permissions have been fixed\n", r);
		return 1;
	}

	if (expect(db, "203.0.113.1", "GB"))
		return 1;

	// A file that is not a database must not replace the one we have. It is being
	// moved into place like any other update, because the file that we have mapped
	// must never be written to.
	char tmp[sizeof(path) + 8];
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	f = fopen(tmp, "w");
	if (!f)
		return 1;

	fprintf(f, "This is not a database\n");
	fclose(f);

	r = rename(tmp, path);
	if (r)
		return 1;

	r = loc_database_reload(db);
	if (r >= 0) {
		fprintf(stderr, "Reloading something that is not a database returned %d\n", r);
		return 1;
	}

	if (expect(db, "203.0.113.1", "GB"))
		return 1;

	// The same if there is no file at all
	unlink(path);

	r = loc_database_reload(db);
	if (r != -ENOENT) {
		fprintf(stderr, "Reloading a database that is gone returned %d\n", r);
		return 1;
	}

	if (expect(db, "203.0.113.1", "GB"))
		return 1;

	loc_database_unref(db);

	return 0;
}

/*
	Waits for the database to find out on its own that it has been replaced
*/
static int test_automatic(struct loc_ctx* ctx) {
	struct loc_database* db = NULL;
	FILE* f = NULL;
	int r;

	r = write_database(ctx, "192.0.2.0/24", "DE");
	if (r)
		return 1;

	// A database that does not know where it is cannot check anything
	f = fopen(path, "r");
	if (!f)
		return 1;

	r = loc_database_new(ctx, &db, f);
	fclose(f);
	if (r)
		return 1;

	r = loc_database_set_reload_interval(db, 1);
	if (r != -ENOTSUP) {
		fprintf(stderr, "Setting the interval of a database without a path returned %d\n", r);
		return 1;
	}

	// But it may say that it does not want to
	r = loc_database_set_reload_interval(db, 0);
	if (r)
		return 1;

	loc_database_unref(db);

	r = loc_database_open(ctx, &db, path);
	if (r)
		return 1;

	// Check every second
	r = loc_database_set_reload_interval(db, 1);
	if (r)
		return 1;

	r = write_database(ctx, "198.51.100.0/24", "FR");
	if (r)
		return 1;

	// The clock that we use is not very accurate, so give it some time
	for (unsigned int i = 0; i < 50; i++) {
		usleep(100000);

		// This is what triggers the check
		struct loc_network* network = NULL;

		r = loc_database_lookup_from_string(db, "198.51.100.1", &network);
		if (r)
			return 1;

		if (network) {
			loc_network_unref(network);
			break;
		}
	}

	if (expect(db, "192.0.2.1", NULL) || expect(db, "198.51.100.1", "FR")) {
		fprintf(stderr, "The database has not been reloaded automatically\n");
		return 1;
	}

	// Turn it off
	r = loc_database_set_reload_interval(db, 0);
	if (r)
		return 1;

	r = write_database(ctx, "203.0.113.0/24", "GB");
	if (r)
		return 1;

	for (unsigned int i = 0; i < 25; i++) {
		usleep(100000);

		if (expect(db, "198.51.100.1", "FR") || expect(db, "203.0.113.1", NULL)) {
			fprintf(stderr, "The database has been reloaded although that is turned off\n");
			return 1;
		}
	}

	// We can still ask for it
	r = loc_database_reload(db);
	if (r != 0)
		return 1;

	if (expect(db, "203.0.113.1", "GB"))
		return 1;

	loc_database_unref(db);

	return 0;
}

/*
	Looks up addresses from a couple of threads while the database is
	being replaced over and over again
*/
#define NUM_THREADS			8
#define NUM_RELOADS			200

// Every thread does a fixed amount of work. If they were running until we
// are done with replacing the database, we might never get to do that when
// all of this is being run in valgrind, which only runs one thread at a time.
#define NUM_LOOKUPS			20000

static void* lookup(void* data) {
	struct loc_database* db = data;
	struct loc_network* network = NULL;
	int r;

	static const char* addresses[] = { "192.0.2.1", "198.51.100.1", NULL };

	for (unsigned int i = 0; i < NUM_LOOKUPS; i++) {
		for (const char** address = addresses; *address; address++) {
			r = loc_database_lookup_from_string(db, *address, &network);
			if (r) {
				fprintf(stderr, "Could not look up %s: %s\n", *address, strerror(-r));
				return data;
			}

			if (!network)
				continue;

			// Whatever we have found must be one of the networks that we have written
			const char* s = loc_network_str(network);
			const char* cc = loc_network_get_country_code(network);

			if (!((strcmp(s, "192.0.2.0/24") == 0 && strcmp(cc, "DE") == 0)
					|| (strcmp(s, "198.51.100.0/24") == 0 && strcmp(cc, "FR") == 0))) {
				fprintf(stderr, "Found %s (%s) for %s\n", s, cc, *address);
				r = 1;
			}

			loc_network_unref(network);

			if (r)
				return data;
		}

	}

	return NULL;
}

static int test_threads(struct loc_ctx* ctx) {
	struct loc_database* db = NULL;
	pthread_t threads[NUM_THREADS];
	char databases[2][sizeof(path) + 8];
	char tmp[sizeof(path) + 8];
	int failed = 0;
	int r;

	// Write the two databases that we are going to switch between only once.
	// The writer is slow, especially if all of this is being run in valgrind.
	snprintf(databases[0], sizeof(databases[0]), "%s.0", path);
	snprintf(databases[1], sizeof(databases[1]), "%s.1", path);
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	r = write_database_to(ctx, databases[0], "198.51.100.0/24", "FR");
	if (r)
		return 1;

	r = write_database_to(ctx, databases[1], "192.0.2.0/24", "DE");
	if (r)
		return 1;

	r = write_database(ctx, "192.0.2.0/24", "DE");
	if (r)
		return 1;

	r = loc_database_open(ctx, &db, path);
	if (r)
		return 1;

	for (unsigned int i = 0; i < NUM_THREADS; i++) {
		r = pthread_create(&threads[i], NULL, lookup, db);
		if (r)
			return 1;
	}

	// Switch between the two databases
	for (unsigned int i = 0; i < NUM_RELOADS && !failed; i++) {
		// Give the database another name and move that into place
		r = link(databases[i % 2], tmp);
		if (r == 0)
			r = rename(tmp, path);
		if (r) {
			fprintf(stderr, "Could not replace the database: %s\n", strerror(errno));
			failed++;
			break;
		}

		r = loc_database_reload(db);
		if (r != 0) {
			fprintf(stderr, "Reload %u returned %d\n", i, r);
			failed++;
		}
	}

	for (unsigned int i = 0; i < NUM_THREADS; i++) {
		void* result = NULL;

		r = pthread_join(threads[i], &result);
		if (r || result)
			failed++;
	}

	loc_database_unref(db);

	unlink(databases[0]);
	unlink(databases[1]);

	return failed;
}

int main(int argc, char** argv) {
	struct loc_ctx* ctx = NULL;
	int r;

	r = loc_new(&ctx);
	if (r < 0)
		exit(EXIT_FAILURE);

	if (!mkdtemp(directory)) {
		fprintf(stderr, "Could not create a temporary directory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(path, sizeof(path), "%s/database.db", directory);

	r = test_open(ctx);

	if (!r)
		r = test_reload(ctx);

	if (!r)
		r = test_automatic(ctx);

	if (!r)
		r = test_threads(ctx);

	// Cleanup
	unlink(path);
	rmdir(directory);

	loc_unref(ctx);

	if (r)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
