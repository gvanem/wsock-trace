/*
	Compares lookups in libloc with lookups in libmaxminddb

	  lookup LOCATION.DB COUNTRY.MMDB ASN.MMDB [libloc|mmdb]

	See README.md for how to build and run it.
*/

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <maxminddb.h>

#include <libloc/libloc.h>
#include <libloc/database.h>
#include <libloc/network.h>

#define COUNT 1000000
#define ROUNDS 5
#define THREADS 16

// How many IPv6 networks we pick addresses from at most
#define MAX_NETWORKS 4000000

static struct sockaddr_storage* addrs4;
static struct sockaddr_storage* addrs6;
static struct in6_addr* in6s4;
static struct in6_addr* in6s6;

static struct loc_database* db;
static MMDB_s mmdb_country;
static MMDB_s mmdb_asn;

static volatile uint64_t sink;

static double now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static uint64_t rng = 0x9e3779b97f4a7c15;

static uint64_t next(void) {
	// xorshift64
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;

	return rng;
}

// Picks addresses for IPv6 from the networks that have been allocated
static void generate6(const char* path) {
	struct loc_database_enumerator* e = NULL;
	struct loc_network* network = NULL;
	struct loc_network** networks = NULL;
	struct loc_ctx* ctx = NULL;
	struct loc_database* d = NULL;
	size_t count = 0;

	loc_new(&ctx);
	loc_database_open(ctx, &d, path);
	loc_database_enumerator_new(&e, d, LOC_DB_ENUMERATE_NETWORKS, LOC_DB_ENUMERATOR_FLAGS_FLATTEN);
	loc_database_enumerator_set_family(e, AF_INET6);

	networks = malloc(sizeof(*networks) * MAX_NETWORKS);
	if (!networks)
		abort();

	while (loc_database_enumerator_next_network(e, &network) == 0 && network) {
		if (*loc_network_get_country_code(network) && count < MAX_NETWORKS)
			networks[count++] = network;
		else
			loc_network_unref(network);
	}

	for (int i = 0; i < COUNT; i++) {
		struct loc_network* n = networks[next() % count];
		const struct in6_addr* first = loc_network_get_first_address(n);
		const struct in6_addr* last = loc_network_get_last_address(n);

		struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&addrs6[i];
		sin6->sin6_family = AF_INET6;

		// Random bits wherever the first and the last address differ
		for (int b = 0; b < 16; b++) {
			uint8_t mask = first->s6_addr[b] ^ last->s6_addr[b];
			sin6->sin6_addr.s6_addr[b] = first->s6_addr[b] | (next() & mask);
		}

		in6s6[i] = sin6->sin6_addr;
	}

	printf("IPv6 addresses from %zu allocated networks\n", count);

	for (size_t i = 0; i < count; i++)
		loc_network_unref(networks[i]);
	free(networks);
	loc_database_enumerator_unref(e);
	loc_database_unref(d);
	loc_unref(ctx);
}

static void generate(void) {
	addrs4 = calloc(COUNT, sizeof(*addrs4));
	addrs6 = calloc(COUNT, sizeof(*addrs6));
	in6s4 = calloc(COUNT, sizeof(*in6s4));
	in6s6 = calloc(COUNT, sizeof(*in6s6));

	for (int i = 0; i < COUNT; i++) {
		// IPv4: anything
		uint32_t a = next();
		struct sockaddr_in* sin = (struct sockaddr_in*)&addrs4[i];
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = a;

		// libloc wants IPv4-mapped addresses
		in6s4[i].s6_addr[10] = 0xff;
		in6s4[i].s6_addr[11] = 0xff;
		memcpy(&in6s4[i].s6_addr[12], &a, 4);
	}
}

// Returns the addresses for libloc
static const struct in6_addr* loc_addresses(int family) {
	if (family == 4)
		return in6s4;

	return in6s6;
}

// Returns the addresses for libmaxminddb
static const struct sockaddr_storage* mmdb_addresses(int family) {
	if (family == 4)
		return addrs4;

	return addrs6;
}

// Returns how many addresses had a country
static int loc_run(const struct in6_addr* addresses, int from, int to) {
	struct loc_network* network = NULL;
	int found = 0;

	for (int i = from; i < to; i++) {
		if (loc_database_lookup(db, &addresses[i], &network))
			abort();

		if (network) {
			const char* cc = loc_network_get_country_code(network);
			if (*cc)
				found++;

			// One lookup returns both
			sink += cc[0] + loc_network_get_asn(network);

			loc_network_unref(network);
		}
	}

	return found;
}

static int mmdb_run(const struct sockaddr_storage* addresses, int from, int to, int asn) {
	MMDB_entry_data_s data;
	int found = 0;
	int error;

	for (int i = from; i < to; i++) {
		MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdb_country,
			(const struct sockaddr*)&addresses[i], &error);
		if (error)
			abort();

		if (result.found_entry) {
			if (MMDB_get_value(&result.entry, &data, "country", "iso_code", NULL) == MMDB_SUCCESS
					&& data.has_data) {
				sink += data.utf8_string[0];
				found++;
			}
		}

		if (asn) {
			result = MMDB_lookup_sockaddr(&mmdb_asn, (const struct sockaddr*)&addresses[i], &error);
			if (error)
				abort();

			if (result.found_entry) {
				if (MMDB_get_value(&result.entry, &data, "autonomous_system_number", NULL) == MMDB_SUCCESS
						&& data.has_data)
					sink += data.uint32;
			}
		}
	}

	return found;
}

struct job {
	int lib;
	int family;
	int from;
	int to;
};

static void* thread(void* data) {
	struct job* job = data;

	if (job->lib == 0)
		loc_run(loc_addresses(job->family), job->from, job->to);
	else
		mmdb_run(mmdb_addresses(job->family), job->from, job->to, 1);

	return NULL;
}

static double median(double* v, int n) {
	for (int i = 0; i < n; i++) {
		for (int j = i + 1; j < n; j++) {
			if (v[j] < v[i]) {
				double t = v[i];
				v[i] = v[j];
				v[j] = t;
			}
		}
	}

	return v[n / 2];
}

static void single(const char* what, int lib, int family, int asn) {
	double t[ROUNDS];
	int found = 0;

	for (int r = 0; r < ROUNDS; r++) {
		double start = now();

		if (lib == 0)
			found = loc_run(loc_addresses(family), 0, COUNT);
		else
			found = mmdb_run(mmdb_addresses(family), 0, COUNT, asn);

		t[r] = now() - start;
	}

	printf("%-44s %7.0f ns/lookup  %5.1f%% have a country\n", what,
		median(t, ROUNDS) / COUNT * 1e9, found * 100.0 / COUNT);
}

static void parallel(const char* what, int lib, int family) {
	pthread_t threads[THREADS];
	struct job jobs[THREADS];
	double t[ROUNDS];

	printf("%-44s", what);

	for (int n = 1; n <= THREADS; n *= 2) {
		for (int r = 0; r < ROUNDS; r++) {
			double start = now();

			for (int i = 0; i < n; i++) {
				jobs[i] = (struct job){ lib, family, COUNT / n * i, COUNT / n * (i + 1) };
				pthread_create(&threads[i], NULL, thread, &jobs[i]);
			}

			for (int i = 0; i < n; i++)
				pthread_join(threads[i], NULL);

			t[r] = now() - start;
		}

		printf(" %2d: %5.1f", n, COUNT / median(t, ROUNDS) / 1e6);
	}

	printf("  M lookups/s\n");
}

// Returns the name of a file without its directory
static const char* file_name(const char* path) {
	const char* name = strrchr(path, '/');
	if (name)
		return name + 1;

	return path;
}

//
// How much of the database files is in memory?
// The WIN32 version function of this is in 'src/win_misc.c' and exported
// in libloc*.dll as 'loc_memory()'
//
#if !defined(_WIN32)
static void memory(const char* what, const char* path1, const char* path2) {
	char line[512];
	FILE* f = fopen("/proc/self/smaps", "r");
	long rss = 0, value = 0;
	int ours = 0;

	if (!f)
		abort();

	while (fgets(line, sizeof(line), f)) {
		unsigned long start, end;

		// A new mapping starts with its address range, and ends with the file
		if (sscanf(line, "%lx-%lx ", &start, &end) == 2) {
			ours = 0;

			if (path1 && strstr(line, file_name(path1)))
				ours = 1;

			if (path2 && strstr(line, file_name(path2)))
				ours = 1;
		}

		if (ours && sscanf(line, "Rss: %ld kB", &value) == 1)
			rss += value;
	}

	fclose(f);

	printf("%-44s %6.1f MiB of the database in memory\n", what, rss / 1024.0);
}
#endif  /* !_WIN32 */

int main(int argc, char** argv) {
	struct loc_ctx* ctx = NULL;
	double start;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s LOCATION.DB COUNTRY.MMDB ASN.MMDB [libloc|mmdb]\n", argv[0]);
		return 2;
	}

	const char* only = NULL;

	// Only run the benchmarks of one library
	if (argc > 4)
		only = argv[4];

	generate();
	generate6(argv[1]);

	if (!only || strcmp(only, "libloc") == 0) {
		memory("libloc: before opening", argv[1], NULL);

		loc_new(&ctx);

		start = now();
		if (loc_database_open(ctx, &db, argv[1]))
			abort();
		printf("%-44s %7.2f ms, ASN-nodes: %zd\n", "libloc: open",
		       (now() - start) * 1e3, loc_database_count_as(db));

		memory("libloc: after opening", argv[1], NULL);

		single("libloc: IPv4, country + ASN", 0, 4, 1);
		single("libloc: IPv6, country + ASN", 0, 6, 1);

		memory("libloc: after the lookups", argv[1], NULL);

		parallel("libloc: IPv4, country + ASN, threads", 0, 4);
		parallel("libloc: IPv6, country + ASN, threads", 0, 6);
	}

	if (!only || strcmp(only, "mmdb") == 0) {
		memory("mmdb: before opening", argv[2], argv[3]);

		start = now();
		if (MMDB_open(argv[2], MMDB_MODE_MMAP, &mmdb_country) != MMDB_SUCCESS)
			abort();
		if (MMDB_open(argv[3], MMDB_MODE_MMAP, &mmdb_asn) != MMDB_SUCCESS)
			abort();
		printf("%-44s %7.2f ms, ASN-nodes: %u, county nodes: %u\n",
		 	"mmdb: open both", (now() - start) * 1e3,
		 	mmdb_country.metadata.node_count, mmdb_asn.metadata.node_count);

		memory("mmdb: after opening", argv[2], argv[3]);

		single("mmdb: IPv4, country only", 1, 4, 0);
		single("mmdb: IPv4, country + ASN (two databases)", 1, 4, 1);
		single("mmdb: IPv6, country only", 1, 6, 0);
		single("mmdb: IPv6, country + ASN (two databases)", 1, 6, 1);

		memory("mmdb: after the lookups", argv[2], argv[3]);

		parallel("mmdb: IPv4, country + ASN, threads", 1, 4);
		parallel("mmdb: IPv6, country + ASN, threads", 1, 6);
	}

	return 0;
}
