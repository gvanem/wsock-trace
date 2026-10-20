EXTRA_DIST =
CLEANFILES =
noinst_PROGRAMS =
INSTALL_DIRS =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
check_SCRIPTS =

SUBDIRS = . po
BINDINGS =

OS = $(shell uname -s)

if ENABLE_PERL
BINDINGS += perl
endif

bashcompletiondir = @bashcompletiondir@

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-I${top_srcdir}/src

AM_CFLAGS = \
	$(OUR_CFLAGS) \
	$(ASAN_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS = \
	$(OUR_LDFLAGS) \
	$(ASAN_LDFLAGS) \
	$(COVERAGE_LDFLAGS)

LIBLOC_CURRENT=2
LIBLOC_REVISION=0
LIBLOC_AGE=1

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
	-e 's,@LUA_VERSION\@,$(LUA_VERSION),g' \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix\@,$(exec_prefix),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	-e 's,@databasedir\@,$(databasedir),g' \
	< $< > $@ || rm $@

cron_dailydir = $(sysconfdir)/cron.daily
databasedir = $(localstatedir)/lib/location
pkgconfigdir = $(libdir)/pkgconfig
systemdsystemunitdir = $(prefix)/lib/systemd/system

# Overwrite Python path
pkgpythondir = $(pythondir)/location

%: %.in Makefile
	$(SED_PROCESS)

@INTLTOOL_POLICY_RULE@

# ------------------------------------------------------------------------------

AM_V_ASCIIDOC   = $(AM_V_ASCIIDOC_$(V))
AM_V_ASCIIDOC_  = $(AM_V_ASCIIDOC_$(AM_DEFAULT_VERBOSITY))
AM_V_ASCIIDOC_0 = @echo "  ASCIIDOC" $@;

AM_V_XSLT   = $(AM_V_XSLT_$(V))
AM_V_XSLT_  = $(AM_V_XSLT_$(AM_DEFAULT_VERBOSITY))
AM_V_XSLT_0 = @echo "  XSLT    " $@;

# ------------------------------------------------------------------------------

.PHONY: update-pot
update-pot: po/POTFILES.in
	$(MAKE) -C po $(GETTEXT_PACKAGE).pot

po/POTFILES.in: Makefile
	find $(abs_srcdir)/src $(abs_srcdir)/tools \
		-type f \( -name '*.in' -o -name '*.py' \) \
		\! -exec git check-ignore -q {} \; -print | \
		sed -e "s@$(abs_srcdir)/@@g" | LC_ALL=C sort > $@

EXTRA_DIST += \
	README.md \
	autogen.sh \
	examples/private-key.pem \
	examples/public-key.pem \
	examples/python/create-database.py \
	examples/python/read-database.py

pkginclude_HEADERS = \
	src/libloc/libloc.h \
	src/libloc/as.h \
	src/libloc/as-list.h \
	src/libloc/country.h \
	src/libloc/country-list.h \
	src/libloc/database.h \
	src/libloc/format.h \
	src/libloc/network.h \
	src/libloc/network-list.h \
	src/libloc/resolv.h \
	src/libloc/writer.h

# Headers that only declare what is private to the library
noinst_HEADERS = \
	src/libloc/address.h \
	src/libloc/compat.h \
	src/libloc/network-tree.h \
	src/libloc/private.h \
	src/libloc/stringpool.h

lib_LTLIBRARIES = \
	src/libloc.la

src_libloc_la_SOURCES = \
	src/libloc.c \
	src/address.c \
	src/as.c \
	src/as-list.c \
	src/country.c \
	src/country-list.c \
	src/database.c \
	src/network.c \
	src/network-list.c \
	src/network-tree.c \
	src/resolv.c \
	src/stringpool.c \
	src/writer.c

EXTRA_DIST += src/libloc.sym

src_libloc_la_CFLAGS = \
	$(AM_CFLAGS) \
	-DLIBLOC_PRIVATE \
	-fvisibility=hidden \
	$(OPENSSL_CFLAGS)

src_libloc_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBLOC_CURRENT):$(LIBLOC_REVISION):$(LIBLOC_AGE) \
	$(OPENSSL_LDFLAGS)

if HAVE_LD_VERSION_SCRIPT
src_libloc_la_LDFLAGS += -Wl,--version-script=$(top_srcdir)/src/libloc.sym
endif

src_libloc_la_LIBADD = \
	$(OPENSSL_LIBS) \
	$(RESOLV_LIBS)

src_libloc_la_DEPENDENCIES = \
	${top_srcdir}/src/libloc.sym

noinst_LTLIBRARIES = \
	src/libloc-internal.la

src_libloc_internal_la_SOURCES = \
	$(src_libloc_la_SOURCES)

src_libloc_internal_la_CFLAGS = \
	$(src_libloc_la_CFLAGS)

src_libloc_internal_la_LDFLAGS = \
	$(filter-out -version-info %,$(src_libloc_la_LDFLAGS))

src_libloc_internal_la_LIBADD = \
	$(src_libloc_la_LIBADD)

src_libloc_internal_la_DEPENDENCIES = \
	$(src_libloc_la_DEPENDENCIES)

pkgconfig_DATA = \
	src/libloc.pc

EXTRA_DIST += \
	src/libloc.pc.in

CLEANFILES += \
	src/libloc.pc

if BUILD_BASH_COMPLETION
bashcompletion_DATA = \
	bash-completion/location
endif

EXTRA_DIST += \
	bash-completion/location

dist_pkgpython_PYTHON = \
	src/python/location/__init__.py \
	src/python/location/database.py \
	src/python/location/downloader.py \
	src/python/location/export.py \
	src/python/location/i18n.py \
	src/python/location/logger.py

pyexec_LTLIBRARIES = \
	src/python/_location.la

src_python__location_la_SOURCES = \
	src/python/locationmodule.c \
	src/python/locationmodule.h \
	src/python/as.c \
	src/python/as.h \
	src/python/country.c \
	src/python/country.h \
	src/python/database.c \
	src/python/database.h \
	src/python/network.c \
	src/python/network.h \
	src/python/writer.c \
	src/python/writer.h

src_python__location_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PYTHON_CFLAGS) \
	-Wno-cast-function-type \
	-Wno-redundant-decls \
	-Wno-strict-aliasing

src_python__location_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

src_python__location_la_LIBADD = \
	src/libloc.la \
	$(PYTHON_LIBS)

# ------------------------------------------------------------------------------

if ENABLE_LUA
luaexec_LTLIBRARIES = \
	src/lua/location.la

luaexecdir = $(LUA_INSTALL_CMOD)

src_lua_location_la_SOURCES = \
	src/lua/as.c \
	src/lua/as.h \
	src/lua/compat.h \
	src/lua/country.c \
	src/lua/country.h \
	src/lua/database.c \
	src/lua/database.h \
	src/lua/location.c \
	src/lua/location.h \
	src/lua/network.c \
	src/lua/network.h

src_lua_location_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(LUA_CFLAGS)

src_lua_location_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LUA_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

src_lua_location_la_LIBADD = \
	src/libloc.la \
	$(LUA_LIBS)
endif

EXTRA_DIST += \
	src/lua/as.c \
	src/lua/as.h \
	src/lua/country.c \
	src/lua/country.h \
	src/lua/database.c \
	src/lua/database.h \
	src/lua/location.c \
	src/lua/location.h \
	src/lua/network.c \
	src/lua/network.h

LUA_TESTS = \
	tests/lua/main.lua

EXTRA_DIST += \
	tests/lua/main.lua.in

CLEANFILES += \
	tests/lua/main.lua

tests/lua/main.lua: tests/lua/main.lua.in Makefile
	$(SED_PROCESS)
	chmod a+x $@

# ------------------------------------------------------------------------------

# Compile & install bindings
all-local: $(foreach binding,$(BINDINGS),build-$(binding))
check-local: $(foreach binding,$(BINDINGS),check-$(binding))
install-exec-local: $(foreach binding,$(BINDINGS),install-$(binding))
clean-local: $(foreach binding,$(BINDINGS),clean-$(binding)) clean-local-fuzz clean-local-scan-build
uninstall-local: $(foreach binding,$(BINDINGS),uninstall-$(binding))

# Perl Bindings
EXTRA_DIST += \
	src/perl/.gitignore \
	src/perl/Location.xs \
	src/perl/MANIFEST \
	src/perl/Makefile.PL \
	src/perl/lib/Location.pm \
	src/perl/t/Location.t \
	src/perl/typemap

build-perl: src/libloc.la
	@mkdir -p $(builddir)/src/perl/{lib,t}
	@test -e $(builddir)/src/perl/Location.xs || ln -s --relative $(srcdir)/src/perl/Location.xs $(builddir)/src/perl/
	@test -e $(builddir)/src/perl/MANIFEST || ln -s --relative $(srcdir)/src/perl/MANIFEST $(builddir)/src/perl/
	@test -e $(builddir)/src/perl/Makefile.PL || ln -s --relative $(srcdir)/src/perl/Makefile.PL $(builddir)/src/perl/
	@test -e $(builddir)/src/perl/lib/Location.pm || ln -s --relative $(srcdir)/src/perl/lib/Location.pm $(builddir)/src/perl/lib/
	@test -e $(builddir)/src/perl/t/Location.t || ln -s --relative $(srcdir)/src/perl/t/Location.t $(builddir)/src/perl/t/
	@test -e $(builddir)/src/perl/typemap || ln -s --relative $(srcdir)/src/perl/typemap $(builddir)/src/perl/

	cd $(builddir)/src/perl && $(PERL) Makefile.PL NO_PACKLIST=1 NO_PERLLOCAL=1 \
		INSTALLDIRS=vendor \
		INC="-I$(abs_srcdir)/src" LIBS="-L$(abs_builddir)/src/.libs -lloc"
	cd $(builddir)/src/perl && $(MAKE)
	touch build-perl

.PHONY: check-perl
check-perl: testdata.db build-perl
	cd $(builddir)/src/perl && env $(BINDINGS_TEST_ENV) \
		$(MAKE) LD_LIBRARY_PATH="$(abs_builddir)/src/.libs" test \
		database="../../$<" keyfile="$(abs_srcdir)/examples/public-key.pem"

.PHONY: install-perl
install-perl: build-perl
	cd $(builddir)/src/perl && $(MAKE) install DESTDIR=$(DESTDIR)

.PHONY: clean-perl
clean-perl:
	cd $(builddir)/src/perl && $(MAKE) distclean
	rm -f build-perl

.PHONY: uninstall-perl
uninstall-perl:
	rm -vf \
		$(DESTDIR)/@PERL_MODPATH@/Location.pm \
		$(DESTDIR)/@PERL_MODPATH@/auto/Location/Location.so \
		$(DESTDIR)/@PERL_MANPATH@/Location.3pm
	-rmdir $(DESTDIR)/@PERL_MODPATH@/auto/Location

bin_SCRIPTS = \
	src/scripts/location \
	src/scripts/location-importer

EXTRA_DIST += \
	src/scripts/location.in \
	src/scripts/location-importer.in

CLEANFILES += \
	src/scripts/location \
	src/scripts/location-importer

# ------------------------------------------------------------------------------

# Avoid installing .la files, as we do not use libltdl.
install-exec-hook:
	@for la in $(lib_LTLIBRARIES); do \
	  rm -f "$(DESTDIR)$(libdir)/`basename $$la`"; \
	done
	@for la in $(pyexec_LTLIBRARIES); do \
	  rm -f "$(DESTDIR)$(pyexecdir)/`basename $$la`"; \
	done
	@for la in $(luaexec_LTLIBRARIES); do \
	  rm -f "$(DESTDIR)$(luaexecdir)/`basename $$la`"; \
	done

# libtool needs those files to find what it has installed, so that
# we have to remove the libraries and modules ourselves.
uninstall-hook:
	rm -f "$(DESTDIR)$(libdir)"/libloc.so*
	rm -f "$(DESTDIR)$(pyexecdir)/_location.so"
if ENABLE_LUA
	rm -f "$(DESTDIR)$(luaexecdir)/location.so"
endif

# ------------------------------------------------------------------------------

# Use systemd timers if available
if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	src/systemd/location-update.service \
	src/systemd/location-update.timer

CLEANFILES += \
	$(systemdsystemunit_DATA)

INSTALL_DIRS += \
	$(systemdsystemunitdir)
endif

# The cron job is always being installed. It does nothing if systemd is
# running, so that the database is also being updated on systems that have
# the units, but that have been booted with something else.
cron_daily_SCRIPTS = \
	src/cron/location-update

CLEANFILES += \
	$(cron_daily_SCRIPTS)

EXTRA_DIST += \
	src/cron/location-update.in \
	src/systemd/location-update.service.in \
	src/systemd/location-update.timer.in

# ------------------------------------------------------------------------------

dist_database_DATA = \
	data/database.db \
	data/signing-key.pem

install-data-hook:
	chmod 444 $(DESTDIR)$(databasedir)/database.db

.PHONY: update-database
update-database:
	curl https://location.ipfire.org/databases/1/location.db.xz | xz -d > data/database.db

# ------------------------------------------------------------------------------

# The examples only use what the library exports, which is why they are being
# built without LIBLOC_PRIVATE, and against the shared library only
noinst_PROGRAMS += \
	examples/c/lookup

examples_c_lookup_SOURCES = \
	examples/c/lookup.c

examples_c_lookup_LDADD = \
	src/libloc.la

# ------------------------------------------------------------------------------

TESTS_CFLAGS = \
	$(AM_CFLAGS) \
	-DLIBLOC_PRIVATE \
	-DABS_SRCDIR=\"$(abs_srcdir)\"

TESTS_LDADD = \
	src/libloc.la \
	src/libloc-internal.la

TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH="$(abs_builddir)/src/.libs" \
	LUA_CPATH="$(abs_builddir)/src/lua/.libs/?.so;;" \
	PYTHONPATH=$(abs_srcdir)/src/python:$(abs_builddir)/src/python/.libs \
	TEST_DATA_DIR="$(abs_top_srcdir)/data" \
	TEST_DATABASE="$(abs_top_srcdir)/data/database.db" \
	TEST_SIGNING_KEY="$(abs_top_srcdir)/data/signing-key.pem" \
	ABS_BUILDDIR="$(abs_builddir)" \
	ABS_SRCDIR="$(abs_srcdir)"

# Make the address sanitizer fail any test that leaks memory
# and use libunwind for better stack traces
TESTS_ENVIRONMENT += \
	ASAN_OPTIONS=detect_leaks=1:fast_unwind_on_malloc=0

TESTS = \
	$(check_PROGRAMS) \
	$(check_SCRIPTS) \
	$(dist_check_SCRIPTS)

# Run the tests of the bindings with whatever environment their interpreter needs
TEST_EXTENSIONS = .py .lua

PY_LOG_COMPILER = env $(BINDINGS_TEST_ENV) $(PYTHON)
LUA_LOG_COMPILER = env $(BINDINGS_TEST_ENV)

CLEANFILES += \
	testdata.db

testdata.db: examples/python/create-database.py src/python/_location.la
	LD_LIBRARY_PATH="$(abs_builddir)/src/.libs" \
	PYTHONPATH=$(abs_srcdir)/src/python:$(abs_builddir)/src/python/.libs \
	ABS_SRCDIR="$(abs_srcdir)" \
		env $(BINDINGS_TEST_ENV) $(PYTHON) $< $@

dist_check_SCRIPTS = \
	tests/examples/lookup.sh \
	tests/man/index.sh \
	tests/python/as.py \
	tests/python/country.py \
	tests/python/network.py \
	tests/python/networks-dedup.py \
	tests/python/test-database.py \
	tests/python/test-downloader.py \
	tests/python/test-export.py \
	tests/python/test-gil.py

if ENABLE_LUA_TESTS
check_SCRIPTS += \
	$(LUA_TESTS)
endif

check_PROGRAMS = \
	tests/libloc/main \
	tests/libloc/stringpool \
	tests/libloc/database \
	tests/libloc/enumerator \
	tests/libloc/as \
	tests/libloc/as-list \
	tests/libloc/network \
	tests/libloc/network-list \
	tests/libloc/country \
	tests/libloc/country-list \
	tests/libloc/signature \
	tests/libloc/address \
	tests/libloc/threads \
	tests/libloc/reload

tests_libloc_main_SOURCES = \
	tests/libloc/main.c

tests_libloc_main_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_main_LDADD = \
	$(TESTS_LDADD)

tests_libloc_as_SOURCES = \
	tests/libloc/as.c

tests_libloc_as_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_as_LDADD = \
	$(TESTS_LDADD)

tests_libloc_as_list_SOURCES = \
	tests/libloc/as-list.c

tests_libloc_as_list_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_as_list_LDADD = \
	$(TESTS_LDADD)

tests_libloc_country_SOURCES = \
	tests/libloc/country.c

tests_libloc_country_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_country_LDADD = \
	$(TESTS_LDADD)

tests_libloc_country_list_SOURCES = \
	tests/libloc/country-list.c

tests_libloc_country_list_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_country_list_LDADD = \
	$(TESTS_LDADD)

tests_libloc_network_SOURCES = \
	tests/libloc/network.c

tests_libloc_network_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_network_LDADD = \
	$(TESTS_LDADD)

tests_libloc_network_list_SOURCES = \
	tests/libloc/network-list.c

tests_libloc_network_list_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_network_list_LDADD = \
	$(TESTS_LDADD)

tests_libloc_stringpool_SOURCES = \
	tests/libloc/stringpool.c

tests_libloc_stringpool_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_stringpool_LDADD = \
	$(TESTS_LDADD)

tests_libloc_database_SOURCES = \
	tests/libloc/database.c

tests_libloc_database_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_database_LDADD = \
	$(TESTS_LDADD)

tests_libloc_enumerator_SOURCES = \
	tests/libloc/enumerator.c

tests_libloc_enumerator_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_enumerator_LDADD = \
	$(TESTS_LDADD)

tests_libloc_signature_SOURCES = \
	tests/libloc/signature.c

tests_libloc_signature_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_signature_LDADD = \
	$(TESTS_LDADD)

tests_libloc_address_SOURCES = \
	tests/libloc/address.c

tests_libloc_address_CFLAGS = \
	$(TESTS_CFLAGS)

tests_libloc_address_LDADD = \
	$(TESTS_LDADD)

tests_libloc_reload_SOURCES = \
	tests/libloc/reload.c

tests_libloc_reload_CFLAGS = \
	$(TESTS_CFLAGS) \
	-pthread

tests_libloc_reload_LDFLAGS = \
	$(AM_LDFLAGS) \
	-pthread

tests_libloc_reload_LDADD = \
	$(TESTS_LDADD)

tests_libloc_threads_SOURCES = \
	tests/libloc/threads.c

tests_libloc_threads_CFLAGS = \
	$(TESTS_CFLAGS) \
	-pthread

tests_libloc_threads_LDFLAGS = \
	$(AM_LDFLAGS) \
	-pthread

tests_libloc_threads_LDADD = \
	$(TESTS_LDADD)

# ------------------------------------------------------------------------------

# Fuzzers
#
# These are only built with --enable-fuzzing, which requires clang. Each of
# them takes whatever the fuzzing engine comes up with and feeds it to the
# code that parses data that we have not created ourselves.

if ENABLE_FUZZING
FUZZERS = \
	tests/fuzz/address \
	tests/fuzz/database

noinst_PROGRAMS += \
	$(FUZZERS)

FUZZ_LINK_FLAGS = \
	$(AM_LDFLAGS) \
	-fsanitize=fuzzer

tests_fuzz_address_SOURCES = \
	tests/fuzz/address.c \
	tests/fuzz/fuzz.h

tests_fuzz_address_CFLAGS = \
	$(TESTS_CFLAGS)

tests_fuzz_address_LDFLAGS = \
	$(FUZZ_LINK_FLAGS)

tests_fuzz_address_LDADD = \
	$(TESTS_LDADD)

tests_fuzz_database_SOURCES = \
	tests/fuzz/database.c \
	tests/fuzz/fuzz.h

tests_fuzz_database_CFLAGS = \
	$(TESTS_CFLAGS)

tests_fuzz_database_LDFLAGS = \
	$(FUZZ_LINK_FLAGS)

tests_fuzz_database_LDADD = \
	$(TESTS_LDADD)
endif

EXTRA_DIST += \
	tests/fuzz/address.c \
	tests/fuzz/database.c \
	tests/fuzz/fuzz.h \
	tests/fuzz/corpus

# For how long should each fuzzer be run? (in seconds)
FUZZ_TIME = 60

# Runs all fuzzers, one after the other. They start with the files that are
# in tests/fuzz/corpus, and anything that makes them crash is stored in
# tests/fuzz/crashes. The database fuzzer starts with the database that
# the tests use, which we have to create first.
.PHONY: fuzz
fuzz: $(FUZZERS) testdata.db
	@if [ -z "$(FUZZERS)" ]; then \
		echo "The fuzzers have not been built. Run ./configure --enable-fuzzing" >&2; \
		exit 1; \
	fi
	@$(MKDIR_P) tests/fuzz/work/database && cp testdata.db tests/fuzz/work/database/
	@for fuzzer in $(FUZZERS); do \
		name="$$(basename $${fuzzer})"; \
		corpus="$(abs_top_srcdir)/tests/fuzz/corpus/$${name}"; \
		test -d "$${corpus}" || corpus=""; \
		$(MKDIR_P) "tests/fuzz/work/$${name}" "tests/fuzz/crashes/$${name}"; \
		echo "Running $${fuzzer} for $(FUZZ_TIME)s..."; \
		$(LIBTOOL) --mode=execute "$${fuzzer}" \
			-max_total_time=$(FUZZ_TIME) \
			-print_final_stats=1 \
			-artifact_prefix="tests/fuzz/crashes/$${name}/" \
			"tests/fuzz/work/$${name}" $${corpus} || exit $$?; \
	done

.PHONY: clean-local-fuzz
clean-local-fuzz:
	-rm -rf tests/fuzz/work tests/fuzz/crashes

# ------------------------------------------------------------------------------

# Runs all tests that are written in C in valgrind. Any invalid memory access
# makes the test fail.

VALGRIND = valgrind
VALGRIND_FLAGS = \
	--quiet \
	--error-exitcode=99 \
	--errors-for-leak-kinds=none

.PHONY: check-valgrind
# Valgrind refuses to start if the limit of open files is as high as it is
# inside containers, which is why we try to lower it.
check-valgrind: $(check_PROGRAMS)
	ulimit -n 65536 2>/dev/null || :; \
	$(MAKE) $(AM_MAKEFLAGS) check-TESTS \
		TESTS="$(check_PROGRAMS)" \
		LOG_COMPILER="$(LIBTOOL) --mode=execute $(VALGRIND) $(VALGRIND_FLAGS)"

# ------------------------------------------------------------------------------

# Runs everything through Clang's Static Analyzer and writes the report to
# scan-build-output/. Since the analyzer hooks into the compiler, this has to
# build everything from scratch.

SCAN_BUILD = scan-build
SCAN_BUILD_OUTPUT = $(abs_top_builddir)/scan-build-output

.PHONY: scan-build
scan-build:
	$(MAKE) $(AM_MAKEFLAGS) clean
	$(SCAN_BUILD) -o $(SCAN_BUILD_OUTPUT) \
		$(SHELL) -c '$(MAKE) $(AM_MAKEFLAGS) CC="$$CC" LIBTOOLFLAGS="--tag=CC" all'

.PHONY: clean-local-scan-build
clean-local-scan-build:
	-rm -rf $(SCAN_BUILD_OUTPUT)

# ------------------------------------------------------------------------------

MANPAGES = \
	$(MANPAGES_3) \
	$(MANPAGES_1)

MANPAGES_3 = \
	man/libloc.3 \
	man/loc_as_list_append.3 \
	man/loc_as_list_new.3 \
	man/loc_as_new.3 \
	man/loc_country_code_is_valid.3 \
	man/loc_country_list_append.3 \
	man/loc_country_list_new.3 \
	man/loc_country_new.3 \
	man/loc_database_count_as.3 \
	man/loc_database_enumerator_new.3 \
	man/loc_database_enumerator_set_string.3 \
	man/loc_database_get_as.3 \
	man/loc_database_get_country.3 \
	man/loc_database_lookup.3 \
	man/loc_database_new.3 \
	man/loc_database_reload.3 \
	man/loc_database_verify.3 \
	man/loc_discover_latest_version.3 \
	man/loc_get_log_priority.3 \
	man/loc_network_cmp.3 \
	man/loc_network_get_asn.3 \
	man/loc_network_get_first_address.3 \
	man/loc_network_list_new.3 \
	man/loc_network_list_push.3 \
	man/loc_network_new.3 \
	man/loc_new.3 \
	man/loc_set_log_callback.3 \
	man/loc_set_log_fn.3 \
	man/loc_set_log_priority.3 \
	man/loc_writer_new.3 \
	man/loc_writer_set_vendor.3 \
	man/lua-location.3 \
	man/python-location.3

MANPAGES_1 = \
	man/location.1 \
	man/location-importer.1

# Pages that document more than one function are also being created under the
# names of the other functions. Those don't have a source of their own.
MANPAGES_3_ALIASES = \
	man/loc_as_cmp.3 \
	man/loc_as_get_name.3 \
	man/loc_as_get_number.3 \
	man/loc_as_list_clear.3 \
	man/loc_as_list_contains.3 \
	man/loc_as_list_contains_number.3 \
	man/loc_as_list_empty.3 \
	man/loc_as_list_get.3 \
	man/loc_as_list_ref.3 \
	man/loc_as_list_size.3 \
	man/loc_as_list_sort.3 \
	man/loc_as_list_unref.3 \
	man/loc_as_ref.3 \
	man/loc_as_set_name.3 \
	man/loc_as_unref.3 \
	man/loc_country_cmp.3 \
	man/loc_country_get_code.3 \
	man/loc_country_get_continent_code.3 \
	man/loc_country_get_name.3 \
	man/loc_country_list_clear.3 \
	man/loc_country_list_contains.3 \
	man/loc_country_list_contains_code.3 \
	man/loc_country_list_empty.3 \
	man/loc_country_list_get.3 \
	man/loc_country_list_ref.3 \
	man/loc_country_list_size.3 \
	man/loc_country_list_sort.3 \
	man/loc_country_list_unref.3 \
	man/loc_country_ref.3 \
	man/loc_country_set_continent_code.3 \
	man/loc_country_set_name.3 \
	man/loc_country_special_code_to_flag.3 \
	man/loc_country_unref.3 \
	man/loc_database_created_at.3 \
	man/loc_database_enumerator_get_asns.3 \
	man/loc_database_enumerator_get_countries.3 \
	man/loc_database_enumerator_next_as.3 \
	man/loc_database_enumerator_next_country.3 \
	man/loc_database_enumerator_next_network.3 \
	man/loc_database_enumerator_ref.3 \
	man/loc_database_enumerator_set_asns.3 \
	man/loc_database_enumerator_set_countries.3 \
	man/loc_database_enumerator_set_family.3 \
	man/loc_database_enumerator_set_flag.3 \
	man/loc_database_enumerator_unref.3 \
	man/loc_database_get_description.3 \
	man/loc_database_get_license.3 \
	man/loc_database_get_vendor.3 \
	man/loc_database_lookup_from_string.3 \
	man/loc_database_open.3 \
	man/loc_database_ref.3 \
	man/loc_database_set_reload_interval.3 \
	man/loc_database_unref.3 \
	man/loc_network_address_family.3 \
	man/loc_network_exclude.3 \
	man/loc_network_exclude_list.3 \
	man/loc_network_format_first_address.3 \
	man/loc_network_format_last_address.3 \
	man/loc_network_get_country_code.3 \
	man/loc_network_get_last_address.3 \
	man/loc_network_has_flag.3 \
	man/loc_network_is_subnet.3 \
	man/loc_network_list_clear.3 \
	man/loc_network_list_contains.3 \
	man/loc_network_list_dump.3 \
	man/loc_network_list_empty.3 \
	man/loc_network_list_get.3 \
	man/loc_network_list_merge.3 \
	man/loc_network_list_pop.3 \
	man/loc_network_list_pop_first.3 \
	man/loc_network_list_ref.3 \
	man/loc_network_list_size.3 \
	man/loc_network_list_unref.3 \
	man/loc_network_matches_address.3 \
	man/loc_network_matches_country_code.3 \
	man/loc_network_new_from_string.3 \
	man/loc_network_overlaps.3 \
	man/loc_network_prefix.3 \
	man/loc_network_ref.3 \
	man/loc_network_reverse_pointer.3 \
	man/loc_network_set_asn.3 \
	man/loc_network_set_country_code.3 \
	man/loc_network_set_flag.3 \
	man/loc_network_str.3 \
	man/loc_network_subnets.3 \
	man/loc_network_unref.3 \
	man/loc_ref.3 \
	man/loc_unref.3 \
	man/loc_writer_add_as.3 \
	man/loc_writer_add_country.3 \
	man/loc_writer_add_network.3 \
	man/loc_writer_get_description.3 \
	man/loc_writer_get_license.3 \
	man/loc_writer_get_vendor.3 \
	man/loc_writer_ref.3 \
	man/loc_writer_set_description.3 \
	man/loc_writer_set_license.3 \
	man/loc_writer_unref.3 \
	man/loc_writer_write.3

man/loc_as_cmp.3: man/loc_as_new.3
man/loc_as_get_name.3: man/loc_as_new.3
man/loc_as_get_number.3: man/loc_as_new.3
man/loc_as_list_clear.3: man/loc_as_list_new.3
man/loc_as_list_contains.3: man/loc_as_list_append.3
man/loc_as_list_contains_number.3: man/loc_as_list_append.3
man/loc_as_list_empty.3: man/loc_as_list_new.3
man/loc_as_list_get.3: man/loc_as_list_new.3
man/loc_as_list_ref.3: man/loc_as_list_new.3
man/loc_as_list_size.3: man/loc_as_list_new.3
man/loc_as_list_sort.3: man/loc_as_list_new.3
man/loc_as_list_unref.3: man/loc_as_list_new.3
man/loc_as_ref.3: man/loc_as_new.3
man/loc_as_set_name.3: man/loc_as_new.3
man/loc_as_unref.3: man/loc_as_new.3
man/loc_country_cmp.3: man/loc_country_new.3
man/loc_country_get_code.3: man/loc_country_new.3
man/loc_country_get_continent_code.3: man/loc_country_new.3
man/loc_country_get_name.3: man/loc_country_new.3
man/loc_country_list_clear.3: man/loc_country_list_new.3
man/loc_country_list_contains.3: man/loc_country_list_append.3
man/loc_country_list_contains_code.3: man/loc_country_list_append.3
man/loc_country_list_empty.3: man/loc_country_list_new.3
man/loc_country_list_get.3: man/loc_country_list_new.3
man/loc_country_list_ref.3: man/loc_country_list_new.3
man/loc_country_list_size.3: man/loc_country_list_new.3
man/loc_country_list_sort.3: man/loc_country_list_new.3
man/loc_country_list_unref.3: man/loc_country_list_new.3
man/loc_country_ref.3: man/loc_country_new.3
man/loc_country_set_continent_code.3: man/loc_country_new.3
man/loc_country_set_name.3: man/loc_country_new.3
man/loc_country_special_code_to_flag.3: man/loc_country_code_is_valid.3
man/loc_country_unref.3: man/loc_country_new.3
man/loc_database_created_at.3: man/loc_database_new.3
man/loc_database_enumerator_get_asns.3: man/loc_database_enumerator_set_string.3
man/loc_database_enumerator_get_countries.3: man/loc_database_enumerator_set_string.3
man/loc_database_enumerator_next_as.3: man/loc_database_enumerator_new.3
man/loc_database_enumerator_next_country.3: man/loc_database_enumerator_new.3
man/loc_database_enumerator_next_network.3: man/loc_database_enumerator_new.3
man/loc_database_enumerator_ref.3: man/loc_database_enumerator_new.3
man/loc_database_enumerator_set_asns.3: man/loc_database_enumerator_set_string.3
man/loc_database_enumerator_set_countries.3: man/loc_database_enumerator_set_string.3
man/loc_database_enumerator_set_family.3: man/loc_database_enumerator_set_string.3
man/loc_database_enumerator_set_flag.3: man/loc_database_enumerator_set_string.3
man/loc_database_enumerator_unref.3: man/loc_database_enumerator_new.3
man/loc_database_get_description.3: man/loc_database_new.3
man/loc_database_get_license.3: man/loc_database_new.3
man/loc_database_get_vendor.3: man/loc_database_new.3
man/loc_database_lookup_from_string.3: man/loc_database_lookup.3
man/loc_database_open.3: man/loc_database_new.3
man/loc_database_ref.3: man/loc_database_new.3
man/loc_database_set_reload_interval.3: man/loc_database_reload.3
man/loc_database_unref.3: man/loc_database_new.3
man/loc_network_address_family.3: man/loc_network_new.3
man/loc_network_exclude.3: man/loc_network_cmp.3
man/loc_network_exclude_list.3: man/loc_network_cmp.3
man/loc_network_format_first_address.3: man/loc_network_get_first_address.3
man/loc_network_format_last_address.3: man/loc_network_get_first_address.3
man/loc_network_get_country_code.3: man/loc_network_get_asn.3
man/loc_network_get_last_address.3: man/loc_network_get_first_address.3
man/loc_network_has_flag.3: man/loc_network_get_asn.3
man/loc_network_is_subnet.3: man/loc_network_cmp.3
man/loc_network_list_clear.3: man/loc_network_list_new.3
man/loc_network_list_contains.3: man/loc_network_list_new.3
man/loc_network_list_dump.3: man/loc_network_list_new.3
man/loc_network_list_empty.3: man/loc_network_list_new.3
man/loc_network_list_get.3: man/loc_network_list_new.3
man/loc_network_list_merge.3: man/loc_network_list_push.3
man/loc_network_list_pop.3: man/loc_network_list_push.3
man/loc_network_list_pop_first.3: man/loc_network_list_push.3
man/loc_network_list_ref.3: man/loc_network_list_new.3
man/loc_network_list_size.3: man/loc_network_list_new.3
man/loc_network_list_unref.3: man/loc_network_list_new.3
man/loc_network_matches_address.3: man/loc_network_cmp.3
man/loc_network_matches_country_code.3: man/loc_network_get_asn.3
man/loc_network_new_from_string.3: man/loc_network_new.3
man/loc_network_overlaps.3: man/loc_network_cmp.3
man/loc_network_prefix.3: man/loc_network_new.3
man/loc_network_ref.3: man/loc_network_new.3
man/loc_network_reverse_pointer.3: man/loc_network_get_first_address.3
man/loc_network_set_asn.3: man/loc_network_get_asn.3
man/loc_network_set_country_code.3: man/loc_network_get_asn.3
man/loc_network_set_flag.3: man/loc_network_get_asn.3
man/loc_network_str.3: man/loc_network_new.3
man/loc_network_subnets.3: man/loc_network_cmp.3
man/loc_network_unref.3: man/loc_network_new.3
man/loc_ref.3: man/loc_new.3
man/loc_unref.3: man/loc_new.3
man/loc_writer_add_as.3: man/loc_writer_new.3
man/loc_writer_add_country.3: man/loc_writer_new.3
man/loc_writer_add_network.3: man/loc_writer_new.3
man/loc_writer_get_description.3: man/loc_writer_set_vendor.3
man/loc_writer_get_license.3: man/loc_writer_set_vendor.3
man/loc_writer_get_vendor.3: man/loc_writer_set_vendor.3
man/loc_writer_ref.3: man/loc_writer_new.3
man/loc_writer_set_description.3: man/loc_writer_set_vendor.3
man/loc_writer_set_license.3: man/loc_writer_set_vendor.3
man/loc_writer_unref.3: man/loc_writer_new.3
man/loc_writer_write.3: man/loc_writer_new.3

MANPAGES_TXT   = $(MANPAGES_TXT_3) $(MANPAGES_TXT_1)
MANPAGES_TXT_3 = $(patsubst %.3,%.txt,$(MANPAGES_3))
MANPAGES_TXT_1 = $(patsubst %.1,%.txt,$(MANPAGES_1))
MANPAGES_HTML  = $(patsubst %.txt,%.html,$(MANPAGES_TXT))
MANPAGES_XML   = $(patsubst %.txt,%.xml,$(MANPAGES_TXT))

# The index of all pages, which only exists in HTML
MANPAGES_INDEX = man/index.html

.PHONY: man
man: $(MANPAGES) $(MANPAGES_3_ALIASES) $(MANPAGES_HTML) $(MANPAGES_INDEX)

if ENABLE_MAN_PAGES
man_MANS = \
	$(MANPAGES) \
	$(MANPAGES_3_ALIASES)
endif

CLEANFILES += \
	$(MANPAGES) \
	$(MANPAGES_3_ALIASES) \
	$(MANPAGES_HTML) \
	$(MANPAGES_INDEX) \
	$(MANPAGES_XML)

EXTRA_DIST += \
	man/asciidoc.conf \
	man/index.txt \
	$(MANPAGES_TXT)

XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 1 \
	--stringparam man.copyright.section.enabled 1

XSLTPROC_COMMAND_MAN = \
	$(AM_V_XSLT)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) \
		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

# Let XSLT find its source on Mac OS X
 ifeq ($(OS),Darwin)
export XML_CATALOG_FILES = /usr/local/etc/xml/catalog
 endif

man/%.xml: man/%.txt man/asciidoc.conf
	$(AM_V_ASCIIDOC)$(MKDIR_P) $(dir $@) && \
	$(ASCIIDOC) \
		-f $(abs_srcdir)/man/asciidoc.conf \
		-d manpage -b docbook -o $@ $<

man/%.3: man/%.xml
	$(XSLTPROC_COMMAND_MAN)

man/%.1: man/%.xml
	$(XSLTPROC_COMMAND_MAN)

man/%.html: man/%.txt man/asciidoc.conf
	$(AM_V_ASCIIDOC)$(MKDIR_P) $(dir $@) && \
	$(ASCIIDOC) \
		-f $(abs_srcdir)/man/asciidoc.conf \
		-b html5 -a icons -a theme=flask -o $@ $<

.PHONY: upload-man
upload-man: $(MANPAGES_HTML) $(MANPAGES_INDEX)
	rsync -avHz --delete --progress $(MANPAGES_HTML) $(MANPAGES_INDEX) ms@fs01.haj.ipfire.org:/pub/man-pages/$(PACKAGE_NAME)/

EXTRA_DIST += \
	tools/copy.py

EXTRA_DIST += \
	benchmarks/README.md \
	benchmarks/lookup.c \
	benchmarks/lookup.py

EXTRA_DIST += \
	contrib/archlinux/PKGBUILD \
	contrib/archlinux/libloc-database.install \
	contrib/rpm/build.sh \
	contrib/rpm/libloc.spec

EXTRA_DIST += \
	debian/build.sh \
	debian/changelog \
	debian/control \
	debian/copyright \
	debian/genchangelog.sh \
	debian/gensymbols.sh \
	debian/libloc1.install \
	debian/libloc1.symbols \
	debian/libloc-dev.install \
	debian/location.install \
	debian/location.postinst \
	debian/location.postrm \
	debian/lua-location.install \
	debian/python3-location.examples \
	debian/python3-location.install \
	debian/rules \
	debian/source/format \
	debian/watch

.PHONY: debian
debian: dist
	$(SHELL) debian/build.sh $(PACKAGE_NAME)-$(PACKAGE_VERSION) $(distdir).tar.gz
