EXTRA_DIST =
CLEANFILES =
INSTALL_DIRS =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

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

AM_CFLAGS = ${my_CFLAGS} \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS = ${my_LDFLAGS}

# leaving a space here to work around automake's conditionals
 ifeq ($(OS),Darwin)
	AM_LDFLAGS += -Wl,-dead_strip
 else
	AM_LDFLAGS += \
		-Wl,--as-needed \
		-Wl,--gc-sections
 endif

LIBLOC_CURRENT=1
LIBLOC_REVISION=2
LIBLOC_AGE=0

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
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

.PHONY: update-po
update-po: po/POTFILES.in
	$(MAKE) -C po update-po

po/POTFILES.in: Makefile
	find $(abs_srcdir)/src -type f \( -name '*.in' -o -name '*.py' \) \
		\! -exec git check-ignore -q {} \; -print | \
		sed -e "s@$(abs_srcdir)/@@g" | LC_ALL=C sort > $@

EXTRA_DIST += \
	examples/private-key.pem \
	examples/public-key.pem \
	examples/python/create-database.py \
	examples/python/read-database.py

pkginclude_HEADERS = \
	src/libloc/libloc.h \
	src/libloc/address.h \
	src/libloc/as.h \
	src/libloc/as-list.h \
	src/libloc/compat.h \
	src/libloc/country.h \
	src/libloc/country-list.h \
	src/libloc/database.h \
	src/libloc/format.h \
	src/libloc/network.h \
	src/libloc/network-list.h \
	src/libloc/private.h \
	src/libloc/stringpool.h \
	src/libloc/resolv.h \
	src/libloc/writer.h

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
	src/resolv.c \
	src/stringpool.c \
	src/writer.c

EXTRA_DIST += src/libloc.sym

src_libloc_la_CFLAGS = \
	$(AM_CFLAGS) \
	-DLIBLOC_PRIVATE \
	-fvisibility=hidden

src_libloc_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBLOC_CURRENT):$(LIBLOC_REVISION):$(LIBLOC_AGE)

if HAVE_LD_VERSION_SCRIPT
src_libloc_la_LDFLAGS += -Wl,--version-script=$(top_srcdir)/src/libloc.sym
else
src_libloc_la_LDFLAGS += -export-symbols $(top_srcdir)/src/libloc.sym
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
	src/python/location/importer.py \
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
	$(PYTHON_CFLAGS)

src_python__location_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

src_python__location_la_LIBADD = \
	src/libloc.la \
	$(PYTHON_LIBS)

# Compile & install bindings
all-local: $(foreach binding,$(BINDINGS),build-$(binding))
check-local: $(foreach binding,$(BINDINGS),check-$(binding))
install-exec-local: $(foreach binding,$(BINDINGS),install-$(binding))
clean-local: $(foreach binding,$(BINDINGS),clean-$(binding))
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
	cd $(builddir)/src/perl && $(MAKE) LD_LIBRARY_PATH="$(abs_builddir)/src/.libs" test \
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

# Use systemd timers if available
if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	src/systemd/location-update.service \
	src/systemd/location-update.timer

CLEANFILES += \
	$(systemdsystemunit_DATA)

INSTALL_DIRS += \
	$(systemdsystemunitdir)

# Otherwise fall back to cron
else
cron_daily_SCRIPTS = \
	src/cron/location-update

CLEANFILES += \
	$(cron_daily_DATA)
endif

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

TESTS_CFLAGS = \
	$(AM_CFLAGS) \
	-DLIBLOC_PRIVATE \
	-DABS_SRCDIR=\"$(abs_srcdir)\"

TESTS_LDADD = \
	src/libloc.la \
	src/libloc-internal.la

TESTS_ENVIRONMENT = \
	PYTHONPATH=$(abs_srcdir)/src/python:$(abs_builddir)/src/python/.libs \
	TEST_DATA_DIR="$(abs_top_srcdir)/data"

TESTS = \
	$(check_PROGRAMS) \
	$(dist_check_SCRIPTS)

CLEANFILES += \
	testdata.db

testdata.db: examples/python/create-database.py
	PYTHONPATH=$(abs_srcdir)/src/python:$(abs_builddir)/src/python/.libs \
	ABS_SRCDIR="$(abs_srcdir)" \
		$(PYTHON) $< $@

dist_check_SCRIPTS = \
	tests/python/test-database.py \
	tests/python/test-export.py

check_PROGRAMS = \
	src/test-libloc \
	src/test-stringpool \
	src/test-database \
	src/test-as \
	src/test-network \
	src/test-network-list \
	src/test-country \
	src/test-signature \
	src/test-address

src_test_libloc_SOURCES = \
	src/test-libloc.c

src_test_libloc_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_libloc_LDADD = \
	$(TESTS_LDADD)

src_test_as_SOURCES = \
	src/test-as.c

src_test_as_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_as_LDADD = \
	$(TESTS_LDADD)

src_test_country_SOURCES = \
	src/test-country.c

src_test_country_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_country_LDADD = \
	$(TESTS_LDADD)

src_test_network_SOURCES = \
	src/test-network.c

src_test_network_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_network_LDADD = \
	$(TESTS_LDADD)

src_test_network_list_SOURCES = \
	src/test-network-list.c

src_test_network_list_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_network_list_LDADD = \
	$(TESTS_LDADD)

src_test_stringpool_SOURCES = \
	src/test-stringpool.c

src_test_stringpool_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_stringpool_LDADD = \
	$(TESTS_LDADD)

src_test_database_SOURCES = \
	src/test-database.c

src_test_database_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_database_LDADD = \
	$(TESTS_LDADD)

src_test_signature_SOURCES = \
	src/test-signature.c

src_test_signature_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_signature_LDADD = \
	$(TESTS_LDADD)

src_test_address_SOURCES = \
	src/test-address.c

src_test_address_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_address_LDADD = \
	$(TESTS_LDADD)

# ------------------------------------------------------------------------------

MANPAGES = \
	$(MANPAGES_3) \
	$(MANPAGES_1)

MANPAGES_3 = \
	man/libloc.3 \
	man/loc_database_count_as.3 \
	man/loc_database_get_as.3 \
	man/loc_database_get_country.3 \
	man/loc_database_lookup.3 \
	man/loc_database_new.3 \
	man/loc_get_log_priority.3 \
	man/loc_new.3 \
	man/loc_set_log_fn.3 \
	man/loc_set_log_priority.3

MANPAGES_1 = \
	man/location.1

MANPAGES_TXT   = $(MANPAGES_TXT_3) $(MANPAGES_TXT_1)
MANPAGES_TXT_3 = $(patsubst %.3,%.txt,$(MANPAGES_3))
MANPAGES_TXT_1 = $(patsubst %.1,%.txt,$(MANPAGES_1))
MANPAGES_HTML  = $(patsubst %.txt,%.html,$(MANPAGES_TXT))
MANPAGES_XML   = $(patsubst %.txt,%.xml,$(MANPAGES_TXT))

.PHONY: man
man: $(MANPAGES) $(MANPAGES_HTML)

if ENABLE_MAN_PAGES
man_MANS = \
	$(MANPAGES)
endif

CLEANFILES += \
	$(MANPAGES) \
	$(MANPAGES_HTML) \
	$(MANPAGES_XML)

EXTRA_DIST += \
	man/asciidoc.conf \
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
upload-man: $(MANPAGES_HTML)
	rsync -avHz --delete --progress $(MANPAGES_HTML) ms@fs01.haj.ipfire.org:/pub/man-pages/$(PACKAGE_NAME)/

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
	debian/python3-location.examples \
	debian/python3-location.install \
	debian/rules \
	debian/source/format \
	debian/watch

.PHONY: debian
debian: dist
	$(SHELL) debian/build.sh $(PACKAGE_NAME)-$(PACKAGE_VERSION) $(distdir).tar.xz
