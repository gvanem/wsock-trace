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

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-I${top_srcdir}/src

AM_CFLAGS = ${my_CFLAGS} \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS =

# leaving a space here to work around automake's conditionals
 ifeq ($(OS),Darwin)
	AM_LDFLAGS += -Wl,-dead_strip
 else
	AM_LDFLAGS += \
		-Wl,--as-needed \
		-Wl,--gc-sections
 endif

LIBLOC_CURRENT=1
LIBLOC_REVISION=0
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
	src/loc/libloc.h \
	src/loc/as.h \
	src/loc/as-list.h \
	src/loc/compat.h \
	src/loc/country.h \
	src/loc/country-list.h \
	src/loc/database.h \
	src/loc/format.h \
	src/loc/network.h \
	src/loc/network-list.h \
	src/loc/private.h \
	src/loc/stringpool.h \
	src/loc/resolv.h \
	src/loc/writer.h

lib_LTLIBRARIES = \
	src/libloc.la

src_libloc_la_SOURCES = \
	src/libloc.c \
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

pkgconfig_DATA = \
	src/libloc.pc

EXTRA_DIST += \
	src/libloc.pc.in

CLEANFILES += \
	src/libloc.pc

dist_pkgpython_PYTHON = \
	src/python/database.py \
	src/python/downloader.py \
	src/python/export.py \
	src/python/i18n.py \
	src/python/importer.py \
	src/python/logger.py

pkgpython_PYTHON = \
	src/python/__init__.py

EXTRA_DIST += \
	src/python/__init__.py.in

CLEANFILES += \
	src/python/__init__.py

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

.PHONY: build-perl
build-perl:
	@mkdir -p $(builddir)/src/perl/{lib,t}
	@test -e $(builddir)/src/perl/Location.xs || ln -s --relative $(srcdir)/src/perl/Location.xs $(builddir)/src/perl/
	@test -e $(builddir)/src/perl/MANIFEST || ln -s --relative $(srcdir)/src/perl/MANIFEST $(builddir)/src/perl/
	@test -e $(builddir)/src/perl/Makefile.PL || ln -s --relative $(srcdir)/src/perl/Makefile.PL $(builddir)/src/perl/
	@test -e $(builddir)/src/perl/lib/Location.pm || ln -s --relative $(srcdir)/src/perl/lib/Location.pm $(builddir)/src/perl/lib/
	@test -e $(builddir)/src/perl/t/Location.t || ln -s --relative $(srcdir)/src/perl/t/Location.t $(builddir)/src/perl/t/
	@test -e $(builddir)/src/perl/typemap || ln -s --relative $(srcdir)/src/perl/typemap $(builddir)/src/perl/

	cd $(builddir)/src/perl && $(PERL) Makefile.PL PREFIX="$(prefix)" \
		INC="-I$(abs_srcdir)/src" LIBS="-L$(abs_builddir)/src/.libs -lloc"
	cd $(builddir)/src/perl && $(MAKE) LD_RUN_PATH=

.PHONY: check-perl
check-perl: testdata.db
	cd $(builddir)/src/perl && $(MAKE) LD_LIBRARY_PATH="$(abs_builddir)/src/.libs" test \
		database="../../$<" keyfile="$(abs_srcdir)/examples/public-key.pem"

.PHONY: install-perl
install-perl:
	cd $(builddir)/src/perl && $(MAKE) install DESTIDR=$(DESTDIR)

.PHONY: clean-perl
clean-perl:
	cd $(builddir)/src/perl && $(MAKE) distclean

.PHONY: uninstall-perl
uninstall-perl:
	rm -rvf \
		$(DESTDIR)/$(prefix)/lib/*/perl/*/Location.pm \
		$(DESTDIR)/$(prefix)/lib/*/perl/*/auto/Location \
		$(DESTDIR)/$(prefix)/lib/*/perl/*/perllocal.pod \
		$(DESTDIR)/$(prefix)/man/man3/Location.3pm

bin_SCRIPTS = \
	src/python/location \
	src/python/location-importer

EXTRA_DIST += \
	src/python/location.in \
	src/python/location-importer.in

CLEANFILES += \
	src/python/location \
	src/python/location-importer

# ------------------------------------------------------------------------------

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	src/systemd/location-update.service \
	src/systemd/location-update.timer

CLEANFILES += \
	$(systemdsystemunit_DATA)

INSTALL_DIRS += \
	$(systemdsystemunitdir)
endif

EXTRA_DIST += \
	src/systemd/location-update.service.in \
	src/systemd/location-update.timer.in

# ------------------------------------------------------------------------------

dist_database_DATA = \
	src/signing-key.pem

# ------------------------------------------------------------------------------

TESTS_CFLAGS = \
	$(AM_CFLAGS) \
	-DLIBLOC_PRIVATE \
	-DABS_SRCDIR=\"$(abs_srcdir)\"

TESTS = \
	src/test-libloc \
	src/test-stringpool \
	src/test-database \
	src/test-as \
	src/test-network \
	src/test-country \
	src/test-signature

CLEANFILES += \
	testdata.db

testdata.db: examples/python/create-database.py
	PYTHONPATH=$(abs_builddir)/src/python/.libs \
	ABS_SRCDIR="$(abs_srcdir)" \
		$(PYTHON) $< $@

check_PROGRAMS = \
	src/test-libloc \
	src/test-stringpool \
	src/test-database \
	src/test-as \
	src/test-network \
	src/test-network-list \
	src/test-country \
	src/test-signature

src_test_libloc_SOURCES = \
	src/test-libloc.c

src_test_libloc_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_libloc_LDADD = \
	src/libloc.la

src_test_as_SOURCES = \
	src/test-as.c

src_test_as_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_as_LDADD = \
	src/libloc.la

src_test_country_SOURCES = \
	src/test-country.c

src_test_country_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_country_LDADD = \
	src/libloc.la

src_test_network_SOURCES = \
	src/test-network.c

src_test_network_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_network_LDADD = \
	src/libloc.la

src_test_network_list_SOURCES = \
	src/test-network-list.c

src_test_network_list_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_network_list_LDADD = \
	src/libloc.la

src_test_stringpool_SOURCES = \
	src/test-stringpool.c

src_test_stringpool_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_stringpool_LDADD = \
	src/libloc.la

src_test_database_SOURCES = \
	src/test-database.c

src_test_database_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_database_LDADD = \
	src/libloc.la

src_test_signature_SOURCES = \
	src/test-signature.c

src_test_signature_CFLAGS = \
	$(TESTS_CFLAGS)

src_test_signature_LDADD = \
	src/libloc.la

# ------------------------------------------------------------------------------

MANPAGES = \
	man/location.8

MANPAGES_TXT  = $(patsubst %.8,%.txt,$(MANPAGES))
MANPAGES_HTML = $(patsubst %.txt,%.html,$(MANPAGES_TXT))
MANPAGES_XML  = $(patsubst %.txt,%.xml,$(MANPAGES_TXT))

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

man/%.8: man/%.xml
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
	debian/compat \
	debian/control \
	debian/copyright \
	debian/location.install \
	debian/location.manpages \
	debian/location-python.install \
	debian/libloc1.install \
	debian/libloc-dev.install \
	debian/rules \
	debian/source/format

.PHONY: debian
debian: dist
	$(SHELL) debian/build.sh $(PACKAGE_NAME)-$(PACKAGE_VERSION) $(distdir).tar.xz
