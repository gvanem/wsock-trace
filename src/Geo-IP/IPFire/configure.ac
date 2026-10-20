AC_PREREQ(2.60)
AC_INIT([libloc],
        [0.9.19],
        [location@lists.ipfire.org],
        [libloc],
        [https://www.ipfire.org/location/])

AC_CONFIG_SRCDIR([src/libloc.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([
	foreign
	1.11
	-Wall
	-Wno-portability
	silent-rules
	tar-pax
	subdir-objects
])
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT([
	disable-static
	pic-only
])
AC_PREFIX_DEFAULT([/usr])
gl_LD_VERSION_SCRIPT

AM_GNU_GETTEXT_VERSION(0.21)
AM_GNU_GETTEXT([external])

IT_PROG_INTLTOOL([0.40.0])

# Interpret embedded Python in HTML files
XGETTEXT="${XGETTEXT} -L Python --keyword=_:1,2 --keyword=N_:1,2 --no-location"

GETTEXT_PACKAGE=${PACKAGE_TARNAME}
AC_SUBST(GETTEXT_PACKAGE)

AC_PROG_SED
AC_PROG_MKDIR_P

# - man ------------------------------------------------------------------------

have_man_pages=no
AC_ARG_ENABLE(man_pages, AS_HELP_STRING([--disable-man-pages],
	[do not install man pages]))
AS_IF([test "x$enable_man_pages" != xno], [have_man_pages=yes])
AM_CONDITIONAL(ENABLE_MAN_PAGES, [test "x$have_man_pages" = "xyes"])

AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_CHECK_PROGS(ASCIIDOC, [asciidoc])
if test "${have_man_pages}" = "yes" && test -z "${ASCIIDOC}"; then
	AC_MSG_ERROR([Required program 'asciidoc' not found])
fi

# - pkg-config -----------------------------------------------------------------

m4_ifndef([PKG_PROG_PKG_CONFIG],
	[m4_fatal([Could not locate the pkg-config autoconf
		macros. These are usually located in /usr/share/aclocal/pkg.m4.
		If your macros are in a different location, try setting the
		environment variable AL_OPTS="-I/other/macro/dir" before running
		./autogen.sh or autoreconf again. Make sure pkg-config is installed.])])

PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR(['${usrlib_execdir}/pkgconfig'])

# - bash-completion ------------------------------------------------------------

#enable_bash_completion=yes
AC_ARG_WITH([bashcompletiondir],
	AS_HELP_STRING([--with-bashcompletiondir=DIR], [Bash completions directory]),
	[],
	[AS_IF([`$PKG_CONFIG --exists bash-completion`], [
		with_bashcompletiondir=`$PKG_CONFIG --variable=completionsdir bash-completion`
	], [
		with_bashcompletiondir=${datadir}/bash-completion/completions
	])
])

AC_SUBST([bashcompletiondir], [$with_bashcompletiondir])

AC_ARG_ENABLE([bash-completion],
	AS_HELP_STRING([--disable-bash-completion], [do not install bash completion files]),
	[], [enable_bash_completion=yes]
)

AM_CONDITIONAL([BUILD_BASH_COMPLETION], [test "x$enable_bash_completion" = xyes])

# - debug ----------------------------------------------------------------------

AC_ARG_ENABLE([debug],
        AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
        [], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], [
        AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
])

dnl Switch to enable build with address sanitization
AC_ARG_ENABLE([asan],
	AS_HELP_STRING([--enable-asan], [build with -fsanitize=address @<:@default=disabled@:>@]),
	[],
	[enable_asan=no]
)

dnl Switch to enable build with the undefined behavior sanitizer
AC_ARG_ENABLE([ubsan],
	AS_HELP_STRING([--enable-ubsan], [build with -fsanitize=undefined @<:@default=disabled@:>@]),
	[],
	[enable_ubsan=no]
)

dnl Switch to build the fuzzers
AC_ARG_ENABLE([fuzzing],
	AS_HELP_STRING([--enable-fuzzing], [build the fuzzers (requires clang) @<:@default=disabled@:>@]),
	[],
	[enable_fuzzing=no]
)

dnl Switch to enable build with --coverage
AC_ARG_ENABLE([coverage],
	AS_HELP_STRING([--enable-coverage], [build with --coverage @<:@default=disabled@:>@]),
	[], [enable_coverage=no])

AC_CHECK_HEADERS_ONCE([
	arpa/inet.h \
	arpa/nameser.h \
	arpa/nameser_compat.h \
	endian.h \
	netinet/in.h \
	resolv.h \
	string.h \
])

AC_CHECK_FUNCS([ \
	be16toh \
	be32toh \
	be64toh \
	htobe16 \
	htobe32 \
	htobe64 \
	madvise \
	mmap \
	munmap \
	res_query \
	__secure_getenv \
	secure_getenv \
	qsort \
])

CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
	-std=gnu17 \
	-Wall \
	-Wextra \
	-Warray-bounds=2 \
	-Wbad-function-cast \
	-Wcomma \
	-Wdate-time \
	-Wdouble-promotion \
	-Wduplicated-branches \
	-Wduplicated-cond \
	-Wendif-labels \
	-Werror=format=2 \
	-Werror=format-signedness \
	-Werror=implicit-function-declaration \
	-Werror=implicit-int \
	-Werror=incompatible-pointer-types \
	-Werror=int-conversion \
	-Werror=missing-declarations \
	-Werror=missing-prototypes \
	-Werror=overflow \
	-Werror=override-init \
	-Werror=return-type \
	-Werror=shift-count-overflow \
	-Werror=shift-overflow=2 \
	-Werror=switch \
	-Werror=strict-flex-arrays \
	-Werror=undef \
	-Wfloat-equal \
	-Wformat-overflow=2 \
	-Wimplicit-fallthrough=5 \
	-Winit-self \
	-Wlogical-op \
	-Wloop-analysis \
	-Wmissing-include-dirs \
	-Wmissing-noreturn \
	-Wnested-externs \
	-Wnull-dereference \
	-Wold-style-definition \
	-Wpointer-arith \
	-Wredundant-decls \
	-Wshadow \
	-Wstrict-aliasing=2 \
	-Wstrict-prototypes \
	-Wstringop-overflow=4 \
	-Wsuggest-attribute=noreturn \
	-Wtautological-compare \
	-Wtrampolines \
	-Wunused-const-variable \
	-Wunused-function \
	-Wvla \
	-Wwrite-strings \
	-Wzero-length-bounds \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers \
	-fdiagnostics-show-option \
	-fno-common \
])

# --as-needed / --gc-sections are GNU ld flags. Apple's ld ignores them with a
# warning, which the link probe can't detect, so only offer them off-Darwin.
AS_CASE([$host_os],
	[darwin*], [],
	[
		CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [\
			-Wl,--as-needed \
			-Wl,--gc-sections \
		])
	]
)

# Enable -fno-semantic-interposition (if available)
CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [-fno-semantic-interposition])
CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [-fno-semantic-interposition])

# Enable -fanalyzer if requested
AC_ARG_ENABLE([analyzer],
	AS_HELP_STRING([--enable-analyzer], [enable static analyzer (-fanalyzer) @<:@default=disabled@:>@]),
	[], [enable_analyzer=no])
AS_IF([test "x$enable_analyzer" = "xyes"],
	CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [-fanalyzer])
)

AC_SUBST([OUR_CFLAGS], $with_cflags)
AC_SUBST([OUR_LDFLAGS], $with_ldflags)

dnl Check for support for -fsanitize=address
if test "x${enable_asan}" = "xyes"; then
	CC_CHECK_FLAGS_APPEND([asan_cflags],  [CFLAGS],  [-fsanitize=address])
	CC_CHECK_FLAGS_APPEND([asan_ldflags], [LDFLAGS], [-fsanitize=address])
fi

dnl Check for support for -fsanitize=undefined
if test "x${enable_ubsan}" = "xyes"; then
	CC_CHECK_FLAGS_APPEND([asan_cflags],  [CFLAGS],  [-fsanitize=undefined -fno-sanitize-recover=undefined])
	CC_CHECK_FLAGS_APPEND([asan_ldflags], [LDFLAGS], [-fsanitize=undefined])
fi

dnl The fuzzers need everything to be instrumented, but only they are being
dnl linked against the fuzzing engine (which brings its own main function).
if test "x${enable_fuzzing}" = "xyes"; then
	CC_CHECK_FLAGS_APPEND([asan_cflags], [CFLAGS], [-fsanitize=fuzzer-no-link])

	AS_IF([test "x${asan_cflags}" = "x${asan_cflags%fuzzer-no-link}"], [
		AC_MSG_ERROR([*** The compiler does not support -fsanitize=fuzzer-no-link. Fuzzing requires clang.])
	])

	CC_CHECK_FLAGS_APPEND([asan_ldflags], [LDFLAGS], [-fsanitize=fuzzer-no-link])
fi

AM_CONDITIONAL([ENABLE_FUZZING], [test "x${enable_fuzzing}" = "xyes"])

dnl The interpreters of the bindings are not linked against the sanitizers, so
dnl that their runtime has to be preloaded if we want to load our modules. They
dnl also leak memory by design, which is why we cannot check for any leaks there.
bindings_test_env=""

if test "x${enable_asan}" = "xyes"; then
	asan_runtime="$(${CC} -print-file-name=libasan.so)"

	dnl Clang has a different name for it
	AS_CASE([${asan_runtime}], [*/*], [], [
		asan_runtime="$(${CC} -print-file-name=libclang_rt.asan-$(uname -m).so)"
	])

	bindings_test_env="LD_PRELOAD=${asan_runtime} ASAN_OPTIONS=detect_leaks=0"
fi

AC_SUBST([BINDINGS_TEST_ENV], ${bindings_test_env})

AC_SUBST([ASAN_CFLAGS], ${asan_cflags})
AC_SUBST([ASAN_LDFLAGS], ${asan_ldflags})

dnl Check for support for --coverage
if test "x${enable_coverage}" = "xyes"; then
	CC_CHECK_FLAGS_APPEND([coverage_cflags],  [CFLAGS],  [--coverage])
	CC_CHECK_FLAGS_APPEND([coverage_ldflags], [LDFLAGS], [--coverage])

	dnl Count correctly when more than one thread runs the same code
	CC_CHECK_FLAGS_APPEND([coverage_cflags],  [CFLAGS],  [-fprofile-update=atomic])
	CC_CHECK_FLAGS_APPEND([coverage_ldflags], [LDFLAGS], [-fprofile-update=atomic])
fi

AC_SUBST([COVERAGE_CFLAGS],  ${coverage_cflags})
AC_SUBST([COVERAGE_LDFLAGS], ${coverage_ldflags})

# ------------------------------------------------------------------------------

AC_ARG_WITH([database-path],
	AS_HELP_STRING([--with-database-path], [The default database path]),
	[], [with_database_path=/var/lib/location/database.db]
)

if test -z "${with_database_path}"; then
	AC_MSG_ERROR([The default database path is empty])
fi

AC_DEFINE_UNQUOTED([LIBLOC_DEFAULT_DATABASE_PATH], ["${with_database_path}"],
	[The default path for the database])
AC_SUBST([DEFAULT_DATABASE_PATH], [${with_database_path}])

AC_ARG_WITH([systemd],
	AS_HELP_STRING([--with-systemd],
		[install the systemd units that update the database @<:@default=auto@:>@]),
	[], [with_systemd=auto]
)

# The units are only files that we install and we don't need anything from
# systemd to build. So we only look for it if nobody has told us what to do.
AS_CASE([$with_systemd],
	[yes], [have_systemd=yes],
	[no],  [have_systemd=no],
	[PKG_CHECK_MODULES([systemd], [libsystemd], [have_systemd=yes], [have_systemd=no])]
)

AM_CONDITIONAL(HAVE_SYSTEMD, [test "x$have_systemd" = "xyes"])

# ------------------------------------------------------------------------------

# Python
AM_PATH_PYTHON([3.4])
PKG_CHECK_MODULES([PYTHON], [python-${PYTHON_VERSION}])

# Lua
AC_ARG_ENABLE(lua,
	AS_HELP_STRING([--disable-lua], [do not build the Lua modules]), [], [enable_lua=yes])

AS_IF(
	[test "x$enable_lua" = "xyes"], [
		for lua in lua lua5.4 lua5.3 lua5.2 lua5.1; do
			PKG_CHECK_MODULES([LUA], [${lua}], [break], [true])
		done

		LUA_VERSION=$($PKG_CONFIG --variable=major_version ${lua})
		if test -z "${LUA_VERSION}"; then
			LUA_VERSION=$($PKG_CONFIG --variable=V ${lua})
		fi

		# Not everybody has those variables (Alpine Linux for example), but
		# we can always take the first two parts of the version of the package
		if test -z "${LUA_VERSION}"; then
			LUA_VERSION=$($PKG_CONFIG --modversion ${lua} | $SED -n 's/^\(@<:@0-9@:>@*\.@<:@0-9@:>@*\).*/\1/p')
		fi

		# Fail if we could not find anything to link against
		if test "x${LUA_VERSION}" = "x"; then
			AC_MSG_ERROR([Could not find Lua])
		fi

		AC_SUBST(LUA_VERSION)

		LUA_INSTALL_LMOD=$($PKG_CONFIG --define-variable=prefix=${prefix} --variable=INSTALL_LMOD ${lua})
		if test -z "${LUA_INSTALL_LMOD}"; then
			LUA_INSTALL_LMOD="${datadir}/lua/${LUA_VERSION}"
		fi
		AC_SUBST(LUA_INSTALL_LMOD)

		LUA_INSTALL_CMOD=$($PKG_CONFIG --define-variable=prefix=${prefix} --variable=INSTALL_CMOD ${lua})
		if test -z "${LUA_INSTALL_CMOD}"; then
			LUA_INSTALL_CMOD="${libdir}/lua/${LUA_VERSION}"
		fi
		AC_SUBST(LUA_INSTALL_CMOD)

		# The tests are being run by the Lua interpreter of the system that we
		# are building on, which cannot load a module that we have built for
		# another architecture.
		AS_IF([test "x$cross_compiling" = "xyes"], [
			AC_MSG_WARN([cross-compiling, won't run the Lua tests])
		], [
			# The interpreter does not have the same name everywhere
			AC_CHECK_PROGS([LUA], [lua${LUA_VERSION} lua])

			AX_PROG_LUA_MODULES([luaunit], [enable_lua_tests=yes],
				[AC_MSG_WARN([luaunit is missing, won't run tests])])
		])
	],
)

AM_CONDITIONAL(ENABLE_LUA, [test "x$enable_lua" = "xyes"])
AM_CONDITIONAL(ENABLE_LUA_TESTS, [test "x$enable_lua_tests" = "xyes"])

# Perl
AC_PATH_PROG(PERL, perl, no)
AC_SUBST(PERL)

AX_PROG_PERL_MODULES(Config ExtUtils::MakeMaker,, AC_MSG_WARN(Need some Perl modules))

AC_ARG_ENABLE(perl, AS_HELP_STRING([--disable-perl], [do not build the perl modules]), [],[enable_perl=yes])
AM_CONDITIONAL(ENABLE_PERL, test "$enable_perl" = "yes")
AS_IF([test "$enable_perl" = "yes"],
      [
       PERL_MODPATH=$($PERL -MConfig -e 'print $Config{installvendorarch}')
       PERL_MANPATH=$($PERL -MConfig -e 'print $Config{installvendorman3dir}')
       AC_SUBST(PERL_MODPATH)
       AC_SUBST(PERL_MANPATH)
       ],
)

dnl Checking for libresolv
case "${host}" in
	*-gnu*)
		AC_CHECK_LIB(resolv, ns_msg_getflag, [LIBS="-lresolv $LIBS"], AC_MSG_ERROR([libresolv has not been found]), -lresolv)
		;;
	*)
		AC_CHECK_LIB(resolv, res_init, [LIBS="-lresolv $LIBS"], AC_MSG_ERROR([libresolv has not been found]), -lresolv)
		;;
esac
RESOLV_LIBS="${LIBS}"
AC_SUBST(RESOLV_LIBS)

dnl Checking for OpenSSL
PKG_CHECK_MODULES([OPENSSL], [openssl])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
        Makefile
        po/Makefile.in
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}

        database path:          ${with_database_path}
        debug:                  ${enable_debug}
        address sanitizer:      ${enable_asan}
        undefined behavior:     ${enable_ubsan}
        fuzzing:                ${enable_fuzzing}
        coverage:               ${enable_coverage}
        systemd support:        ${have_systemd}
	bash-completion:        ${enable_bash_completion}

	Bindings:
	  Lua:			${enable_lua}
	  Lua shared path:	${LUA_INSTALL_LMOD}
	  Lua module path:	${LUA_INSTALL_CMOD}
	  Perl:			${enable_perl}
	  Perl module path:     ${PERL_MODPATH}
	  Perl manual path:     ${PERL_MANPATH}
])
