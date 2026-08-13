# SPDX-License-Identifier: BSD-2-Clause
#
# stnsd - a small STNS API server for NetBSD, FreeBSD and DragonFly BSD.
# Written for BSD make; run it as "make".

OS!=		uname -s

.if ${OS} == "NetBSD"
LOCALBASE?=	/usr/pkg
# pkgsrc copies rc.d scripts out of share/examples/rc.d when the administrator
# asks it to; FreeBSD ports install them ready to run.
RCDDIR?=	${PREFIX}/share/examples/rc.d
# NetBSD's rc.subr convention is "stnsd=YES" in rc.conf, FreeBSD's is
# "stnsd_enable=YES".  The script is otherwise identical, so the name of the
# variable is substituted in rather than the script being written twice.
RCVAR?=		stnsd
.elif ${OS} == "FreeBSD" || ${OS} == "DragonFly" || ${OS} == "MidnightBSD"
LOCALBASE?=	/usr/local
RCDDIR?=	${PREFIX}/etc/rc.d
RCVAR?=		stnsd_enable
.  if ${OS} == "DragonFly"
# DragonFly's base crypto library is private -- there are no openssl headers
# under /usr/include -- so TLS is built against the package instead.  Install
# it with "pkg install openssl", or build WITHOUT_TLS.
OPENSSL_PREFIX?=	${LOCALBASE}
.  endif
.else
.error stnsd supports NetBSD, FreeBSD and DragonFly BSD only, not ${OS}
.endif

PREFIX?=	${LOCALBASE}
# pkgsrc calls this PKG_SYSCONFDIR and FreeBSD ports ETCDIR; both default to
# ${PREFIX}/etc.
SYSCONFDIR?=	${PREFIX}/etc
SBINDIR?=	${PREFIX}/sbin
EXAMPLESDIR?=	${PREFIX}/share/examples/stnsd
VARBASE?=	/var

PROG=		stnsd
TEST=		unit_test
# A stand-in for Server::Starter, used by the functional tests only.
STARTER=	starter

CC?=		cc
INSTALL?=	install
CFLAGS?=	-O2 -pipe
WARNS=		-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes \
		-Wpointer-arith -Wno-unused-parameter
CPPFLAGS+=	-I${.CURDIR}/src -I${.CURDIR}/external/mit/tomlc99 \
		-DSTNSD_CONFDIR=\"${SYSCONFDIR}\"

# TLS comes from OpenSSL: the base system's on NetBSD and FreeBSD, the
# package's on DragonFly, whose base crypto is private.  In pkgsrc the package
# includes
# security/openssl/buildlink3.mk instead of assuming that, which is what makes
# PREFER_PKGSRC=yes get the pkgsrc one.
#
# "make WITHOUT_TLS=yes" drops it, for a machine that terminates TLS elsewhere
# and would rather not have the library mapped into a process holding every
# password hash it serves.  Such a build refuses to start on a configuration
# that asks for TLS, rather than serving it in the clear.
# OPENSSL_PREFIX points the build at an OpenSSL that is not on the compiler's
# own search path: the package on DragonFly, whose base crypto is private;
# pkgsrc's, on a machine set up with PREFER_PKGSRC=yes; a homebrew one while
# developing.  Left empty, the search path is used, which is what finds the
# base library on NetBSD and FreeBSD.  The pkgsrc
# package does not set it: buildlink3 puts the right one in front of the
# compiler wrapper, and honours PREFER_PKGSRC itself.
OPENSSL_PREFIX?=	# empty

.if defined(WITHOUT_TLS)
CPPFLAGS+=	-DSTNSD_NO_TLS
.else
LIBS+=		-lssl -lcrypto
.  if !empty(OPENSSL_PREFIX)
CPPFLAGS+=	-I${OPENSSL_PREFIX}/include
LDFLAGS+=	-L${OPENSSL_PREFIX}/lib -Wl,-rpath,${OPENSSL_PREFIX}/lib
.  endif
.endif

CORE_OBJS=	src/acl.o \
		src/github.o \
		src/config.o \
		src/model.o \
		src/json.o \
		src/http.o \
		src/tls.o \
		src/log.o \
		external/mit/tomlc99/toml.o

OBJS=		${CORE_OBJS} src/main.o tests/unit_test.o tests/starter.o

# Every object depends on the header, because a struct that changes shape
# under an object that was not rebuilt is a bug that only appears at run time,
# in whichever field happens to land on the old offset.  CI never sees it -- it
# always builds from nothing -- so it is the developer's build that suffers.
# One line per object: a list of targets sharing a dependency does not reliably
# give it to all of them.
.for _obj in ${OBJS}
${_obj}: ${.CURDIR}/src/stnsd.h
.endfor
external/mit/tomlc99/toml.o: ${.CURDIR}/external/mit/tomlc99/toml.h

all: ${PROG} rc.d/stnsd

.SUFFIXES: .c .o

.c.o:
	${CC} ${CFLAGS} ${WARNS} ${CPPFLAGS} -c ${.IMPSRC} -o ${.TARGET}

${PROG}: ${CORE_OBJS} src/main.o
	${CC} -o ${.TARGET} ${CORE_OBJS} src/main.o ${LDFLAGS} ${LIBS}

${TEST}: ${CORE_OBJS} tests/unit_test.o
	${CC} -o ${.TARGET} ${CORE_OBJS} tests/unit_test.o ${LDFLAGS} ${LIBS}

${STARTER}: tests/starter.o
	${CC} -o ${.TARGET} tests/starter.o ${LDFLAGS}

rc.d/stnsd: rc.d/stnsd.in
	sed -e 's|@PREFIX@|${PREFIX}|g' \
	    -e 's|@SYSCONFDIR@|${SYSCONFDIR}|g' \
	    -e 's|@VARBASE@|${VARBASE}|g' \
	    -e 's|@RCVAR@|${RCVAR}|g' \
	    ${.CURDIR}/rc.d/stnsd.in > ${.TARGET}
	chmod 755 ${.TARGET}

# The unit tests, then the daemon put through its paces on a real socket.
test: ${TEST} ${PROG} ${STARTER}
	./${TEST}
	STARTER=./${STARTER} sh ${.CURDIR}/tests/functional.sh ./${PROG}

# The test that decides whether "compatible" is true: the same configuration
# served by this and by upstream STNS, and every answer compared.  Needs the
# upstream binary in ${STNS} or in ${PATH}.
compat: ${PROG}
	sh ${.CURDIR}/tests/compat.sh ./${PROG}

# Check the bundled third party code against external/MANIFEST.  Add
# --upstream to also ask github whether the recorded revision is current.
external:
	sh ${.CURDIR}/tests/check_external.sh

# Stage an install and diff it against the packing lists, which live in the
# packaging overlays rather than here.  See tests/check_plist.sh for where it
# looks for them.
plist: all
	sh ${.CURDIR}/tests/check_plist.sh

# The unit tests under AddressSanitizer, which is where a parser's bugs show.
asan:
	${CC} -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
		${WARNS} ${CPPFLAGS} \
		src/acl.c src/github.c src/config.c src/model.c src/json.c src/http.c \
		src/tls.c src/log.c \
		external/mit/tomlc99/toml.c tests/unit_test.c \
		${LDFLAGS} ${LIBS} -o ${TEST}-asan
	./${TEST}-asan

install: install-prog install-rcd install-conf

install-prog: ${PROG}
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m 555 ${PROG} ${DESTDIR}${SBINDIR}/${PROG}

install-rcd: rc.d/stnsd
	${INSTALL} -d ${DESTDIR}${RCDDIR}
	${INSTALL} -m 555 rc.d/stnsd ${DESTDIR}${RCDDIR}/stnsd

# The sample lives under share/examples the way pkgsrc and ports expect; the
# real file is left for the administrator to write, because it is the whole
# directory and nobody should inherit somebody else's.
install-conf:
	${INSTALL} -d ${DESTDIR}${EXAMPLESDIR}
	${INSTALL} -m 644 ${.CURDIR}/stns.conf.example ${DESTDIR}${EXAMPLESDIR}/stns.conf
	${INSTALL} -d ${DESTDIR}${SYSCONFDIR}/stns/server

deinstall:
	rm -f ${DESTDIR}${SBINDIR}/${PROG}
	rm -f ${DESTDIR}${RCDDIR}/stnsd
	rm -f ${DESTDIR}${EXAMPLESDIR}/stns.conf

clean:
	rm -f ${OBJS} ${PROG} ${TEST} ${TEST}-asan ${STARTER} rc.d/stnsd

.PHONY: all test compat external plist asan install install-prog install-rcd \
	install-conf deinstall clean
