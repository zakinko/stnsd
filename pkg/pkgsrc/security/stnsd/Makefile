# $NetBSD$

DISTNAME=	stnsd-0.2.0
CATEGORIES=	security
MASTER_SITES=	${MASTER_SITE_GITHUB:=zakinko/}
GITHUB_TAG=	v${PKGVERSION_NOREV}

MAINTAINER=	zakinko@snowrabbit.org
HOMEPAGE=	https://github.com/zakinko/stnsd/
COMMENT=	Small STNS API server
LICENSE=	2-clause-bsd

USE_LANGUAGES=	c

# The upstream Makefile is BSD make, so pkgsrc's bmake drives it directly.
# It appends stns/server to SYSCONFDIR itself, which is why the base is
# handed over rather than PKG_SYSCONFDIR.
MAKE_FLAGS+=	PREFIX=${PREFIX}
MAKE_FLAGS+=	LOCALBASE=${PREFIX}
MAKE_FLAGS+=	SYSCONFDIR=${PKG_SYSCONFBASE}
MAKE_FLAGS+=	VARBASE=${VARBASE}
MAKE_FLAGS+=	CC=${CC:Q}

BUILD_DEFS+=	PKG_SYSCONFBASE VARBASE

# The server's configuration lives beside the client's, as it does upstream:
# security/nss_stns keeps stns/client, this keeps stns/server.
PKG_SYSCONFSUBDIR=	stns/server

# The build installs the rc.d script into share/examples/rc.d itself, paths
# and rc.conf variable already substituted, so the automatic generation from
# files/stnsd.sh is turned off by emptying its source.  RCD_SCRIPTS is still
# what registers the script: it is what copies it into /etc/rc.d when
# PKG_RCD_SCRIPTS=YES, removes it again on deinstall, and adds it to the
# packing list -- which is why PLIST does not mention it.
RCD_SCRIPTS=		stnsd
RCD_SCRIPT_SRC.stnsd=	# empty

EGDIR=		${PREFIX}/share/examples/stnsd

# ${PKG_SYSCONFDIR} is added to the install script's directory list on our
# behalf, but with an empty owner, group and mode unless this says otherwise
# -- and a configuration file cannot be created into a directory that was
# never made.  The directory is ordinary; the file in it is not.
PKG_SYSCONFDIR_PERMS=	${REAL_ROOT_USER} ${REAL_ROOT_GROUP} 0755

# Root owned and unreadable to anyone else: this is the file the password
# hashes go in.
CONF_FILES_PERMS=	${EGDIR}/stns.conf ${PKG_SYSCONFDIR}/stns.conf \
			${REAL_ROOT_USER} ${REAL_ROOT_GROUP} 0600

TEST_TARGET=	test

# Which OpenSSL this builds against is buildlink3's decision, not ours: the
# base one where it is good enough, pkgsrc's where the administrator asked for
# that with PREFER_PKGSRC=yes.  The compiler wrapper then puts the right
# headers and libraries in front of the build, so OPENSSL_PREFIX stays unset.
.include "../../security/openssl/buildlink3.mk"
.include "../../mk/bsd.pkg.mk"
