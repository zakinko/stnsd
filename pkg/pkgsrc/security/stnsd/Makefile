# $NetBSD$

DISTNAME=	stnsd-0.1.0
CATEGORIES=	security
MASTER_SITES=	${MASTER_SITE_GITHUB:=zakinko/}
GITHUB_TAG=	v${PKGVERSION_NOREV}

MAINTAINER=	zakinko@snowrabbit.org
HOMEPAGE=	https://github.com/zakinko/stnsd/
COMMENT=	Small STNS API server
LICENSE=	2-clause-bsd

USE_LANGUAGES=	c

# The upstream Makefile is BSD make, so pkgsrc's bmake drives it directly.
MAKE_FLAGS+=	PREFIX=${PREFIX}
MAKE_FLAGS+=	LOCALBASE=${LOCALBASE}
MAKE_FLAGS+=	SYSCONFDIR=${PKG_SYSCONFBASE}
MAKE_FLAGS+=	VARBASE=${VARBASE}
MAKE_FLAGS+=	CC=${CC:Q}

# The server's configuration lives beside the client's, as it does upstream:
# security/nss_stns keeps stns/client, this keeps stns/server.
PKG_SYSCONFSUBDIR=	stns/server

# The build installs the script into share/examples/rc.d itself, which is
# where RCD_SCRIPTS expects to find it.
RCD_SCRIPTS=	stnsd

EGDIR=		${PREFIX}/share/examples/stnsd
CONF_FILES_PERMS=	${EGDIR}/stns.conf ${PKG_SYSCONFDIR}/stns.conf \
			${ROOT_USER} ${ROOT_GROUP} 0600

TEST_TARGET=	test

.include "../../mk/bsd.pkg.mk"
