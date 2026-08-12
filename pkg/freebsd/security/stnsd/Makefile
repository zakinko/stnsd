PORTNAME=	stnsd
DISTVERSIONPREFIX=	v
DISTVERSION=	0.1.0
CATEGORIES=	security

MAINTAINER=	zakinko@snowrabbit.org
COMMENT=	Small STNS API server
WWW=		https://github.com/zakinko/stnsd

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

USE_GITHUB=	yes
GH_ACCOUNT=	zakinko

# The upstream Makefile is BSD make, so it is driven directly.  It installs
# the rc.d script into ${PREFIX}/etc/rc.d itself, with the rc.conf variable
# substituted for this system's convention, so USE_RC_SUBR is not needed.
MAKE_ARGS=	PREFIX=${PREFIX} \
		LOCALBASE=${LOCALBASE} \
		SYSCONFDIR=${PREFIX}/etc \
		CC=${CC}

TEST_TARGET=	test

.include <bsd.port.mk>
