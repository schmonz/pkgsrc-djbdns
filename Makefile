# $NetBSD: Makefile,v 1.76 2025/05/22 04:51:28 schmonz Exp $

DISTNAME=		djbdns-1.05
PKGREVISION=		16
CATEGORIES=		net
MASTER_SITES=		http://cr.yp.to/djbdns/
MANPAGES_DIST=		${DISTNAME}-man-20031023.tar.gz
DISTFILES=		${DISTNAME}${EXTRACT_SUFX} ${MANPAGES_DIST}
SITES.${MANPAGES_DIST}=	http://smarden.org/pape/djb/manpages/

MAINTAINER=		schmonz@NetBSD.org
HOMEPAGE=		https://cr.yp.to/djbdns.html
COMMENT=		Collection of secure and reliable DNS tools
LICENSE=		public-domain

CONFLICTS+=		djbdnscurve6-[0-9]*

FORCE_C_STD=		c89

DJB_ERRNO_FIXUP=	error.h

SUBST_CLASSES+=		etc
SUBST_STAGE.etc=	do-configure
SUBST_FILES.etc=	dns_rcrw.c
SUBST_SED.etc=		-e 's|/etc/dnsrewrite|${PKG_SYSCONFBASE}/dnsrewrite|g'
SUBST_MESSAGE.etc=	Fixing prefix.

EGDIR=			${PREFIX}/share/examples/${PKGBASE}
CPPFLAGS+=		-DPKG_SYSCONFDIR="\"${PKG_SYSCONFDIR}\""
MAKE_DIRS+=		${PKG_SYSCONFDIR}
CONF_FILES+=		${EGDIR}/dnsroots.global ${PKG_SYSCONFDIR}/dnsroots.global
BUILD_DEFS+=		PKG_SYSCONFBASE

INSTALLATION_DIRS=	bin ${PKGMANDIR}/man1 ${PKGMANDIR}/man5 ${PKGMANDIR}/man8 share/examples/${PKGBASE}

.include "options.mk"

post-install:
	cd ${WRKDIR}/${PKGBASE}-man; for i in 1 5 8; do		 	\
		for j in *.$$i; do ${INSTALL_MAN} $$j			\
			${DESTDIR}${PREFIX}/${PKGMANDIR}/man$$i; done	\
	done

.include "../../mk/djbware.mk"
.include "../../mk/bsd.pkg.mk"
