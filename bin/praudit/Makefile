#
# $FreeBSD$
#

CFLAGS+=	-I ../.. -I ../../libbsm
PROG=		praudit
MAN=		praudit.1
DPADD=		/usr/lib/libbsm.a
LDADD=		-lbsm
BINDIR=		/usr/sbin

.include <bsd.prog.mk>
