#
# $FreeBSD$
#

CFLAGS+=	-I- -I ../.. -I ../../libbsm -I.
PROG=		praudit
MAN=		praudit.1
DPADD=		/usr/lib/libbsm.a
LDADD=		-lbsm
BINDIR=		/usr/sbin

.include <bsd.prog.mk>
