#
# $FreeBSD$
#

CFLAGS+=	-I ../.. -I ../../libbsm
PROG=		auditreduce
MAN=		auditreduce.1
DPADD=		/usr/lib/libbsm.a
LDADD=		-lbsm
BINDIR=		/usr/sbin

.include <bsd.prog.mk>
