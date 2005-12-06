#
# $FreeBSD$
#

CFLAGS+=	-I- -I .. -I ../libbsm -L ../libbsm -I.
PROG=		audump
NO_MAN=
DPADD=		/usr/lib/libbsm.a
LDADD=		-lbsm
BINDIR=		/usr/sbin

.include <bsd.prog.mk>
