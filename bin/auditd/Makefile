#
# $P4: //depot/projects/trustedbsd/openbsm/bin/auditd/Makefile#1 $
#

CFLAGS+=	-I- -I ../.. -I ../../libbsm -L ../../libbsm -I.
PROG=		auditd
MAN=		auditd.8
DPADD=		/usr/lib/libbsm.a
LDADD=		-lbsm
BINDIR=		/usr/sbin

.include <bsd.prog.mk>
