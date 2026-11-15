if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

sbin_PROGRAMS = auditdistd
AM_YFLAGS = -d
auditdistd_LDFLAGS = -lcrypto

BUILT_SOURCES = parse.c parse.h token.c
CLEANFILES = $(BUILT_SOURCES)

auditdistd_SOURCES =		\
	auditdistd.c		\
	parse.y			\
	pjdlog.c		\
	proto.c			\
	proto_common.c		\
	proto_socketpair.c	\
	proto_tcp.c		\
	proto_tls.c		\
	proto_uds.c		\
	receiver.c		\
	sandbox.c		\
	sender.c		\
	subr.c			\
	token.l			\
	trail.c

noinst_HEADERS =		\
	auditdistd.h		\
	faccessat.h 		\
	fstatat.h		\
	openat.h 		\
	parse.h 		\
	pjdlog.h 		\
	proto_impl.h 		\
	proto.h 		\
	renameat.h 		\
	sandbox.h 		\
	sigtimedwait.h 		\
	strndup.h 		\
	subr.h 			\
	synch.h 		\
	trail.h 		\
	unlinkat.h

man_MANS = \
	auditdistd.conf.5	\
	auditdistd.8
EXTRA_DIST = $(man_MANS)
