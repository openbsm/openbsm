if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

sbin_PROGRAMS = auditfilterd
auditfilterd_LDADD = $(top_builddir)/libbsm/libbsm.la

auditfilterd_SOURCES =		\
	auditfilterd_conf.c	\
	auditfilterd.c

noinst_HEADERS =		\
	auditfilterd.h

man_MANS =			\
	auditfilterd.8
EXTRA_DIST = $(man_MANS)
