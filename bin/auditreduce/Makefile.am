if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

sbin_PROGRAMS = auditreduce
auditreduce_LDADD = $(top_builddir)/libbsm/libbsm.la

auditreduce_SOURCES =		\
	auditreduce.c

noinst_HEADERS =		\
	auditreduce.h

man_MANS =			\
	auditreduce.1
EXTRA_DIST = $(man_MANS)
