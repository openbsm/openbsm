if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

lib_LTLIBRARIES = libauditd.la

libauditd_la_SOURCES = \
	auditd_lib.c

man_MANS = libauditd.3
EXTRA_DIST = $(man_MANS)
