if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

sbin_PROGRAMS = praudit
praudit_SOURCES = praudit.c
praudit_LDADD = $(top_builddir)/libbsm/libbsm.la
man_MANS = praudit.1
EXTRA_DIST = $(man_MANS)
