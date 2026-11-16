if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

sbin_PROGRAMS = audit
audit_LDADD = $(top_builddir)/libbsm/libbsm.la

audit_SOURCES =			\
	audit.c

if USE_MACH_IPC
nodist_audit_SOURCES =		\
	auditd_controlUser.c
nodist_noinst_HEADERS =		\
	auditd_control.h
BUILT_SOURCES = $(nodist_audit_SOURCES) $(nodist_noinst_HEADERS)
CLEANFILES = $(BUILT_SOURCES)

auditd_srcdir = $(top_srcdir)/bin/auditd

auditd_controlUser.c auditd_control.h: $(auditd_srcdir)/auditd_control.defs
	$(MIG)	-user auditd_controlUser.c -header auditd_control.h -server /dev/null -sheader /dev/null $(auditd_srcdir)/auditd_control.defs
endif

man_MANS =			\
	audit.8
EXTRA_DIST = $(man_MANS)
