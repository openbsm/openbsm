if USE_NATIVE_INCLUDES
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/sys
endif

sbin_PROGRAMS = auditd
auditd_LDADD = $(top_builddir)/libbsm/libbsm.la $(top_builddir)/libauditd/libauditd.la

auditd_SOURCES =		\
	audit_warn.c		\
	auditd.c

noinst_HEADERS =		\
	auditd.h

if USE_MACH_IPC
auditd_SOURCES +=		\
	auditd_darwin.c
nodist_auditd_SOURCES =		\
	auditd_controlServer.c	\
	audit_triggersServer.c
nodist_noinst_HEADERS =		\
	auditd_controlServer.h	\
	audit_triggersServer.h
BUILT_SOURCES = $(nodist_auditd_SOURCES) $(nodist_noinst_HEADERS)
CLEANFILES = $(BUILT_SOURCES)

auditd_controlServer.c auditd_controlServer.h: auditd_control.defs
	$(MIG) -user /dev/null -header /dev/null -server auditd_controlServer.c -sheader auditd_controlServer.h auditd_control.defs

audit_triggersServer.c audit_triggersServer.h: audit_triggers.defs
	$(MIG) -user /dev/null -header /dev/null -server audit_triggersServer.c -sheader audit_triggersServer.h audit_triggers.defs
else
auditd_SOURCES +=		\
	auditd_fbsd.c
endif

man_MANS =			\
	auditd.8
EXTRA_DIST = $(man_MANS)
