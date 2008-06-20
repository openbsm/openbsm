#
# $P4: //depot/projects/trustedbsd/openbsm/bin/audit/Makefile.am#2 $
#

INCLUDES = -I$(top_srcdir)

sbin_PROGRAMS = audit
audit_LDADD = $(top_builddir)/libbsm/libbsm.la
man8_MANS = audit.8

if USE_MACH_IPC
audit_SOURCES = auditd_control_user.c audit.c
CLEANFILES = auditd_control_user.c auditd_control_user.h

auditd_control_user.c: auditd_control.defs 
	$(MIG)	-user auditd_control_user.c -header auditd_control_user.h -server /dev/null -sheader /dev/null auditd_control.defs
else
audit_SOURCES = audit.c
endif
