#
# $P4: //depot/projects/trustedbsd/openbsm/bin/auditfilterd/Makefile.am#2 $
#

INCLUDES = -I$(top_builddir) -I$(top_srcdir)

sbin_PROGRAMS = auditfilterd
auditfilterd_SOURCES = auditfilterd_conf.c auditfilterd.c
auditfilterd_LDADD = $(top_builddir)/libbsm/libbsm.la
man8_MANS = auditfilterd.8
