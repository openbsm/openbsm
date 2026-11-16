ACLOCAL_AMFLAGS = -I m4

SUBDIRS =		\
	bsm		\
	compat		\
	sys		\
	libbsm

if HAVE_AUDIT_SYSCALLS
SUBDIRS +=              \
	libauditd
endif

SUBDIRS +=		\
	bin		\
	man		\
	modules		\
	test		\
	tools

EXTRA_DIST =		\
	NEWS		\
	LICENSE		\
	README		\
	TODO		\
	VERSION
