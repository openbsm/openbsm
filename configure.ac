#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([OpenBSM], [1.0a5], [trustedbsd-audit@TrustesdBSD.org],[openbsm])
AC_REVISION($P4: //depot/projects/trustedbsd/openbsm/configure.ac#1 $)
AC_CONFIG_SRCDIR([bin/auditreduce/auditreduce.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lbsm':
AC_CHECK_LIB([bsm], [main])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h mach/mach.h netinet/in.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h sys/endian.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero ftruncate gettimeofday inet_ntoa memset strchr strerror strrchr strstr strtol strtoul])

AC_CONFIG_FILES([Makefile
                 bin/Makefile
                 bin/audit/Makefile
                 bin/auditd/Makefile
                 bin/auditreduce/Makefile
                 bin/praudit/Makefile
                 bsm/Makefile
                 libbsm/Makefile
                 man/Makefile
                 tools/Makefile])

AC_OUTPUT
