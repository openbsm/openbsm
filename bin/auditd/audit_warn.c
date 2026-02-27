/*-
 * Copyright (c) 2005-2009 Apple Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "auditd.h"

#ifndef __DECONST
#define __DECONST(type, var)    ((type)(uintptr_t)(const void *)(var))
#endif
#ifndef nitems
#define nitems(x)       (sizeof((x)) / sizeof((x)[0]))
#endif

/*
 * Write an audit-related error to the system log via syslog(3).
 */
static int
auditwarnlog(int count, ...)
{
	char *loc_args[9];
	va_list ap;
	pid_t pid;
	int i;

	/*
	 * execv's prototype wrongly takes the arguments as mutable, rather
	 * than const pointers.  deconstify them to make the compiler happy.
	 */
	loc_args[0] = __DECONST(char*, AUDITWARN_SCRIPT);
	va_start(ap, count);
	for (i = 0; i < count && i < nitems(loc_args) - 1; i++)
		loc_args[i + 1] = __DECONST(char*, va_arg(ap, const char*));
	loc_args[i + 1] = NULL;

	pid = fork();
	if (pid == -1)
		return (-1);
	if (pid == 0) {
		execv(AUDITWARN_SCRIPT, loc_args);
		syslog(LOG_ERR, "Could not exec %s (%m)\n", AUDITWARN_SCRIPT);
		exit(1);
	}
	/*
	 * Parent.
	 */
	return (0);
}

/*
 * Indicates that the hard limit for all filesystems has been exceeded.
 */
int
audit_warn_allhard(void)
{
	return (auditwarnlog(1, HARDLIM_ALL_WARN));
}

/*
 * Indicates that the soft limit for all filesystems has been exceeded.
 */
int
audit_warn_allsoft(void)
{
	return (auditwarnlog(1, SOFTLIM_ALL_WARN));
}

/*
 * Indicates that someone other than the audit daemon turned off auditing.
 * XXX Its not clear at this point how this function will be invoked.
 *
 * XXXRW: This function is not used.
 */
int
audit_warn_auditoff(void)
{
	return (auditwarnlog(1, AUDITOFF_WARN));
}

/*
 * Indicates that a trail file has been closed, so can now be post-processed.
 */
int
audit_warn_closefile(char *filename)
{
	return (auditwarnlog(2, CLOSEFILE_WARN, filename));
}

/*
 * Indicates that the audit daemon is already running
 */
int
audit_warn_ebusy(void)
{
	return (auditwarnlog(1, EBUSY_WARN));
}

/*
 * Indicates that there is a problem getting the directory from
 * audit_control.
 *
 * XXX Note that we take the filename instead of a count as the argument here
 * (different from BSM).
 */
int
audit_warn_getacdir(char *filename)
{
	return (auditwarnlog(2, GETACDIR_WARN, filename));
}

/*
 * Indicates that the hard limit for this file has been exceeded.
 */
int
audit_warn_hard(char *filename)
{
	return (auditwarnlog(2, HARDLIM_WARN, filename));
}

/*
 * Indicates that auditing could not be started.
 */
int
audit_warn_nostart(void)
{
	return (auditwarnlog(1, NOSTART_WARN));
}

/*
 * Indicates that an error occurred during the orderly shutdown of the audit
 * daemon.
 */
int
audit_warn_postsigterm(void)
{
	return (auditwarnlog(1, POSTSIGTERM_WARN));
}

/*
 * Indicates that the soft limit for this file has been exceeded.
 */
int
audit_warn_soft(char *filename)
{
	return (auditwarnlog(2, SOFTLIM_WARN, filename));
}

/*
 * Indicates that the temporary audit file already exists resulting in a fatal
 * error.
 */
int
audit_warn_tmpfile(void)
{
	return (auditwarnlog(1, TMPFILE_WARN));
}

/*
 * Indicates that this trail file has expired and was removed.
 */
int
audit_warn_expired(char *filename)
{
	return (auditwarnlog(2, EXPIRED_WARN, filename));
}
