/*-
 * Copyright (c) 2004 Apple Inc.
 * Copyright (c) 2006 Robert N. M. Watson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $P4: //depot/projects/trustedbsd/openbsm/libbsm/bsm_control.c#26 $
 */

#include <config/config.h>

#include <bsm/libbsm.h>

#include <errno.h>
#include <string.h>
#ifdef HAVE_PTHREAD_MUTEX_LOCK
#include <pthread.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#ifndef HAVE_STRLCAT
#include <compat/strlcat.h>
#endif
#ifndef HAVE_STRLCPY
#include <compat/strlcpy.h>
#endif

/*
 * Parse the contents of the audit_control file to return the audit control
 * parameters.  These static fields are protected by 'mutex'.
 */
static FILE	*fp = NULL;
static char	linestr[AU_LINE_MAX];
static char	*delim = ":";

static char	inacdir = 0;
static char	ptrmoved = 0;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
static pthread_mutex_t	mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/*
 * Audit policy string token table for au_poltostr() and au_strtopol().
 */
struct audit_polstr {
	long 		 ap_policy;
	const char 	*ap_str;	
};

static struct audit_polstr au_polstr[] = {
	{ AUDIT_CNT,		"cnt"		},
	{ AUDIT_AHLT,		"ahlt"		},
	{ AUDIT_ARGV,		"argv"		},
	{ AUDIT_ARGE,		"arge"		},
	{ AUDIT_SEQ,		"seq"		},
	{ AUDIT_WINDATA,	"windata"	},
	{ AUDIT_USER,		"user"		},
	{ AUDIT_GROUP,		"group"		},
	{ AUDIT_TRAIL,		"trail"		},
	{ AUDIT_PATH,		"path"		},
	{ AUDIT_SCNT,		"scnt"		},
	{ AUDIT_PUBLIC,		"public"	},
	{ AUDIT_ZONENAME,	"zonename"	},
	{ AUDIT_PERZONE,	"perzone"	},
	{ -1,			NULL		}
};

/*
 * Returns the string value corresponding to the given label from the
 * configuration file.
 *
 * Must be called with mutex held.
 */
static int
getstrfromtype_locked(char *name, char **str)
{
	char *type, *nl;
	char *tokptr;
	char *last;

	*str = NULL;

	if ((fp == NULL) && ((fp = fopen(AUDIT_CONTROL_FILE, "r")) == NULL))
		return (-1); /* Error */

	while (1) {
		if (fgets(linestr, AU_LINE_MAX, fp) == NULL) {
			if (ferror(fp))
				return (-1);
			return (0);	/* EOF */
		}

		if (linestr[0] == '#')
			continue;

		/* Remove trailing new line character. */
		if ((nl = strrchr(linestr, '\n')) != NULL)
			*nl = '\0';

		tokptr = linestr;
		if ((type = strtok_r(tokptr, delim, &last)) != NULL) {
			if (strcmp(name, type) == 0) {
				/* Found matching name. */
				*str = strtok_r(NULL, delim, &last);
				if (*str == NULL) {
					errno = EINVAL;
					return (-1); /* Parse error in file */
				}
				return (0); /* Success */
			}
		}
	}
}

/*
 * Convert a policy to a string.  Return -1 on failure, or >= 0 representing
 * the actual size of the string placed in the buffer (excluding terminating
 * nul).
 */
ssize_t
au_poltostr(long policy, size_t maxsize, char *buf)
{
	int first = 1;
	int i = 0;

	if (maxsize < 1)
		return (-1);
	buf[0] = '\0';

	do {
		if (policy & au_polstr[i].ap_policy) {
			if (!first && strlcat(buf, ",", maxsize) >= maxsize)
				return (-1);
			if (strlcat(buf, au_polstr[i].ap_str, maxsize) >=
			    maxsize)
				return (-1);
			first = 0;
		}
	} while (NULL != au_polstr[++i].ap_str);

	return (strlen(buf));
}

/*
 * Convert a string to a policy.  Return -1 on failure (with errno EINVAL,
 * ENOMEM) or 0 on success.
 */
int
au_strtopol(const char *polstr, long *policy)
{
	char *bufp, *string;
	char *buffer;
	int i, matched;

	*policy = 0;
	buffer = strdup(polstr);
	if (buffer == NULL)
		return (-1);

	bufp = buffer;
	while ((string = strsep(&bufp, ",")) != NULL) {
		matched = i = 0;

		do {
			if (strcmp(string, au_polstr[i].ap_str) == 0) {
				*policy |= au_polstr[i].ap_policy;
				matched = 1;
				break;
			}
		} while (NULL != au_polstr[++i].ap_str);

		if (!matched) {
			free(buffer);
			errno = EINVAL;
			return (-1);
		}
	}
	free(buffer);
	return (0);
}

/*
 * Rewind the file pointer to beginning.
 */
static void
setac_locked(void)
{

	ptrmoved = 1;
	if (fp != NULL)
		fseek(fp, 0, SEEK_SET);
}

void
setac(void)
{

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
}

/*
 * Close the audit_control file.
 */
void
endac(void)
{

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	ptrmoved = 1;
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
}

/*
 * Return audit directory information from the audit control file.
 */
int
getacdir(char *name, int len)
{
	char *dir;
	int ret = 0;

	/*
	 * Check if another function was called between successive calls to
	 * getacdir.
	 */
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	if (inacdir && ptrmoved) {
		ptrmoved = 0;
		if (fp != NULL)
			fseek(fp, 0, SEEK_SET);
		ret = 2;
	}
	if (getstrfromtype_locked(DIR_CONTROL_ENTRY, &dir) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (dir == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-1);
	}
	if (strlen(dir) >= (size_t)len) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-3);
	}
	strlcpy(name, dir, len);
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (ret);
}

/*
 * Return the minimum free diskspace value from the audit control file.
 */
int
getacmin(int *min_val)
{
	char *min;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
	if (getstrfromtype_locked(MINFREE_CONTROL_ENTRY, &min) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (min == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (1);
	}
	*min_val = atoi(min);
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (0);
}

/*
 * Return the desired trail rotation size from the audit control file.
 */
int
getacfilesz(size_t *filesz_val)
{
	char *filesz, *dummy;
	long long ll;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
	if (getstrfromtype_locked(FILESZ_CONTROL_ENTRY, &filesz) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (filesz == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		errno = EINVAL;
		return (1);
	}
	ll = strtoll(filesz, &dummy, 10);
	if (*dummy != '\0') {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		errno = EINVAL;
		return (-1);
	}
	/*
	 * The file size must either be 0 or >= MIN_AUDIT_FILE_SIZE.  0
	 * indicates no rotation size.
	 */
	if (ll < 0 || (ll > 0 && ll < MIN_AUDIT_FILE_SIZE)) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		errno = EINVAL;
		return (-1);
	}
	*filesz_val = ll;
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (0);
}

/*
 * Return the system audit value from the audit contol file.
 */
int
getacflg(char *auditstr, int len)
{
	char *str;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
	if (getstrfromtype_locked(FLAGS_CONTROL_ENTRY, &str) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (str == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (1);
	}
	if (strlen(str) >= (size_t)len) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-3);
	}
	strlcpy(auditstr, str, len);
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (0);
}

/*
 * Return the non attributable flags from the audit contol file.
 */
int
getacna(char *auditstr, int len)
{
	char *str;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
	if (getstrfromtype_locked(NA_CONTROL_ENTRY, &str) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (str == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (1);
	}
	if (strlen(str) >= (size_t)len) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-3);
	}
	strlcpy(auditstr, str, len);
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (0);
}

/*
 * Return the policy field from the audit control file.
 */
int
getacpol(char *auditstr, size_t len)
{
	char *str;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
	if (getstrfromtype_locked(POLICY_CONTROL_ENTRY, &str) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (str == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-1);
	}
	if (strlen(str) >= len) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-3);
	}
	strlcpy(auditstr, str, len);
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (0);
}

int
getachost(char *auditstr, size_t len)
{
	char *str;

#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_lock(&mutex);
#endif
	setac_locked();
	if (getstrfromtype_locked(AUDIT_HOST_CONTROL_ENTRY, &str) < 0) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-2);
	}
	if (str == NULL) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (1);
	}
	if (strlen(str) >= len) {
#ifdef HAVE_PTHREAD_MUTEX_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		return (-3);
	}
	strlcpy(auditstr, str, len);
#ifdef HAVE_PTHREAD_MUTEX_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	return (0);
}
