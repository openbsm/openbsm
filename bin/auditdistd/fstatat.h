/*-
 * Copyright (c) 2012 The FreeBSD Foundation
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_FSTATAT_H_
#define	_FSTATAT_H_

#include <sys/stat.h>

#include <unistd.h>

#define	AT_SYMLINK_NOFOLLOW	0x01

static int
fstatat(int fd, const char *path, struct stat *buf, int flag)
{
	int cfd, error, ret;

	cfd = open(".", O_RDONLY | O_DIRECTORY);
	if (cfd == -1)
		return (-1);

	if (fchdir(fd) == -1) {
		error = errno;
		(void)close(cfd);
		errno = error;
		return (-1);
	}

	if (flag == AT_SYMLINK_NOFOLLOW)
		ret = lstat(path, buf);
	else
		ret = stat(path, buf);

	error = errno;
	(void)fchdir(cfd);
	(void)close(cfd);
	errno = error;
	return (ret);
}

#endif	/* !_FSTATAT_H_ */
