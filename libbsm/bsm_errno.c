/*-
 * Copyright (c) 2008 Apple Inc.
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
 * $P4: //depot/projects/trustedbsd/openbsm/libbsm/bsm_errno.c#1 $
 */

#include <sys/types.h>

#include <config/config.h>
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#else /* !HAVE_SYS_ENDIAN_H */
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#else /* !HAVE_MACHINE_ENDIAN_H */
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#else /* !HAVE_ENDIAN_H */
#error "No supported endian.h"
#endif /* !HAVE_ENDIAN_H */
#endif /* !HAVE_MACHINE_ENDIAN_H */
#include <compat/endian.h>
#endif /* !HAVE_SYS_ENDIAN_H */

#include <bsm/audit_errno.h>

#include <errno.h>

/*
 * Different operating systems use different numeric constants for different
 * error numbers, and sometimes error numbers don't exist in more than one
 * operating system.  These routines convert between BSM and local error
 * number spaces, subject to the above realities.  BSM error numbers are
 * always stored in network byte order.
 */

struct bsm_errors {
	int	be_bsm_error;
	int	be_os_error;
};

/*
 * Mapping table -- please maintain in numeric sorted order with respect to
 * the BSM constant.  Today we do a linear lookup, but could switch to a
 * binary search if it makes sense.  We only ifdef errors that aren't
 * generally available.
 *
 * XXXRW: It would be nice to have a similar ordered table mapping to BSM
 * constant from local constant, but the order of local constants varies by
 * OS.  Really we need to build that table at compile-time but don't do that
 * yet.
 */
static const struct bsm_errors bsm_errors[] = {
	{ BSM_EPERM, EPERM },
	{ BSM_ENOENT, ENOENT },
	{ BSM_ESRCH, ESRCH },
	{ BSM_EINTR, EINTR },
	{ BSM_EIO, EIO },
	{ BSM_ENXIO, ENXIO },
	{ BSM_E2BIG, E2BIG },
	{ BSM_ENOEXEC, ENOEXEC },
	{ BSM_EBADF, EBADF },
	{ BSM_ECHILD, ECHILD },
	{ BSM_EAGAIN, EAGAIN },
	{ BSM_ENOMEM, ENOMEM },
	{ BSM_EACCES, EACCES },
	{ BSM_EFAULT, EFAULT },
	{ BSM_ENOTBLK, ENOTBLK },
	{ BSM_EBUSY, EBUSY },
	{ BSM_EEXIST, EEXIST },
	{ BSM_EXDEV, EXDEV },
	{ BSM_ENODEV, ENODEV },
	{ BSM_ENOTDIR, ENOTDIR },
	{ BSM_EISDIR, EISDIR },
	{ BSM_EINVAL, EINVAL },
	{ BSM_ENFILE, ENFILE },
	{ BSM_EMFILE, EMFILE },
	{ BSM_ENOTTY, ENOTTY },
	{ BSM_ETXTBSY, ETXTBSY },
	{ BSM_EFBIG, EFBIG },
	{ BSM_ENOSPC, ENOSPC },
	{ BSM_ESPIPE, ESPIPE },
	{ BSM_EROFS, EROFS },
	{ BSM_EMLINK, EMLINK },
	{ BSM_EPIPE, EPIPE },
	{ BSM_EDOM, EDOM },
	{ BSM_ERANGE, ERANGE },
	{ BSM_ENOMSG, ENOMSG },
	{ BSM_EIDRM, EIDRM },
#ifdef ECHRNG
	{ BSM_ECHRNG, ECHRNG },
#endif
#ifdef EL2NSYNC
	{ BSM_EL2NSYNC, EL2NSYNC },
#endif
#ifdef EL3HLT
	{ BSM_EL3HLT, EL3HLT },
#endif
#ifdef EL3RST
	{ BSM_EL3RST, EL3RST },
#endif
#ifdef ELNRNG
	{ BSM_ELNRNG, ELNRNG },
#endif
#ifdef EUNATCH
	{ BSM_EUNATCH, EUNATCH },
#endif
#ifdef ENOCSI
	{ BSM_ENOCSI, ENOCSI },
#endif
#ifdef EL2HLT
	{ BSM_EL2HLT, EL2HLT }.
#endif
	{ BSM_EDEADLK, EDEADLK },
	{ BSM_ENOLCK, ENOLCK },
	{ BSM_ECANCELED, ECANCELED },
	{ BSM_ENOTSUP, ENOTSUP },
	{ BSM_EDQUOT, EDQUOT },
#ifdef EBADE
	{ BSM_EBADE, EBADE },
#endif
#ifdef EBADR
	{ BSM_EBADR, EBADR },
#endif
#ifdef EXFULL
	{ BSM_EXFULL, EXFULL },
#endif
#ifdef ENOANO
	{ BSM_ENOANO, ENOANO },
#endif
#ifdef EBADRQC
	{ BSM_EBADRQC, EBADRQC },
#endif
#ifdef EBADSLT
	{ BSM_EBADSLT, EBADSLT },
#endif
#ifdef EDEADLOCK
	{ BSM_EDEADLOCK, EDEADLOCK },
#endif
#ifdef EBFONT
	{ BSM_EBFONT, EBFONT },
#endif
#ifdef EOWNERDEAD
	{ BSM_EOWNERDEAD, EOWNERDEAD },
#endif
#ifdef ENOTRECOVERABLE
	{ BSM_ENOTRECOVERABLE, ENOTRECOVERABLE },
#endif
#ifdef ENOSTR
	{ BSM_ENOSTR, ENOSTR },
#endif
#ifdef ENONET
	{ BSM_ENONET, ENONET },
#endif
#ifdef ENOPKG
	{ BSM_ENOPKG, ENOPKG },
#endif
	{ BSM_EREMOTE, EREMOTE },
	{ BSM_ENOLINK, ENOLINK },
#ifdef EADV
	{ BSM_EADV, EADV },
#endif
#ifdef ESRMNT
	{ BSM_ESRMNT, ESRMNT },
#endif
#ifdef ECOMM
	{ BSM_ECOMM, ECOMM },
#endif
	{ BSM_EPROTO, EPROTO },
#ifdef ELOCKUNMAPPED
	{ BSM_ELOCKUNMAPPED, ELOCKUNMAPPED },
#endif
#ifdef ENOTACTIVE
	{ BSM_ENOTACTIVE, ENOTACTIVE },
#endif
	{ BSM_EMULTIHOP, EMULTIHOP },
	{ BSM_EBADMSG, EBADMSG },
	{ BSM_ENAMETOOLONG, ENAMETOOLONG },
	{ BSM_EOVERFLOW, EOVERFLOW },
#ifdef ENOTUNIQ
	{ BSM_ENOTUNIQ, ENOTUNIQ },
#endif
#ifdef EBADFD
	{ BSM_EBADFD, EBADFD },
#endif
#ifdef EREMCHG
	{ BSM_EREMCHG, EREMCHG },
#endif
#ifdef ELIBACC
	{ BSM_ELIBACC, ELIBACC },
#endif
#ifdef ELIBBAD
	{ BSM_ELIBBAD, ELIBBAD },
#endif
#ifdef ELIBSCN
	{ BSM_ELIBSCN, ELIBSCN },
#endif
#ifdef ELIBMAX
	{ BSM_ELIBMAX, ELIBMAX },
#endif
#ifdef ELIBEXEC
	{ BSM_ELIBEXEC, ELIBEXEC },
#endif
	{ BSM_EILSEQ, EILSEQ },
	{ BSM_ENOSYS, ENOSYS },
	{ BSM_ELOOP, ELOOP },
#ifdef ERESTART
	{ BSM_ERESTART, ERESTART },
#endif
#ifdef ESTRPIPE
	{ BSM_ESTRPIPE, ESTRPIPE },
#endif
	{ BSM_ENOTEMPTY, ENOTEMPTY },
	{ BSM_EUSERS, EUSERS },
	{ BSM_ENOTSOCK, ENOTSOCK },
	{ BSM_EDESTADDRREQ, EDESTADDRREQ },
	{ BSM_EMSGSIZE, EMSGSIZE },
	{ BSM_EPROTOTYPE, EPROTOTYPE },
	{ BSM_ENOPROTOOPT, ENOPROTOOPT },
	{ BSM_EPROTONOSUPPORT, EPROTONOSUPPORT },
	{ BSM_ESOCKTNOSUPPORT, ESOCKTNOSUPPORT },
	{ BSM_EOPNOTSUPP, EOPNOTSUPP },
	{ BSM_EPFNOSUPPORT, EPFNOSUPPORT },
	{ BSM_EAFNOSUPPORT, EAFNOSUPPORT },
	{ BSM_EADDRINUSE, EADDRINUSE },
	{ BSM_EADDRNOTAVAIL, EADDRNOTAVAIL },
	{ BSM_ENETDOWN, ENETDOWN },
	{ BSM_ENETRESET, ENETRESET },
	{ BSM_ECONNABORTED, ECONNABORTED },
	{ BSM_ECONNRESET, ECONNRESET },
	{ BSM_ENOBUFS, ENOBUFS },
	{ BSM_EISCONN, EISCONN },
	{ BSM_ENOTCONN, ENOTCONN },
	{ BSM_ESHUTDOWN, ESHUTDOWN },
	{ BSM_ETOOMANYREFS, ETOOMANYREFS },
	{ BSM_ETIMEDOUT, ETIMEDOUT },
	{ BSM_ECONNREFUSED, ECONNREFUSED },
	{ BSM_EHOSTDOWN, EHOSTDOWN },
	{ BSM_EHOSTUNREACH, EHOSTUNREACH },
	{ BSM_EALREADY, EALREADY },
	{ BSM_EINPROGRESS, EINPROGRESS },
	{ BSM_ESTALE, ESTALE },
};
static const int bsm_errors_count = sizeof(bsm_errors) / sizeof(bsm_errors[0]);

int
au_bsm_to_errno(int bsm_error)
{
	int i;

	bsm_error = be32toh(bsm_error);
	for (i = 0; i < bsm_errors_count; i++) {
		if (bsm_errors[i].be_bsm_error == bsm_error)
			return (bsm_errors[i].be_os_error);
	}

	/*
	 * If there is no local match, return EINVAL.  Perhaps there is
	 * something better we could be doing here?
	 */
	return (EINVAL);
}

int
au_errno_to_bsm(int error)
{
	int i;

	for (i = 0; i < bsm_errors_count; i++) {
		if (bsm_errors[i].be_os_error == error)
			return (htobe32(bsm_errors[i].be_bsm_error));
	}
	return (htobe32(BSM_UNKNOWNERR));
}
