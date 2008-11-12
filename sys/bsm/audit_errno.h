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
 * $P4: //depot/projects/trustedbsd/openbsm/sys/bsm/audit_errno.h#1 $
 */

#ifndef _BSM_AUDIT_ERRNO_H_
#define	_BSM_AUDIT_ERRNO_H_

/*
 * For the purposes of portable encoding, we convert between local error
 * numbers and Solaris error numbers (as well as some extensions for error
 * numbers that don't exist in Solaris).  Although the first 35 or so
 * constants are the same across all OS's, we don't handle that in any
 * special way.
 *
 * When adding constants here, also add them to bsm_errno.c.
 */
#define	BSM_EPERM		1
#define	BSM_ENOENT		2
#define	BSM_ESRCH		3
#define	BSM_EINTR		4
#define	BSM_EIO			5
#define	BSM_ENXIO		6
#define	BSM_E2BIG		7
#define	BSM_ENOEXEC		8
#define	BSM_EBADF		9
#define	BSM_ECHILD		10
#define	BSM_EAGAIN		11
#define	BSM_ENOMEM		12
#define	BSM_EACCES		13
#define	BSM_EFAULT		14
#define	BSM_ENOTBLK		15
#define	BSM_EBUSY		16
#define	BSM_EEXIST		17
#define	BSM_EXDEV		18
#define	BSM_ENODEV		19
#define	BSM_ENOTDIR		20
#define	BSM_EISDIR		21
#define	BSM_EINVAL		22
#define	BSM_ENFILE		23
#define	BSM_EMFILE		24
#define	BSM_ENOTTY		25
#define	BSM_ETXTBSY		26
#define	BSM_EFBIG		27
#define	BSM_ENOSPC		28
#define	BSM_ESPIPE		29
#define	BSM_EROFS		30
#define	BSM_EMLINK		31
#define	BSM_EPIPE		32
#define	BSM_EDOM		33
#define	BSM_ERANGE		34
#define	BSM_ENOMSG		35
#define	BSM_EIDRM		36
#define	BSM_ECHRNG		37	/* Solaris-specific. */
#define	BSM_EL2NSYNC		38	/* Solaris-specific. */
#define	BSM_EL3HLT		39	/* Solaris-specific. */
#define	BSM_EL3RST		40	/* Solaris-specific. */
#define	BSM_ELNRNG		41	/* Solaris-specific. */
#define	BSM_EUNATCH		42	/* Solaris-specific. */
#define	BSM_ENOCSI		43	/* Solaris-specific. */
#define	BSM_EL2HLT		44	/* Solaris-specific. */
#define	BSM_EDEADLK		45
#define	BSM_ENOLCK		46
#define	BSM_ECANCELED		47
#define	BSM_ENOTSUP		48
#define	BSM_EDQUOT		49
#define	BSM_EBADE		50	/* Solaris-specific. */
#define	BSM_EBADR		51	/* Solaris-specific. */
#define	BSM_EXFULL		52	/* Solaris-specific. */
#define	BSM_ENOANO		53	/* Solaris-specific. */
#define	BSM_EBADRQC		54	/* Solaris-specific. */
#define	BSM_EBADSLT		55	/* Solaris-specific. */
#define	BSM_EDEADLOCK		56	/* Solaris-specific. */
#define	BSM_EBFONT		57	/* Solaris-specific. */
#define	BSM_EOWNERDEAD		58	/* Solaris-specific. */
#define	BSM_ENOTRECOVERABLE	59	/* Solaris-specific. */
#define	BSM_ENOSTR		60	/* Solaris-specific. */
#define	BSM_ENODATA		61	/* Solaris-specific. */
#define	BSM_ETIME		62	/* Solaris-specific. */
#define	BSM_ENOSR		63	/* Solaris-specific. */
#define	BSM_ENONET		64	/* Solaris-specific. */
#define	BSM_ENOPKG		65	/* Solaris-specific. */
#define	BSM_EREMOTE		66
#define	BSM_ENOLINK		67
#define	BSM_EADV		68	/* Solaris-specific. */
#define	BSM_ESRMNT		69	/* Solaris-specific. */
#define	BSM_ECOMM		70	/* Solaris-specific. */
#define	BSM_EPROTO		71
#define	BSM_ELOCKUNMAPPED	72	/* Solaris-specific. */
#define	BSM_ENOTACTIVE		73	/* Solaris-specific. */
#define	BSM_EMULTIHOP		74
#define	BSM_EBADMSG		77
#define	BSM_ENAMETOOLONG	78
#define	BSM_EOVERFLOW		79
#define	BSM_ENOTUNIQ		80	/* Solaris-specific. */
#define	BSM_EBADFD		81	/* Solaris-specific. */
#define	BSM_EREMCHG		82	/* Solaris-specific. */
#define	BSM_ELIBACC		83	/* Solaris-specific. */
#define	BSM_ELIBBAD		84	/* Solaris-specific. */
#define	BSM_ELIBSCN		85	/* Solaris-specific. */
#define	BSM_ELIBMAX		86	/* Solaris-specific. */
#define	BSM_ELIBEXEC		87	/* Solaris-specific. */
#define	BSM_EILSEQ		88
#define	BSM_ENOSYS		89
#define	BSM_ELOOP		90
#define	BSM_ERESTART		91
#define	BSM_ESTRPIPE		92	/* Solaris-specific. */
#define	BSM_ENOTEMPTY		93
#define	BSM_EUSERS		94
#define	BSM_ENOTSOCK		95
#define	BSM_EDESTADDRREQ	96
#define	BSM_EMSGSIZE		97
#define	BSM_EPROTOTYPE		98
#define	BSM_ENOPROTOOPT		99
#define	BSM_EPROTONOSUPPORT	120
#define	BSM_ESOCKTNOSUPPORT	121
#define	BSM_EOPNOTSUPP		122
#define	BSM_EPFNOSUPPORT	123
#define	BSM_EAFNOSUPPORT	124
#define	BSM_EADDRINUSE		125
#define	BSM_EADDRNOTAVAIL	126
#define	BSM_ENETDOWN		127
#define	BSM_ENETUNREACH		128
#define	BSM_ENETRESET		129
#define	BSM_ECONNABORTED	130
#define	BSM_ECONNRESET		131
#define	BSM_ENOBUFS		132
#define	BSM_EISCONN		133
#define	BSM_ENOTCONN		134
#define	BSM_ESHUTDOWN		143
#define	BSM_ETOOMANYREFS	144
#define	BSM_ETIMEDOUT		145
#define	BSM_ECONNREFUSED	146
#define	BSM_EHOSTDOWN		147
#define	BSM_EHOSTUNREACH	148
#define	BSM_EALREADY		149
#define	BSM_EINPROGRESS		150
#define	BSM_ESTALE		151

/*
 * OpenBSM constants for error numbers not defined in Solaris.  In the event
 * that these errors are added to Solaris, we will deprecate the OpenBSM
 * numbers in the same way we do for audit event constants.
 */
#define	BSM_EPROCLIM		5000	/* FreeBSD-specific. */
#define	BSM_EBADRPC		5001	/* FreeBSD-specific. */
#define	BSM_ERPCMISMATCH	5002	/* FreeBSD-specific. */
#define	BSM_EPROGUNAVAIL	5003	/* FreeBSD-specific. */
#define	BSM_EPROGMISMATCH	5004	/* FreeBSD-specific. */
#define	BSM_EPROCUNAVAIL	5005	/* FreeBSD-specific. */
#define	BSM_EFTYPE		5006	/* FreeBSD-specific. */
#define	BSM_EAUTH		5007	/* FreeBSD-specific. */
#define	BSM_ENEEDAUTH		5008	/* FreeBSD-specific. */
#define	BSM_ENOATTR		5009	/* FreeBSD-specific. */
#define	BSM_EDOOFUS		5010	/* FreeBSD-specific. */
#define	BSM_ELAST		5011	/* FreeBSD-specific. */
#define	BSM_EJUSTRETURN		5012	/* FreeBSD-specific. */
#define	BSM_ENOIOCTL		5013	/* FreeBSD-specific. */
#define	BSM_EDIRIOCTL		5014	/* FreeBSD-specific. */

/*
 * In the event that OpenBSM doesn't have a file representation of a local
 * error number, use this.
 */
#define	BSM_UNKNOWNERR		10000	/* OpenBSM-specific. */

#endif /* !_BSM_AUDIT_ERRNO_H_ */
