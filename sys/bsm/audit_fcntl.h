/*-
 * Copyright (c) 2009 Apple Inc.
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
 * $P4: //depot/projects/trustedbsd/openbsm/sys/bsm/audit_fcntl.h#1 $
 */

#ifndef	_BSM_AUDIT_FCNTL_H_
#define	_BSM_AUDIT_FCNTL_H_

/*
 * Shared and Solaris-specific: (0-99).
 */
#define	BSM_F_DUPFD		0
#define	BSM_F_GETFD		1
#define	BSM_F_SETFD		2
#define	BSM_F_GETFL		3
#define	BSM_F_SETFL		4
#define	BSM_F_O_GETLK		5	/* Solaris-specific. */
#define	BSM_F_SETLK		6
#define	BSM_F_SETLKW		7
#define	BSM_F_CHKFL		8	/* Solaris-specific */
#define	BSM_F_DUP2FD		9	/* Solaris-specific */
#define	BSM_F_ALLOCSP		10	/* Solaris-specific */
#define	BSM_F_FREESP		11	/* Solaris-specific */

#define	BSM_F_ISSTREAM		13	/* Solaris-specific */
#define	BSM_F_GETLK		14	
#define	BSM_F_PRIV		15	/* Solaris-specific */
#define	BSM_F_NPRIV		16	/* Solaris-specific */
#define	BSM_F_QUOTACTL		17	/* Solaris-specific */
#define	BSM_F_BLOCKS		18	/* Solaris-specific */
#define	BSM_F_BLKSIZE		19	/* Solaris-specific */

#define	BSM_F_GETOWN		23
#define	BSM_F_SETOWN		24
#define	BSM_F_REVOKE		25	/* Solaris-specific */
#define	BSM_F_HASREMOTELOCKS	26	/* Solaris-specific */
#define	BSM_F_FREESP64		27	/* Solaris-specific */
#define	BSM_F_ALLOCSP64		28	/* Solaris-specific */

#define	BSM_F_GETLK64		33	/* Solaris-specific */
#define	BSM_F_SETLK64		34	/* Solaris-specific */
#define	BSM_F_SETLKW64		35	/* Solaris-specific */

#define	BSM_F_SHARE		40	/* Solaris-specific */
#define	BSM_F_UNSHARE		41 	/* Solaris-specific */
#define	BSM_F_SETLK64_NBMAND	42	/* Solaris-specific */
#define	BSM_F_SHARE_NBMAND	43	/* Solaris-specific */
#define	BSM_F_SETLK_NBMAND	44 	/* Solaris-specific */

#define	BSM_F_BADFD		46	/* Solaris-specific */

/*
 * FreeBSD-specific (100-199).
 */
#define	BSM_F_OGETLK		107	/* FreeBSD-specific */
#define	BSM_F_OSETLK		108	/* FreeBSD-specific */
#define	BSM_F_OSETLKW		109	/* FreeBSD-specific */

#define	BSM_F_SETLK_REMOTE	114	/* FreeBSD-specific */

/*
 * Darwin-specific (200-299).
 */
#define	BSM_F_CHKCLEAN 		241	/* Darwin-specific */
#define	BSM_F_PREALLOCATE	242	/* Darwin-specific */
#define	BSM_F_SETSIZE		243	/* Darwin-specific */
#define	BSM_F_RDADVISE		244	/* Darwin-specific */
#define	BSM_F_RDAHEAD		245	/* Darwin-specific */
#define	BSM_F_READBOOTSTRAP	246	/* Darwin-specific */
#define	BSM_F_WRITEBOOTSTRAP	247	/* Darwin-specific */
#define	BSM_F_NOCACHE		248	/* Darwin-specific */
#define	BSM_F_LOG2PHYS		249	/* Darwin-specific */
#define	BSM_F_GETPATH		250	/* Darwin-specific */
#define	BSM_F_FULLFSYNC		251	/* Darwin-specific */
#define	BSM_F_PATHPKG_CHECK	252	/* Darwin-specific */
#define	BSM_F_FREEZE_FS		253	/* Darwin-specific */
#define	BSM_F_THAW_FS		254	/* Darwin-specific */
#define	BSM_F_GLOBAL_NOCACHE	255	/* Darwin-specific */
#define	BSM_F_OPENFROM		256	/* Darwin-specific */
#define	BSM_F_UNLINKFROM	257	/* Darwin-specific */
#define	BSM_F_CHECK_OPENEVT	258	/* Darwin-specific */
#define	BSM_F_ADDSIGS		259	/* Darwin-specific */
#define	BSM_F_MARKDEPENDENCY	260	/* Darwin-specific */

/*
 * Linux-specific (300-399).
 */
#define	BSM_F_SETSIG		310	/* Linux-specific */
#define	BSM_F_GETSIG		311	/* Linux-specific */

#define	BSM_F_UNKNOWN		500

#endif /* !_BSM_AUDIT_FCNTL_H_ */
