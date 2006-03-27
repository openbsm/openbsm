/*-
 * Copyright (c) 2006 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $P4: //depot/projects/trustedbsd/openbsm/bin/auditfilterd/auditfilterd.c#3 $
 */

#include <sys/types.h>
#include <sys/time.h>

#include <config/config.h>
#ifdef HAVE_FULL_QUEUE_H
#include <sys/queue.h>
#else
#include <compat/queue.h>
#endif

#include <bsm/libbsm.h>
#include <bsm/audit_filter.h>

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "auditfilterd.h"

struct auditfilter_module_list	filter_list;
int debug, reread_config, quit;

static void
usage(void)
{

	fprintf(stderr, "auditfilterd [-c conffile] [-d] [-t trailfile]\n");
	fprintf(stderr, "  -c    Specify configuration file (default: %s)\n",
	    AUDITFILTERD_CONFFILE);
	fprintf(stderr, "  -d    Debugging mode, don't daemonize\n");
	fprintf(stderr, "  -t    Specify audit trail file (default: %s)",
	    AUDITFILTERD_TRAILFILE);
	exit(-1);
}

static void
auditfilterd_init(void)
{

	TAILQ_INIT(&filter_list);
}

static void
signal_handler(int signum)
{

	switch (signum) {
	case SIGHUP:
		reread_config++;
		break;

	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		quit++;
		break;

	}
}

static void
present_bsmrecord(struct timespec *ts, u_char *data, u_int len)
{
	struct auditfilter_module *am;

	TAILQ_FOREACH(am, &filter_list, am_list) {
		if (am->am_record != NULL)
			(*am->am_bsmrecord)(am->am_instance, ts, data, len);
	}
}

static void
present_tokens(struct timespec *ts, u_char *data, u_int len)
{
	struct auditfilter_module *am;
	u_int bytesread;
	tokenstr_t tok;

	while (bytesread < len) {
		if (au_fetch_tok(&tok, data + bytesread, len - bytesread)
		    == -1)
			break;
		bytesread += tok.len;
	}
	TAILQ_FOREACH(am, &filter_list, am_list) {

	}
}

static void
mainloop(const char *conffile, const char *trailfile, FILE *trail_fp)
{
	struct timespec ts;
	FILE *conf_fp;
	u_char *buf;
	int reclen;

	while (1) {
		/*
		 * On SIGHUP, we reread the configuration file and reopen
		 * the trail file.
		 */
		if (reread_config) {
			reread_config = 0;
			warnx("rereading configuration");
			conf_fp = fopen(conffile, "r");
			if (conf_fp == NULL)
				err(-1, "%s", conffile);
			auditfilterd_conf(conffile, conf_fp);
			fclose(conf_fp);

			fclose(trail_fp);
			trail_fp = fopen(trailfile, "r");
			if (trail_fp == NULL)
				err(-1, "%s", trailfile);
		}
		if (quit) {
			warnx("quitting");
			break;
		}

		/*
		 * For now, be relatively unrobust about incomplete records,
		 * but in the future will want to do better.  Need to look
		 * more at the right blocking and signal behavior here.
		 */
		reclen = au_read_rec(trail_fp, &buf);
		if (reclen == -1) {
			sleep(1);
			continue;
		}
		if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
			err(-1, "clock_gettime");
		present_bsmrecord(&ts, buf, reclen);
		present_tokens(&ts, buf, reclen);
		free(buf);
	}
}

int
main(int argc, char *argv[])
{
	const char *trailfile;
	const char *conffile;
	FILE *trail_fp;
	FILE *conf_fp;
	int ch;

	conffile = AUDITFILTERD_CONFFILE;
	trailfile = AUDITFILTERD_TRAILFILE;
	while ((ch = getopt(argc, argv, "c:dt:")) != -1) {
		switch (ch) {
		case 'c':
			conffile = optarg;
			break;

		case 'd':
			debug++;
			break;

		case 't':
			trailfile = optarg;
			break;

		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	trail_fp = fopen(trailfile, "r");
	if (trail_fp == NULL)
		err(-1, "%s", trailfile);

	conf_fp = fopen(conffile, "r");
	if (conf_fp == NULL)
		err(-1, "%s", conffile);

	auditfilterd_init();
	if (auditfilterd_conf(conffile, conf_fp) < 0)
		exit(-1);
	fclose(conf_fp);

	if (!debug) {
		if (daemon(0, 0) < 0)
			err(-1, "daemon");
	}

	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGTERM, signal_handler);

	mainloop(conffile, trailfile, trail_fp);

	auditfilterd_conf_shutdown();
	return (0);
}
