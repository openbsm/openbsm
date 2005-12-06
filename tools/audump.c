/*-
 * Copyright (c) 2005 Robert N. M. Watson
 * All rights reserved.
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
 */

#include <bsm/libbsm.h>
#include <limits.h>
#include <stdio.h>

/*
 * Simple tool to dump various /etc/security databases using the defined APIs.
 */

static void
usage(void)
{

	fprintf(stderr, "usage: dump [class|control|event|user]\n");
	exit(-1);
}

static void
audump_class(void)
{
	au_class_ent_t *c;

	while ((c = getauclassent()) != NULL)
		printf("0x%08x:%s:%s\n", c->ac_class, c->ac_name, c->ac_desc);
}

static void
audump_control(void)
{
	char string[PATH_MAX];
	int ret, val;

	ret = getacflg(string, PATH_MAX);
	if (ret == -2)
		err(-1, "getacflg");
	if (ret != 0)
		errx(-1, "getacflg: %d", ret);

	printf("flags:%s\n", string);

	ret = getacmin(&val);
	if (ret == -2)
		err(-1, "getacmin");
	if (ret != 0)
		errx(-1, "getacmin: %d", ret);

	printf("min:%d\n", val);

	ret = getacna(string, PATH_MAX);
	if (ret == -2)
		err(-1, "getacna");
	if (ret != 0)
		errx(-1, "getacna: %d", ret);

	printf("naflags:%s\n", string);

	setac();
	do {
		ret = getacdir(string, PATH_MAX);
		if (ret == -1)
			break;
		if (ret == -2)
			err(-1, "getacdir");
		if (ret != 0)
			errx(-1, "getacdir: %d", ret);
		printf("dir:%s\n", string);

	} while (ret == 0);
}

static void
printf_classmask(au_class_t classmask)
{
	au_class_ent_t *c;
	u_int32_t i;
	int first;

	first = 1;
	for (i = 0; i < 32; i++) {
		if (classmask & (2 << i)) {
			if (first)
				first = 0;
			else
				printf(",");
			c = getauclassnum(2 << i);
			if (c != NULL) {
				printf("%s", c->ac_name);
				free_au_class_ent(c);
			} else
				printf("0x%x", 2 << i);
		}
	}
}

static void
audump_event(void)
{
	au_event_ent_t *e;

	while ((e = getauevent()) != NULL) {
		printf("%d:%s:%s:", e->ae_number, e->ae_name, e->ae_desc);
		printf_classmask(e->ae_class);
		printf("\n");
		free_au_event_ent(e);
	}
}

static void
audump_user(void)
{
	au_user_ent_t *u;

	while ((u = getauuserent()) != NULL) {
		printf("%s:", u->au_name);
		printf_classmask(u->au_always);
		printf(":");
		printf_classmask(u->au_never);
		printf("\n");
	}
}

int
main(int argc, char *argv[])
{

	if (argc != 2)
		usage();

	if (strcmp(argv[1], "class") == 0)
		audump_class();
	else if (strcmp(argv[1], "control") == 0)
		audump_control();
	else if (strcmp(argv[1], "event") == 0)
		audump_event();
	else if (strcmp(argv[1], "user") == 0)
		audump_user();
	else
		usage();

	return (0);
}
