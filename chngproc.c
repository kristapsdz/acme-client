/*	$Id$ */
/*
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif

#include "extern.h"

#define SUB "challengeproc"

static void
dowarn(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn(SUB, fmt, ap);
	va_end(ap);
}

static void
dodbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg(SUB, fmt, ap);
	va_end(ap);
}

int
chngproc(int netsock, const char *root)
{
	int		 rc;
	long		 op;
	char		*tok, *thumb;
	FILE		*f;

	rc = 0;
	thumb = tok = NULL;
	f = NULL;

#ifdef __APPLE__
	/*
	 * We would use "pure computation", which is correct, but then
	 * we wouldn't be able to chroot().
	 * This call also can't happen after the chroot(), so we're
	 * stuck with a weaker sandbox.
	 */
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL)) {
		dowarn("sandbox_init");
		goto out;
	}
#endif
	/*
	 * Jails: start with file-system.
	 */
	if (-1 == chroot(root)) {
		dowarn("%s: chroot", root);
		goto out;
	} else if (-1 == chdir("/")) {
		dowarn("/: chdir");
		goto out;
	}

#if defined(__OpenBSD__) && OpenBSD >= 201605
	/* 
	 * On OpenBSD, we won't use anything more than what we've
	 * inherited from our open descriptors.
	 */
	if (-1 == pledge("stdio cpath wpath", NULL)) {
		dowarn("pledge");
		goto out;
	}
#endif
	/* Wait til we're triggered to start. */

	if (0 == (op = readop(SUB, netsock, COMM_CHNG))) 
		goto out;
	else if (LONG_MAX == op)
		goto out;

	/* Read the thumbprint and token. */

	if (NULL == (thumb = readstr(SUB, netsock, COMM_THUMB)))
		goto out;
	else if (NULL == (tok = readstr(SUB, netsock, COMM_TOK)))
		goto out;

	/* Create our challenge file. */

	if (NULL == (f = fopen(tok, "wx"))) {
		dowarn("%s", tok);
		goto out;
	} else if (-1 == fprintf(f, "%s.%s", tok, thumb)) {
		dowarn("%s", tok);
		goto out;
	} else if (-1 == fclose(f)) {
		dowarn("%s", tok);
		goto out;
	}

	dodbg("%s/%s: created", root, tok);
	fclose(f);
	f = NULL;

	/* Write our acknowledgement. */

	if ( ! writeop(SUB, netsock, COMM_CHNG_ACK, 1))
		goto out;

	/* Read that we should clean up. */

	if (0 == (op = readop(SUB, netsock, COMM_CHNG_FIN))) 
		goto out;
	else if (LONG_MAX == op)
		goto out;

	rc = 1;
out:
	if (NULL != f)
		fclose(f);
	if (NULL != tok && -1 == remove(tok) && ENOENT != errno)
		dowarn("%s", tok);
	free(thumb);
	free(tok);
	close(netsock);
	return(rc);
}
