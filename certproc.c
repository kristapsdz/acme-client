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
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif

#include "extern.h"

int
certproc(int netsock, const char *certdir)
{
	char		*csr, *csr64;
	size_t		 csrsz, csr64sz;
	int		 rc;
	extern enum comp proccomp;

	proccomp = COMP_CERT;
	csr = csr64 = NULL;
	rc = 0;

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
		goto error;
	}
#endif
	/*
	 * Jails: start with file-system.
	 * Go into the usual place.
	 */
	if (-1 == chroot(certdir)) {
		dowarn("%s: chroot", certdir);
		goto error;
	} else if (-1 == chdir("/")) {
		dowarn("/: chdir");
		goto error;
	}

#if defined(__OpenBSD__) && OpenBSD >= 201605
	if (-1 == pledge("stdio cpath wpath", NULL)) {
		dowarn("pledge");
		goto error;
	}
#endif

	if (NULL == (csr = readbuf(netsock, COMM_CSR, &csrsz)))
		goto error;

	csr64sz = base64len(csrsz);
	if (NULL == (csr64 = malloc(csr64sz))) {
		dowarn("malloc");
		goto error;
	}

	base64buf(csr64, csr, csrsz);
	fprintf(stderr, "%s", csr64);

	rc = 1;
error:
	free(csr);
	free(csr64);
	close(netsock);
	return(rc);
}

