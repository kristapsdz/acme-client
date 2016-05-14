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

#define	CERT_PEM "cert.pem"
#define	CERT_PEM_BAK "cert.pem~"

int
fileproc(int certsock, const char *certdir)
{
	char		*csr;
	int		 rc;
	FILE		*f;

	csr = NULL;
	rc = 0;
	f = NULL;

	/* File-system and sandbox jailing. */

#ifdef __APPLE__
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL)) {
		dowarn("sandbox_init");
		goto error;
	}
#endif

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

	/*
	 * Wait until we receive the DER encoded (signed) certificate
	 * from the network process.
	 */

	if (NULL == (csr = readstream(certsock, COMM_CSR)))
		goto error;

	/*
	 * Create the PEM-encoded file in a backup location, overwriting
	 * anything that previously was there.
	 */

	if (NULL == (f = fopen(CERT_PEM_BAK, "w"))) {
		dowarn(CERT_PEM_BAK);
		goto error;
	} else if (-1 == fprintf(f, "%s", csr)) {
		dowarnx(CERT_PEM_BAK);
		goto error;
	} else if (-1 == fclose(f)) {
		dowarn(CERT_PEM_BAK);
		goto error;
	}
	f = NULL;

	/*
	 * Atomically (?) rename the backup file, wiping out anything in
	 * the real file, and set its permissions appropriately.
	 */

	if (-1 == rename(CERT_PEM_BAK, CERT_PEM)) {
		dowarn(CERT_PEM);
		goto error;
	} else if (-1 == chmod(CERT_PEM, 0444)) {
		dowarn(CERT_PEM);
		goto error;
	}

	dodbg("%s: created", CERT_PEM);

	rc = 1;
error:
	if (NULL != f)
		fclose(f);
	free(csr);
	close(certsock);
	return(rc);
}

