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

#include <openssl/pem.h>
#include <openssl/engine.h>

#include "extern.h"

int
certproc(int netsock, int filesock, uid_t uid, gid_t gid)
{
	char		*csr;
	unsigned char	*csrcp;
	size_t		 csrsz;
	int		 rc;
	FILE		*f;
	X509_NAME	*issuer;
	X509		*x;

	csr = NULL;
	rc = 0;
	f = NULL;
	x = NULL;

	/* File-system and sandbox jailing. */

#ifdef __APPLE__
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL)) {
		dowarn("sandbox_init");
		goto error;
	}
#endif
	if (-1 == chroot(PATH_VAR_EMPTY)) {
		dowarn("%s: chroot", PATH_VAR_EMPTY);
		goto error;
	} else if (-1 == chdir("/")) {
		dowarn("/: chdir");
		goto error;
	}

	/* Pre-pledge due to file access attempts. */

	ERR_load_crypto_strings();

#if defined(__OpenBSD__) && OpenBSD >= 201605
	if (-1 == pledge("stdio", NULL)) {
		dowarn("pledge");
		goto error;
	}
#endif
	if ( ! dropprivs(uid, gid))
		doerrx("dropprivs");

	/*
	 * Wait until we receive the DER encoded (signed) certificate
	 * from the network process.
	 */

	if (NULL == (csr = readbuf(netsock, COMM_CSR, &csrsz)))
		goto error;

	csrcp = (unsigned char *)csr;
	x = d2i_X509(NULL, (const unsigned char **)&csrcp, csrsz);
	if (NULL == x) {
		dowarn("d2i_X509");
		goto error;
	}

	/* TODO: write the issuer back to the netproc. */

	/* Write the certificate to the file socket. */

	if (NULL == (f = fdopen(filesock, "a"))) {
		dowarn("fdopen");
		goto error;
	} else if ( ! PEM_write_X509(f, x)) {
		dowarnx("PEM_write_X509");
		goto error;
	} else if (-1 == fclose(f)) {
		dowarn("fclose");
		goto error;
	}
	f = NULL;

	rc = 1;
error:
	if (NULL != f)
		fclose(f);
	if (NULL != x)
		X509_free(x);
	free(csr);
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
	close(netsock);
	close(filesock);
	return(rc);
}

