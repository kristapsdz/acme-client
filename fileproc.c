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
#include <sys/param.h>

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
#define	CERT_BAK "cert.pem~"
#define	CHAIN_PEM "chain.pem"
#define	CHAIN_BAK "chain.pem~"
#define	FCHAIN_PEM "fullchain.pem"
#define	FCHAIN_BAK "fullchain.pem~"

static int
serialise(const char *tmp, const char *real, 
	const char *v, size_t vsz,
	const char *v2, size_t v2sz)
{
	int 	 fd;

	/* 
	 * Write into backup location, overwriting.
	 * Then atomically (?) do the rename.
	 */

	fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0444);
	if (-1 == fd) {
		dowarn("%s", tmp);
		return(0);
	} else if ((ssize_t)vsz != write(fd, v, vsz)) {
		dowarnx("%s", tmp);
		close(fd);
		return(0);
	} else if (NULL != v2 && (ssize_t)v2sz != write(fd, v2, v2sz)) {
		dowarnx("%s", tmp);
		close(fd);
		return(0);
	} else if (-1 == close(fd)) {
		dowarn("%s", tmp);
		return(0);
	} else if (-1 == rename(tmp, real)) {
		dowarn("%s", real);
		return(0);
	}

	return(1);
}

int
fileproc(int certsock, const char *certdir)
{
	char		*csr, *ch;
	size_t		 chsz, csz;
	int		 rc;
	long		 lval;

	csr = ch = NULL;
	rc = 0;

	/* File-system and sandbox jailing. */

#ifdef __APPLE__
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL)) {
		dowarn("sandbox_init");
		goto out;
	}
#endif

	if ( ! dropfs(certdir)) {
		dowarnx("dropfs");
		goto out;
	} 

#if defined(__OpenBSD__) && OpenBSD >= 201605
	/* 
	 * XXX: rpath shouldn't be here, but it's tripped by the
	 * rename(2) despite that pledge(2) specifically says rename(2)
	 * is cpath.
	 */
	if (-1 == pledge("stdio cpath wpath rpath", NULL)) {
		dowarn("pledge");
		goto out;
	}
#endif

	/*
	 * Start by downloading the chain PEM as a buffer.
	 * This is not nil-terminated, but we're just going to guess
	 * that it's well-formed and not actually touch the data.
	 * Once downloaded, dump it into CHAIN_BAK.
	 */

	if (0 == (lval = readop(certsock, COMM_CHAIN_OP))) {
		rc = 1;
		goto out;
	} else if (NULL == (ch = readbuf(certsock, COMM_CHAIN, &chsz)))
		goto out;

	if ( ! serialise(CHAIN_BAK, CHAIN_PEM, ch, chsz, NULL, 0))
		goto out;

	dodbg("%s: created", CHAIN_PEM);

	/*
	 * Next, wait until we receive the DER encoded (signed)
	 * certificate from the network process.
	 * This comes as a stream of bytes: we don't know how many, so
	 * just keep downloading.
	 */

	if (NULL == (csr = readbuf(certsock, COMM_CSR, &csz)))
		goto out;
	if ( ! serialise(CERT_BAK, CERT_PEM, csr, csz, NULL, 0))
		goto out;

	dodbg("%s: created", CERT_PEM);

	/*
	 * Finally, create the full-chain file.
	 * This is just the concatenation of the certificate and chain.
	 */

	if ( ! serialise(FCHAIN_BAK, FCHAIN_PEM, csr, csz, ch, chsz))
		goto out;

	dodbg("%s: created", FCHAIN_PEM);

	rc = 1;
out:
	close(certsock);
	free(csr);
	free(ch);
	return(rc);
}
