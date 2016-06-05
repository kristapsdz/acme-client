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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

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
		warn("%s", tmp);
		return(0);
	} else if ((ssize_t)vsz != write(fd, v, vsz)) {
		warnx("%s", tmp);
		close(fd);
		return(0);
	} else if (NULL != v2 && (ssize_t)v2sz != write(fd, v2, v2sz)) {
		warnx("%s", tmp);
		close(fd);
		return(0);
	} else if (-1 == close(fd)) {
		warn("%s", tmp);
		return(0);
	} else if (-1 == rename(tmp, real)) {
		warn("%s", real);
		return(0);
	}

	return(1);
}

int
fileproc(int certsock, const char *certdir, const char *domain)
{
	char		*csr, *ch;
	char		*CERT_PEM, *CERT_BAK, *CHAIN_PEM, *CHAIN_BAK, *FCHAIN_PEM, *FCHAIN_BAK;
	size_t		 chsz, csz;
	int		 rc;
	long		 lval;
	enum fileop	 op;

	csr = ch = NULL;
	rc = 0;

	/* File-system and sandbox jailing. */

	if ( ! sandbox_before())
		goto out;
	else if ( ! dropfs(certdir))
		goto out;
	else if ( ! sandbox_after())
		goto out;

	/* asprintf */
	if (-1 == asprintf(&CERT_PEM, CERT_PEM_TEMPLATE, domain)) {
		warn("asprintf");
		goto out;
	}
	if (-1 == asprintf(&CERT_BAK, CERT_BAK_TEMPLATE, domain)) {
		warn("asprintf");
		goto out;
	}
	if (-1 == asprintf(&CHAIN_PEM, CHAIN_PEM_TEMPLATE, domain)) {
		warn("asprintf");
		goto out;
	}
	if (-1 == asprintf(&CHAIN_BAK, CHAIN_BAK_TEMPLATE, domain)) {
		warn("asprintf");
		goto out;
	}
	if (-1 == asprintf(&FCHAIN_PEM, FCHAIN_PEM_TEMPLATE, domain)) {
		warn("asprintf");
		goto out;
	}
	if (-1 == asprintf(&FCHAIN_BAK, FCHAIN_BAK_TEMPLATE, domain)) {
		warn("asprintf");
		goto out;
	}

	/* Read our operation. */

	op = FILE__MAX;
	if (0 == (lval = readop(certsock, COMM_CHAIN_OP))) 
		op = FILE_STOP;
	else if (FILE_CREATE == lval || FILE_REMOVE == lval)
		op = lval;

	if (FILE_STOP == op) {
		rc = 1;
		goto out;
	} else if (FILE__MAX == op) {
		warnx("unknown operation from certproc");
		goto out;
	} 

	/* If revoking certificates, just unlink the files. */

	if (FILE_REMOVE == op) {
		if (-1 == unlink(CERT_PEM) && ENOENT != errno) {
			warn("%s/%s", certdir, CERT_PEM);
			goto out;
		} else
			dodbg("%s/%s: unlinked", certdir, CERT_PEM);

		if (-1 == unlink(CHAIN_PEM) && ENOENT != errno) {
			warn("%s/%s", certdir, CHAIN_PEM);
			goto out;
		} else
			dodbg("%s/%s: unlinked", certdir, CHAIN_PEM);

		if (-1 == unlink(FCHAIN_PEM) && ENOENT != errno) {
			warn("%s/%s", certdir, FCHAIN_PEM);
			goto out;
		} else
			dodbg("%s/%s: unlinked", certdir, FCHAIN_PEM);

		rc = 1;
		goto out;
	}

	/*
	 * Start by downloading the chain PEM as a buffer.
	 * This is not nil-terminated, but we're just going to guess
	 * that it's well-formed and not actually touch the data.
	 * Once downloaded, dump it into CHAIN_BAK.
	 */

	if (NULL == (ch = readbuf(certsock, COMM_CHAIN, &chsz)))
		goto out;
	if ( ! serialise(CHAIN_BAK, CHAIN_PEM, ch, chsz, NULL, 0))
		goto out;

	dodbg("%s/%s: created", certdir, CHAIN_PEM);

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

	dodbg("%s/%s: created", certdir, CERT_PEM);

	/*
	 * Finally, create the full-chain file.
	 * This is just the concatenation of the certificate and chain.
	 */

	if ( ! serialise(FCHAIN_BAK, FCHAIN_PEM, csr, csz, ch, chsz))
		goto out;

	dodbg("%s/%s: created", certdir, FCHAIN_PEM);

	rc = 1;
out:
	close(certsock);
	free(csr);
	free(ch);
	free(CERT_PEM);
	free(CERT_BAK);
	free(CHAIN_PEM);
	free(CHAIN_BAK);
	free(FCHAIN_PEM);
	free(FCHAIN_BAK);
	return(rc);
}
