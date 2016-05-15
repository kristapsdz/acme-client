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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

#include "extern.h"

#define MARKER "-----BEGIN CERTIFICATE-----"

int
certproc(int netsock, int filesock, uid_t uid, gid_t gid)
{
	char		*csr, *chain, *url;
	unsigned char	*csrcp, *chaincp;
	size_t		 csrsz, chainsz;
	int		 i, rc, idx;
	FILE		*f;
	X509		*x, *chainx;
	X509_EXTENSION	*ext;
	const X509V3_EXT_METHOD* method;
	void		*entries;
	STACK_OF(CONF_VALUE) *val;
	BIO		*bio;

	ext = NULL;
	idx = -1;
	method = NULL;
	chain = csr = url = NULL;
	rc = 0;
	f = NULL;
	x = chainx = NULL;
	bio = NULL;

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

	/*
	 * Extract the CA Issuers from its NID.
	 * I have no idea what I'm doing.
	 */

	idx = X509_get_ext_by_NID(x, NID_info_access, idx);
	if (idx >= 0 && NULL != (ext = X509_get_ext(x, idx)))
		method = X509V3_EXT_get(ext);

	entries = X509_get_ext_d2i(x, NID_info_access, 0, 0);
	if (NULL != method && NULL != entries) {
		val = method->i2v(method, entries, 0);
		for (i = 0; i < sk_CONF_VALUE_num(val); i++) {
			CONF_VALUE* nval = sk_CONF_VALUE_value(val, i);
			if (strcmp(nval->name, "CA Issuers - URI"))
				continue;
			url = strdup(nval->value);
			if (NULL == url) {
				dowarn("strdup");
				goto error;
			}
			break;
		}
	}

	if (NULL == url) {
		dowarnx("no CA issuer registered with certificate");
		goto error;
	}

	/* Write the CA issuer to the netsock. */

	if ( ! writestr(netsock, COMM_ISSUER, url))
		goto error;

	/* Read the full-chain back from the netsock. */

	if (NULL == (chain = readbuf(netsock, COMM_CHAIN, &chainsz)))
		goto error;

	/*
	 * Then check if the chain is PEM-encoded by looking to see if
	 * it begins with the PEM marker.
	 * If so, ship it as-is; otherwise, convert to a PEM encoded
	 * buffer and ship that.
	 */
	if (chainsz <= strlen(MARKER) ||
	    strncmp(chain, MARKER, strlen(MARKER))) {
		chaincp = (u_char *)chain;
		chainx = d2i_X509(NULL, 
			(const u_char **)&chaincp, chainsz);
		if (NULL == chainx) {
			dowarnx("d2i_X509");
			goto error;
		}
		free(chain);
		chain = NULL;

		/* Write into a BIO buffer. */

		if (NULL == (bio = BIO_new(BIO_s_mem()))) {
			dowarn("BIO_new");
			goto error;
		} else if ( ! PEM_write_bio_X509(bio, chainx)) {
			dowarn("PEM_write_bio_X509");
			BIO_free(bio);
			goto error;
		}

		/* Convert BIO buffer back into string. */

		chain = calloc(1, bio->num_write + 1);
		if (NULL == chain) {
			dowarn("calloc");
			goto error;
		} else if (BIO_read(bio, chain, bio->num_write) <= 0) {
			dowarnx("BIO_read");
			goto error;
		}

		chainsz = bio->num_write;
		BIO_free(bio);
		bio = NULL;
	} 
	
	if ( ! writebuf(filesock, COMM_CHAIN, chain, chainsz))
		goto error;

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
	if (NULL != chainx)
		X509_free(chainx);
	if (NULL != bio)
		BIO_free(bio);
	free(csr);
	free(url);
	free(chain);
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
	close(netsock);
	close(filesock);
	return(rc);
}

