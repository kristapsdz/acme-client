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

#include <sys/param.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "extern.h"

/*
 * This was lifted more or less directly from demos/x509/mkreq.c of the
 * OpenSSL source code.
 * TODO: is this the best way of doing this?
 */
static int 
add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, const char *value)
{
	X509_EXTENSION 	*ex;
	char		*cp;

	if (-1 == asprintf(&cp, "DNS:%s", value)) {
		warn("asprintf");
		return(0);
	}
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, cp);
	if (NULL == ex) {
		warnx("X509V3_EXT_conf_nid");
		return(0);
	}
	sk_X509_EXTENSION_push(sk, ex);
	return(1);
}

/*
 * Create an X509 certificate from the private RSA key we have on file.
 * To do this, we first open the RSA key file, then jail ourselves.
 * We then use the crypto library to create the certificate within the
 * jail and, on success, ship it to "netsock" as an X509 request.
 */
int
keyproc(int netsock, const char *keyfile, 
	uid_t uid, gid_t gid, const char **alts, size_t altsz)
{
	char		*der64, *der, *dercp;
	FILE		*f;
	size_t		 i;
	RSA		*r;
	EVP_PKEY	*evp;
	X509_REQ	*x;
	X509_NAME 	*name;
	unsigned char	 rbuf[64];
	int		 len, rc, nid;
	STACK_OF(X509_EXTENSION) *exts;

	x = NULL;
	evp = NULL;
	r = NULL;
	name = NULL;
	der = der64 = NULL;
	rc = 0;
	exts = NULL;

	/* Begin by opening our key file. */

	if (NULL == (f = fopen(keyfile, "r"))) {
		warn("%s", keyfile);
		goto error;
	}

	/* File-system, user, and sandbox jail. */
	
	if ( ! sandbox_before()) {
		warnx("sandbox_before");
		goto error;
	}

	ERR_load_crypto_strings();

	if ( ! dropfs(PATH_VAR_EMPTY)) {
		warnx("dropfs");
		goto error;
	} else if ( ! dropprivs(uid, gid)) {
		warnx("dropprivs");
		goto error;
	} else if ( ! sandbox_after()) {
		warnx("sandbox_after");
		goto error;
	}

	/* 
	 * Seed our PRNG with data from arc4random().
	 * Do this until we're told it's ok and use increments of 64
	 * bytes (arbitrarily).
	 * TODO: is this sufficient as a RAND source?
	 */

	while (0 == RAND_status()) {
		arc4random_buf(rbuf, sizeof(rbuf));
		RAND_seed(rbuf, sizeof(rbuf));
	}

	/* 
	 * Parse our private key from an already-open steam. 
	 * Then merge the key into a abstract EVP, at which point the
	 * memory is managed by the EVP.
	 */

	r = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	if (NULL == r) {
		warnx("%s", keyfile);
		goto error;
	}

	fclose(f);
	f = NULL;

	if (NULL == (evp = EVP_PKEY_new())) {
		warnx("EVP_PKEY_new");
		goto error;
	} else if ( ! EVP_PKEY_assign_RSA(evp, r)) {
		warnx("EVP_PKEY_assign_RSA");
		goto error;
	} 

	r = NULL;
	
	/* 
	 * Generate our certificate from the EVP public key.
	 * Then set it as the X509 requester's key.
	 */

	if (NULL == (x = X509_REQ_new())) {
		warnx("X509_new");
		goto error;
	} else if ( ! X509_REQ_set_pubkey(x, evp)) {
		warnx("X509_set_pubkey");
		goto error;
	}

	/* Now specify the common name that we'll request. */

	if (NULL == (name = X509_NAME_new())) {
		warnx("X509_NAME_new");
		goto error;
	} else if ( ! X509_NAME_add_entry_by_txt(name, "CN", 
	           MBSTRING_ASC, (u_char *)alts[0], -1, -1, 0)) {
		warnx("X509_NAME_add_entry_by_txt: CN=%s", alts[0]);
		goto error;
	} else if ( ! X509_REQ_set_subject_name(x, name)) {
		warnx("X509_req_set_issuer_name");
		goto error;
	}

	/* 
	 * Now add the SAN extensions. 
	 * This was lifted more or less directly from demos/x509/mkreq.c
	 * of the OpenSSL source code.
	 * (The zeroth altname is the domain name.)
 	 * TODO: is this the best way of doing this?
	 */

	if (altsz > 1) {
		nid = NID_subject_alt_name;
		if (NULL == (exts = sk_X509_EXTENSION_new_null())) {
			warnx("sk_X509_EXTENSION_new_null");
			goto error;
		}
		for (i = 1; i < altsz; i++)
			if ( ! add_ext(exts, nid, alts[i])) {
				warnx("add_ext");
				goto error;
			}
		if ( ! X509_REQ_add_extensions(x, exts)) {
			warnx("X509_REQ_add_extensions");
			goto error;
		}
		sk_X509_EXTENSION_pop_free
			(exts, X509_EXTENSION_free);
	}

	/* Sign the X509 request using SHA256. */

	if ( ! X509_REQ_sign(x, evp, EVP_sha256())) {
		warnx("X509_sign");
		goto error;
	} 

	/* Now, serialise to DER, then base64. */

	if ((len = i2d_X509_REQ(x, NULL)) < 0) {
		warnx("i2d_X509");
		goto error;
	} else if (NULL == (der = dercp = malloc(len))) {
		warn("malloc");
		goto error;
	} else if (len != i2d_X509_REQ(x, (u_char **)&dercp)) {
		warnx("i2d_X509");
		goto error;
	} else if (NULL == (der64 = base64buf_url(der, len))) {
		warnx("base64buf_url");
		goto error;
	}

	/* Write that we're ready, then write. */
       
	if ( ! writeop(netsock, COMM_KEY_STAT, KEY_READY)) 
		goto error;
	else if ( ! writestr(netsock, COMM_CERT, der64)) 
		goto error;

	rc = 1;
error:
	close(netsock);
	if (NULL != f)
		fclose(f);
	free(der);
	free(der64);
	if (NULL != x)
		X509_REQ_free(x);
	if (NULL != r)
		RSA_free(r);
	if (NULL != name)
		X509_NAME_free(name);
	if (NULL != evp)
		EVP_PKEY_free(evp);
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
	return(rc);
}

