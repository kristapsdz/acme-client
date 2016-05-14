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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "extern.h"

static int 
add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, const char *value)
{
	X509_EXTENSION 	*ex;
	char		*cp;

	if (-1 == asprintf(&cp, "DNS:%s", value)) {
		dowarn("asprintf");
		return(0);
	}
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, cp);
	if (NULL == ex) {
		dowarnx("X509V3_EXT_conf_nid");
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
keyproc(int netsock, const char *keyfile, const char *domain, 
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
	int		 len, rc;
	extern enum comp proccomp;
	STACK_OF(X509_EXTENSION) *exts;

	proccomp = COMP_KEY;

	/* Do this before we chroot()? */
	ERR_load_crypto_strings();

	/* 
	 * Next, open our private key file.
	 * After this, we're going to go dark.
	 */
	if (NULL == (f = fopen(keyfile, "r")))
		doerr("%s", keyfile);

	/*
	 * File-system, user, and sandbox jail.
	 */

#ifdef __APPLE__
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL))
		doerr("sandbox_init");
#endif
	if (-1 == chroot(PATH_VAR_EMPTY))
		doerr("%s: chroot", PATH_VAR_EMPTY);
	if (-1 == chdir("/"))
		doerr("/: chdir");

#if defined(__OpenBSD__) && OpenBSD >= 201605
	if (-1 == pledge("stdio", NULL))
		doerr("pledge");
#endif
	if ( ! dropprivs(uid, gid))
		doerrx("dropprivs");

	x = NULL;
	evp = NULL;
	r = NULL;
	name = NULL;
	der = der64 = NULL;
	rc = 0;
	exts = NULL;

	/* 
	 * Ok, now we're dark.
	 * Seed our PRNG with data from arc4random().
	 * Do this until we're told it's ok and use increments of 64
	 * bytes (arbitrarily).
	 */
	while (0 == RAND_status()) {
		arc4random_buf(rbuf, sizeof(rbuf));
		RAND_seed(rbuf, sizeof(rbuf));
	}

	/* 
	 * Parse our private key from an already-open steam.
	 * From now on, use the "error" label for errors.
	 */
	r = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	if (NULL == r) {
		dowarnx("%s", keyfile);
		goto error;
	}
	fclose(f);
	f = NULL;

	/*
	 * We're going to merge this into an EVP.
	 * Once these succeed, the RSA key will be free'd with the EVP.
	 */
	if (NULL == (evp = EVP_PKEY_new())) {
		dowarnx("EVP_PKEY_new");
		goto error;
	} else if ( ! EVP_PKEY_assign_RSA(evp, r)) {
		dowarnx("EVP_PKEY_assign_RSA");
		goto error;
	} 
	r = NULL;
	
	/* 
	 * Generate our certificate from the EVP public key.
	 * Then set it as the X509 requester's key.
	 */
	if (NULL == (x = X509_REQ_new())) {
		dowarnx("X509_new");
		goto error;
	} else if ( ! X509_REQ_set_pubkey(x, evp)) {
		dowarnx("X509_set_pubkey");
		goto error;
	}

	/* 
	 * Now specify the common name that we'll request.
	 */
	if (NULL == (name = X509_NAME_new())) {
		dowarnx("X509_NAME_new");
		goto error;
	} else if ( ! X509_NAME_add_entry_by_txt(name, "CN", 
	           MBSTRING_ASC, (unsigned char *)domain, -1, -1, 0)) {
		dowarnx("X509_NAME_add_entry_by_txt: CN=%s", domain);
		goto error;
	} else if ( ! X509_REQ_set_subject_name(x, name)) {
		dowarnx("X509_req_set_issuer_name");
		goto error;
	}

	/* 
	 * Now add the SAN extensions. 
	 * Don't do this if we don't need to.
	 * This was lifted more or less directly from demos/x509/mkreq.c
	 * of the OpenSSL source code.
	 * (The zeroth altname is the domain name.)
	 */
	if (altsz > 1) {
		if (NULL == (exts = sk_X509_EXTENSION_new_null())) {
			dowarnx("sk_X509_EXTENSION_new_null");
			goto error;
		}
		for (i = 1; i < altsz; i++)
			add_ext(exts, NID_subject_alt_name, alts[i]);
		if ( ! X509_REQ_add_extensions(x, exts)) {
			dowarnx("X509_REQ_add_extensions");
			goto error;
		}
		sk_X509_EXTENSION_pop_free
			(exts, X509_EXTENSION_free);
	}

	/* Sign the X509 request using SHA256. */

	if ( ! X509_REQ_sign(x, evp, EVP_sha256())) {
		dowarnx("X509_sign");
		goto error;
	} 

	/* Now, serialise to DER, then base64, then write. */

	if ((len = i2d_X509_REQ(x, NULL)) < 0) {
		dowarnx("i2d_X509");
		goto error;
	} else if (NULL == (der = dercp = malloc(len))) {
		dowarn("malloc");
		goto error;
	} else if (len != i2d_X509_REQ(x, (u_char **)&dercp)) {
		dowarnx("i2d_X509");
		goto error;
	} else if (NULL == (der64 = base64buf_url(der, len))) {
		dowarnx("base64buf_url");
		goto error;
	} else if ( ! writestr(netsock, COMM_CERT, der64)) 
		goto error;

	rc = 1;
error:
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
	close(netsock);
	return(rc);
}

