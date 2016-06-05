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

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "extern.h"

#define	RENEW_ALLOW (30 * 24 * 60 * 60)

/*
 * Convert the X509's expiration time (which is in ASN1_TIME format)
 * into a time_t value.
 * There are lots of suggestions on the Internet on how to do this and
 * they're really, really unsafe.
 * Adapt those poor solutions to a safe one.
 */
static time_t
X509expires(X509 *x)
{
	ASN1_TIME	*time;
	struct tm	 t;
	unsigned char	*str;
	size_t 	 	 i = 0;

	time = X509_get_notAfter(x);
	str = time->data;
	memset(&t, 0, sizeof(t));

	/* Account for 2 and 4-digit time. */

	if (time->type == V_ASN1_UTCTIME) {
		if (time->length <= 2) {
			warnx("invalid ASN1_TIME");
			return((time_t)-1);
		}
		t.tm_year = 
			(str[0] - '0') * 10 + 
			(str[1] - '0');
		if (t.tm_year < 70)
			t.tm_year += 100;
		i = 2;
	} else if (time->type == V_ASN1_GENERALIZEDTIME) {
		if (time->length <= 4) {
			warnx("invalid ASN1_TIME");
			return((time_t)-1);
		}
		t.tm_year = 
			(str[0] - '0') * 1000 + 
			(str[1] - '0') * 100 + 
			(str[2] - '0') * 10 + 
			(str[3] - '0');
		t.tm_year -= 1900;
		i = 4;
	}

	/* Now the post-year parts. */

	if (time->length <= (int)i + 10) {
		warnx("invalid ASN1_TIME");
		return((time_t)-1);
	}

	t.tm_mon = ((str[i + 0] - '0') * 10 + (str[i + 1] - '0')) - 1;
	t.tm_mday = (str[i + 2] - '0') * 10 + (str[i + 3] - '0');
	t.tm_hour = (str[i + 4] - '0') * 10 + (str[i + 5] - '0');
	t.tm_min  = (str[i + 6] - '0') * 10 + (str[i + 7] - '0');
	t.tm_sec  = (str[i + 8] - '0') * 10 + (str[i + 9] - '0');
	
	return(mktime(&t));
}

int
revokeproc(int fd, const char *certdir, int force, int revoke,
	const char *const *alts, size_t altsz)
{
	int		 rc, cc, i, extsz, ssz;
	long		 lval;
	FILE		*f;
	size_t		*found;
	char		*path, *der, *dercp, *der64, *san, *str, *tok, *CERT_PEM;
	X509		*x;
	enum revokeop	 op, rop;
	time_t		 t;
	int		 len;
	X509_EXTENSION	*ex;
	ASN1_OBJECT	*obj;
	BIO		*bio;
	size_t		 j;

	found = NULL;
	bio = NULL;
	der = der64 = NULL;
	rc = 0;
	f = NULL;
	path = NULL;
	san = NULL;
	x = NULL;

	/* asprintf */
	if (-1 == asprintf(&CERT_PEM, CERT_PEM_TEMPLATE, alts[0])) {
		warn("asprintf");
		goto out;
	}

	/*
	 * First try to open the certificate before we drop privileges
	 * and jail ourselves.
	 * We allow "f" to be NULL IFF the cert doesn't exist yet.
	 */

	if (-1 == asprintf(&path, "%s/%s", certdir, CERT_PEM)) {
		warn("asprintf");
		goto out;
	} else if (NULL == (f = fopen(path, "r")) && ENOENT != errno) {
		warn("%s", path);
		goto out;
	}

	/* File-system and sandbox jailing. */

	if ( ! sandbox_before())
		goto out;

	ERR_load_crypto_strings();

	if ( ! dropfs(PATH_VAR_EMPTY))
		goto out;
	else if ( ! dropprivs())
		goto out;
	else if ( ! sandbox_after())
		goto out;

	/*
	 * If we couldn't open the certificate, it doesn't exist so we
	 * haven't submitted it yet, so obviously we can mark that it
	 * has expired and we should renew it.
	 * If we're revoking, however, then that's an error!
	 * Ignore if the reader isn't reading in either case.
	 */
	
	if (NULL == f && revoke) {
		warnx("%s/%s: no certificate found",
			certdir, CERT_PEM);
		(void)writeop(fd, COMM_REVOKE_RESP, REVOKE_OK);
		goto out;
	} else if (NULL == f && ! revoke) {
		if (writeop(fd, COMM_REVOKE_RESP, REVOKE_EXP) >= 0)
			rc = 1;
		goto out;
	} 

	if (NULL == (x = PEM_read_X509(f, NULL, NULL, NULL))) {
		warnx("PEM_read_X509");
		goto out;
	} 

	/* Read out the expiration date. */
	
	if ((time_t)-1 == (t = X509expires(x))) {
		warnx("X509expires");
		goto out;
	}

	/*
	 * Next, the long process to make sure that the SAN entries
	 * listed with the certificate fully cover those passed on the
	 * comamnd line.
	 */

	extsz = NULL != x->cert_info->extensions ? 
		sk_X509_EXTENSION_num(x->cert_info->extensions) : 0;

	/* Scan til we find the SAN NID. */

	for (i = 0; i < extsz; i++) {
		ex = sk_X509_EXTENSION_value
			(x->cert_info->extensions, i);
		assert(NULL != ex);
		obj = X509_EXTENSION_get_object(ex);
		assert(NULL != obj);
		if (NID_subject_alt_name != OBJ_obj2nid(obj))
			continue;

		if (NULL != san) {
			warnx("%s/%s: two SAN entries", 
				certdir, CERT_PEM);
			goto out;
		}

		bio = BIO_new(BIO_s_mem());
		if (NULL == bio) {
			warnx("BIO_new");
			goto out;
		} else if ( ! X509V3_EXT_print(bio, ex, 0, 0)) {
			warnx("X509V3_EXT_print");
			goto out;
		} else if (NULL == (san = calloc(1, bio->num_write + 1))) {
			warn("calloc");
			goto out;
		} 
		ssz = BIO_read(bio, san, bio->num_write);
		if (ssz < 0 || (unsigned)ssz != bio->num_write) {
			warnx("BIO_read");
			goto out;
		}
	}

	if (NULL == san) {
		warnx("%s/%s: does not have a SAN entry", certdir, CERT_PEM);
		goto out;
	} 
	
	/* An array of buckets: the number of entries found. */

	if (NULL == (found = calloc(altsz, sizeof(size_t)))) {
		warn("calloc");
		goto out;
	}

	/* 
	 * Parse the SAN line.
	 * Make sure that all of the domains are represented only once.
	 */

	str = san;
	while (NULL != (tok = strsep(&str, ","))) {
		if ('\0' == *tok)
			continue;
		while (isspace((int)*tok))
			tok++;
		if (strncmp(tok, "DNS:", 4))
			continue;
		tok += 4;
		for (j = 0; j < altsz; j++)
			if (0 == strcmp(tok, alts[j]))
				break;
		if (j == altsz) {
			warnx("%s/%s: unknown SAN entry: %s",
				certdir, CERT_PEM, tok);
			goto out;
		}
		if (found[j]++) {
			warnx("%s/%s: duplicate SAN entry: %s",
				certdir, CERT_PEM, tok);
			goto out;
		}
	}

	for (j = 0; j < altsz; j++) {
		if (found[j])
			continue;
		warnx("%s/%s: domain not listed: %s",
			certdir, CERT_PEM, alts[j]);
		goto out;
	}

	/*
	 * If we're going to revoke, write the certificate to the
	 * netproc in DER and base64-encoded format.
	 * Then exit: we have nothing left to do.
	 */
	
	if (revoke) {
		dodbg("%s/%s: revocation", certdir, CERT_PEM);

		/* 
		 * First, tell netproc we're online. 
		 * If they're down, then just exit without warning.
		 */

		cc = writeop(fd, COMM_REVOKE_RESP, REVOKE_EXP);
		if (0 == cc)
			rc = 1;
		if (cc <= 0)
			goto out;

		if ((len = i2d_X509(x, NULL)) < 0) {
			warnx("i2d_X509");
			goto out;
		} else if (NULL == (der = dercp = malloc(len))) {
			warn("malloc");
			goto out;
		} else if (len != i2d_X509(x, (u_char **)&dercp)) {
			warnx("i2d_X509");
			goto out;
		} else if (NULL == (der64 = base64buf_url(der, len))) {
			warnx("base64buf_url");
			goto out;
		} else if (writestr(fd, COMM_CSR, der64) >= 0) 
			rc = 1;

		goto out;
	}

	rop = time(NULL) >= (t - RENEW_ALLOW) ? REVOKE_EXP : REVOKE_OK;

	if (REVOKE_EXP == rop)
		dodbg("%s/%s: certificate renewable: %lld days left",
			certdir, CERT_PEM, 
			(long long)(t - time(NULL)) / 24 / 60 / 60);
	else
		dodbg("%s/%s: certificate valid: %lld days left",
			certdir, CERT_PEM, 
			(long long)(t - time(NULL)) / 24 / 60 / 60);

	if (REVOKE_OK == rop && force) {
		warnx("%s/%s: forcing renewal", certdir, CERT_PEM);
		rop = REVOKE_EXP;
	}

	/* 
	 * We can re-submit it given RENEW_ALLOW time before.
	 * If netproc is down, just exit.
	 */

	if (0 == (cc = writeop(fd, COMM_REVOKE_RESP, rop))) 
		rc = 1;
	if (cc <= 0)
		goto out;

	op = REVOKE__MAX;
	if (0 == (lval = readop(fd, COMM_REVOKE_OP)))
		op = REVOKE_STOP;
	else if (REVOKE_CHECK == lval)
		op = lval;

	if (REVOKE__MAX == op) {
		warnx("unknown operation from netproc");
		goto out;
	} else if (REVOKE_STOP == op) {
		rc = 1;
		goto out;
	}

	rc = 1;
out:
	close(fd);
	if (NULL != f)
		fclose(f);
	if (NULL != x)
		X509_free(x);
	if (NULL != bio)
		BIO_free(bio);
	free(CERT_PEM);
	free(san);
	free(path);
	free(der);
	free(found);
	free(der64);
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
	return(rc);
}
