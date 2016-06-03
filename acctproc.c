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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "extern.h"

/*
 * Default number of bits when creating a new key.
 */
#define	KEY_BITS 4096

/*
 * Converts a BIGNUM to the form used in JWK.
 * This is essentially a base64-encoded big-endian binary string
 * representation of the number.
 */
static char *
bn2string(const BIGNUM *bn)
{
	int	 len;
	char	*buf, *bbuf;

	/* Extract big-endian representation of BIGNUM. */

	len = BN_num_bytes(bn);
	if (NULL == (buf = malloc(len))) {
		warn("malloc");
		return(NULL);
	} else if (len != BN_bn2bin(bn, (unsigned char *)buf)) {
		warnx("BN_bn2bin");
		free(buf);
		return(NULL);
	}

	/* Convert to base64url. */

	if (NULL == (bbuf = base64buf_url(buf, len))) {
		warnx("base64buf_url");
		free(buf);
		return(NULL);
	}

	free(buf);
	return(bbuf);
}

/*
 * The thumbprint operation is used for the challenge sequence.
 */
static int
op_thumbprint(int fd, EVP_PKEY *pkey)
{
	char		*exp, *mod, *thumb, *dig64;
	int		 rc;
	unsigned int	 digsz;
	unsigned char	*dig;

	EVP_MD_CTX	*ctx;
	RSA		*r;

	rc = 0;
	mod = exp = thumb = dig64 = NULL;
	dig = NULL;
	ctx = NULL;

	if (NULL == (r = EVP_PKEY_get1_RSA(pkey))) {
		warnx("EVP_PKEY_get1_RSA");
		goto out;
	} else if (NULL == (mod = bn2string(r->n))) {
		warnx("bn2string");
		goto out;
	} else if (NULL == (exp = bn2string(r->e))) {
		warnx("bn2string");
		goto out;
	}

	/* Construct the thumbprint input itself. */

	if (NULL == (thumb = json_fmt_thumb(exp, mod))) {
		warnx("json_fmt_thumb");
		goto out;
	}

	/*
	 * Compute the SHA256 digest of the thumbprint then
	 * base64-encode the digest itself.
	 * If the reader is closed when we write, ignore it (we'll pick
	 * it up in the read loop).
	 */

	if (NULL == (dig = malloc(EVP_MAX_MD_SIZE))) {
		warn("malloc");
		goto out;
	} else if (NULL == (ctx = EVP_MD_CTX_create())) {
		warnx("EVP_MD_CTX_create");
		goto out;
	} else if ( ! EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
		warnx("EVP_SignInit_ex");
		goto out;
	} else if ( ! EVP_DigestUpdate(ctx, thumb, strlen(thumb))) {
		warnx("EVP_SignUpdate");
		goto out;
	} else if ( ! EVP_DigestFinal_ex(ctx, dig, &digsz)) {
		warnx("EVP_SignFinal");
		goto out;
	} else if (NULL == (dig64 = base64buf_url((char *)dig, digsz))) {
		warnx("base64buf_url");
		goto out;
	} else if (writestr(fd, COMM_THUMB, dig64) < 0)
		goto out;

	rc = 1;
out:
	if (NULL != ctx)
		EVP_MD_CTX_destroy(ctx);

	free(exp);
	free(mod);
	free(thumb);
	free(dig);
	free(dig64);
	return(rc);
}

/*
 * Operation to sign a message with the account key.
 * This requires the sender ("fd") to provide the payload and a nonce.
 */
static int
op_sign(int fd, EVP_PKEY *pkey)
{
	char		*exp, *mod, *nonce, *pay,
			*pay64, *prot, *prot64, *head, 
			*sign, *dig64, *fin;
	int		 cc, rc;
	unsigned int	 digsz;
	unsigned char	*dig;
	EVP_MD_CTX	*ctx;
	RSA		*r;

	rc = 0;
	pay = nonce = mod = exp = head = fin =
		sign = prot = prot64 = pay64 = dig64 = NULL;
	dig = NULL;
	ctx = NULL;

	/* Read our payload and nonce from the requestor. */

	if (NULL == (pay = readstr(fd, COMM_PAY)))
		goto out;
	else if (NULL == (nonce = readstr(fd, COMM_NONCE))) 
		goto out;

	/* Extract relevant portions of our private key. */

	if (NULL == (r = EVP_PKEY_get1_RSA(pkey))) {
		warnx("EVP_PKEY_get1_RSA");
		goto out;
	} else if (NULL == (mod = bn2string(r->n))) {
		warnx("bn2string");
		goto out;
	} else if (NULL == (exp = bn2string(r->e))) {
		warnx("bn2string");
		goto out;
	} 
	
	/* Base64-encode the payload. */

	if (NULL == (pay64 = base64buf_url(pay, strlen(pay)))) {
		warnx("base64buf_url");
		goto out;
	}

	/* Construct the public header. */

	if (NULL == (head = json_fmt_header(exp, mod))) {
		warnx("json_fmt_header");
		goto out;
	}

	/* Now the header combined with the nonce, then base64. */

	if (NULL == (prot = json_fmt_protected(exp, mod, nonce))) {
		warnx("json_fmt_protected");
		goto out;
	} else if (NULL == (prot64 = base64buf_url(prot, strlen(prot)))) {
		warnx("base64buf_url");
		goto out;
	}

	/* Now the signature material. */

	cc = asprintf(&sign, "%s.%s", prot64, pay64);
	if (-1 == cc) {
		warn("asprintf");
		sign = NULL;
		goto out;
	}

	if (NULL == (dig = malloc(EVP_PKEY_size(pkey)))) {
		warn("malloc");
		goto out;
	}

	/*
	 * Here we go: using our RSA key as merged into the envelope,
	 * sign a SHA256 digest of our message.
	 */

	if (NULL == (ctx = EVP_MD_CTX_create())) {
		warnx("EVP_MD_CTX_create");
		goto out;
	} else if ( ! EVP_SignInit_ex(ctx, EVP_sha256(), NULL)) {
		warnx("EVP_SignInit_ex");
		goto out;
	} else if ( ! EVP_SignUpdate(ctx, sign, strlen(sign))) {
		warnx("EVP_SignUpdate");
		goto out;
	} else if ( ! EVP_SignFinal(ctx, dig, &digsz, pkey)) {
		warnx("EVP_SignFinal");
		goto out;
	} else if (NULL == (dig64 = base64buf_url((char *)dig, digsz))) {
		warnx("base64buf_url");
		goto out;
	}

	/* 
	 * Write back in the correct JSON format. 
	 * If the reader is closed, just ignore it (we'll pick it up
	 * when we next enter the read loop).
	 */

	if (NULL == (fin = json_fmt_signed(head, prot64, pay64, dig64))) {
		warnx("json_fmt_signed");
		goto out;
	} else if (writestr(fd, COMM_REQ, fin) < 0)
		goto out;

	rc = 1;
out:
	if (NULL != ctx)
		EVP_MD_CTX_destroy(ctx);

	free(pay);
	free(sign);
	free(pay64);
	free(nonce);
	free(exp);
	free(mod);
	free(head);
	free(prot);
	free(prot64);
	free(dig);
	free(dig64);
	free(fin);
	return(rc);
}

int
acctproc(int netsock, const char *acctkey, int newacct)
{
	FILE		*f;
	EVP_PKEY_CTX	*ctx;
	EVP_PKEY	*pkey;
	long		 lval;
	enum acctop	 op;
	unsigned char	 rbuf[64];
	int		 rc, cc;

	f = NULL;
	ctx = NULL;
	pkey = NULL;
	rc = 0;

	/* 
	 * First, open our private key file read-only or write-only if
	 * we're creating from scratch.
	 */

	if (NULL == (f = fopen(acctkey, newacct ? "wx" : "r"))) {
		warn("%s", acctkey);
		goto out;
	}

	/* File-system, user, and sandbox jailing. */

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
	 * Seed our PRNG with data from arc4random().
	 * Do this until we're told it's ok and use increments of 64
	 * bytes (arbitrarily).
	 */

	while (0 == RAND_status()) {
		arc4random_buf(rbuf, sizeof(rbuf));
		RAND_seed(rbuf, sizeof(rbuf));
	}

	if (newacct) {
		if (NULL == (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) {
			warnx("EVP_PKEY_CTX_new_id");
			goto out;
		} else if (EVP_PKEY_keygen_init(ctx) <= 0) {
			warnx("EVP_PKEY_keygen_init");
			goto out;
		} else if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_BITS) <= 0) {
			warnx("EVP_PKEY_set_rsa_keygen_bits");
			goto out;
		}
		dodbg("%s: creating: %d bits", acctkey, KEY_BITS);
		if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
			warnx("EVP_PKEY_keygen");
			goto out;
		}
		if ( ! PEM_write_PrivateKey
		    (f, pkey, NULL, NULL, 0, NULL, NULL)) {
			warnx("PEM_write_PrivateKey");
			goto out;
		}
		EVP_PKEY_CTX_free(ctx);
		ctx = NULL;
	} else {
		pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
		if (NULL == pkey) {
			warnx("%s", acctkey);
			goto out;
		} else if (EVP_PKEY_RSA != EVP_PKEY_type(pkey->type)) {
			warnx("%s: unsupported key type", acctkey);
			goto out;
		}
	}

	fclose(f);
	f = NULL;

	/* Notify the netproc that we've started up. */

	if (0 == (cc = writeop(netsock, COMM_ACCT_STAT, ACCT_READY)))
		rc = 1;
	if (cc <= 0)
		goto out;

	/*
	 * Now we wait for requests from the network-facing process.
	 * It might ask us for our thumbprint, for example, or for us to
	 * sign a message.
	 */

	for (;;) {
		op = ACCT__MAX;
		if (0 == (lval = readop(netsock, COMM_ACCT)))
			op = ACCT_STOP;
		else if (ACCT_SIGN == lval || ACCT_THUMBPRINT == lval)
			op = lval;

		if (ACCT__MAX == op) {
			warnx("unknown operation from netproc");
			goto out;
		} else if (ACCT_STOP == op)
			break;

		switch (op) {
		case (ACCT_SIGN):
			if (op_sign(netsock, pkey))
				break;
			warnx("op_sign");
			goto out;
		case (ACCT_THUMBPRINT):
			if (op_thumbprint(netsock, pkey))
				break;
			warnx("op_thumbprint");
			goto out;
		default:
			abort();
		}
	}

	rc = 1;
out:
	close(netsock);
	if (NULL != f)
		fclose(f);
	if (NULL != pkey)
		EVP_PKEY_free(pkey);
	if (NULL != ctx)
		EVP_PKEY_CTX_free(ctx);
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
	return(rc);
}

