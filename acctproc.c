#include <sys/param.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

#include "extern.h"

#define SUB "acctproc"

static void
dowarn(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn(SUB, fmt, ap);
	va_end(ap);
}

static void
dowarnx(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarnx(SUB, fmt, ap);
	va_end(ap);
}

static void
dodbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg(SUB, fmt, ap);
	va_end(ap);
}

static void
doerr(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverr(SUB, fmt, ap);
	va_end(ap);
}

static char *
bn2string(const BIGNUM *bn)
{
	int	 len;
	char	*buf, *bbuf;

	/* Extract big-endian representation of BIGNUM. */
	len = BN_num_bytes(bn);
	if (NULL == (buf = malloc(len))) {
		dowarn("malloc");
		return(NULL);
	} else if (len != BN_bn2bin(bn, (unsigned char *)buf)) {
		dowarnx("BN_bn2bin");
		free(buf);
		return(NULL);
	}

	/* Convert to base64url. */
	if (NULL == (bbuf = base64buf_url(buf, len))) {
		dowarnx("base64buf_url");
		free(buf);
		return(NULL);
	}

	free(buf);
	return(bbuf);
}

static int
op_thumbprint(int fd, RSA *r)
{
	char		*exp, *mod, *thumb, *dig64;
	int		 cc, rc;
	unsigned int	 digsz;
	unsigned char	*dig;

	EVP_MD_CTX	*ctx;

	/* Nullify all the things. */
	rc = 0;
	mod = exp = thumb = dig64 = NULL;
	dig = NULL;
	ctx = NULL;

	if (NULL == (mod = bn2string(r->n))) {
		dowarnx("bn2string");
		goto out;
	} else if (NULL == (exp = bn2string(r->e))) {
		dowarnx("bn2string");
		goto out;
	}

	/*
	 * Construct the thumbprint.
	 * NOTE: WHITESPACE IS IMPORTANT.
	 */
	cc = asprintf(&thumb, 
		"{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}",
		exp, mod);
	if (-1 == cc) {
		dowarn("asprintf");
		thumb = NULL;
		goto out;
	}

	/*
	 * Create an envelope for the key an assign the RSA private key
	 * parts to it (we'll use it for signing).
	 * (The dup is because the EVP_PKEY_free will kill the RSA.)
	 */
	if (NULL == (dig = malloc(EVP_MAX_MD_SIZE))) {
		dowarn("malloc");
		goto out;
	}

	/*
	 * Here we go: using our RSA key as merged into the envelope,
	 * sign a SHA256 digest of our message.
	 */
	if (NULL == (ctx = EVP_MD_CTX_create())) {
		dowarnx("EVP_MD_CTX_create");
		goto out;
	} else if ( ! EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
		dowarnx("EVP_SignInit_ex");
		goto out;
	} else if ( ! EVP_DigestUpdate(ctx, thumb, strlen(thumb))) {
		dowarnx("EVP_SignUpdate");
		goto out;
	} else if ( ! EVP_DigestFinal_ex(ctx, dig, &digsz)) {
		dowarnx("EVP_SignFinal");
		goto out;
	} else if (NULL == (dig64 = base64buf_url((char *)dig, digsz))) {
		dowarnx("base64buf_url");
		goto out;
	} else if ( ! writestr(SUB, fd, COMM_THUMB, dig64))
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
op_sign(int fd, RSA *r)
{
	char		*exp, *mod, *nonce, *pay,
			*pay64, *prot, *prot64, *head, 
			*sign, *dig64, *final;
	int		 cc, rc;
	unsigned int	 digsz;
	unsigned char	*dig;

	EVP_MD_CTX	*ctx;
	EVP_PKEY	*pkey;

	/* Nullify all the things. */
	rc = 0;
	pay = nonce = mod = exp = head = final =
		sign = prot = prot64 = pay64 = dig64 = NULL;
	dig = NULL;
	pkey = NULL;
	ctx = NULL;

	/*
	 * Read our payload and nonce from the requestor.
	 * Then entangle these with our encoded modulus and exponent.
	 */
	if (NULL == (pay = readstr(SUB, fd, COMM_PAY)))
		goto out;
	else if (NULL == (nonce = readstr(SUB, fd, COMM_NONCE))) 
		goto out;

	if (NULL == (mod = bn2string(r->n))) {
		dowarnx("bn2string");
		goto out;
	} else if (NULL == (exp = bn2string(r->e))) {
		dowarnx("bn2string");
		goto out;
	} else if (NULL == (pay64 = base64buf_url(pay, strlen(pay)))) {
		dowarnx("base64buf_url");
		goto out;
	}

	/* Now we construct the public header. */
	cc = asprintf(&head, "{\"alg\": \"RS256\", "
		"\"jwk\": {\"e\": \"%s\", \"kty\": \"RSA\", \"n\": \"%s\"}}",
		exp, mod);
	if (-1 == cc) {
		dowarn("asprintf");
		head = NULL;
		goto out;
	}

	/* Now the header combined with the nonce, base64'd. */
	cc = asprintf(&prot, "{"
		"\"alg\": \"RS256\", "
		"\"jwk\": {\"e\": \"%s\", \"kty\": \"RSA\", \"n\": \"%s\"}, "
		"\"nonce\": \"%s\"}", exp, mod, nonce);
	if (-1 == cc) {
		dowarn("asprintf");
		prot = NULL;
		goto out;
	} else if (NULL == (prot64 = base64buf_url(prot, strlen(prot)))) {
		dowarnx("base64buf_url");
		goto out;
	}

	/* Now the signature material. */
	cc = asprintf(&sign, "%s.%s", prot64, pay64);
	if (-1 == cc) {
		dowarn("asprintf");
		sign = NULL;
		goto out;
	}

	/*
	 * Create an envelope for the key an assign the RSA private key
	 * parts to it (we'll use it for signing).
	 * (The dup is because the EVP_PKEY_free will kill the RSA.)
	 */
	if (NULL == (pkey = EVP_PKEY_new())) {
		dowarnx("EVP_PKEY_new");
		goto out;
	} else if ( ! EVP_PKEY_assign_RSA(pkey, RSAPrivateKey_dup(r))) {
		dowarnx("EVP_PKEY_assign_RSA");
		goto out;
	} else if (NULL == (dig = malloc(EVP_PKEY_size(pkey)))) {
		dowarn("malloc");
		goto out;
	}

	/*
	 * Here we go: using our RSA key as merged into the envelope,
	 * sign a SHA256 digest of our message.
	 */
	if (NULL == (ctx = EVP_MD_CTX_create())) {
		dowarnx("EVP_MD_CTX_create");
		goto out;
	} else if ( ! EVP_SignInit_ex(ctx, EVP_sha256(), NULL)) {
		dowarnx("EVP_SignInit_ex");
		goto out;
	} else if ( ! EVP_SignUpdate(ctx, sign, strlen(sign))) {
		dowarnx("EVP_SignUpdate");
		goto out;
	} else if ( ! EVP_SignFinal(ctx, dig, &digsz, pkey)) {
		dowarnx("EVP_SignFinal");
		goto out;
	} else if (NULL == (dig64 = base64buf_url((char *)dig, digsz))) {
		dowarnx("base64buf_url");
		goto out;
	}

	/*
	 * Finally, compose our message.
	 * This incorporates all of the above components.
	 * Write this back to the requester.
	 */
	cc = asprintf(&final, 
		"{\"header\": %s, \"protected\": \"%s\", "
		"\"payload\": \"%s\", \"signature\": \"%s\"}",
			head, prot64, pay64, dig64);

	if (-1 == cc) {
		dowarn("asprintf");
		goto out;
	} else if ( ! writestr(SUB, fd, COMM_REQ, final))
		goto out;

	rc = 1;
out:
	if (NULL != pkey)
		EVP_PKEY_free(pkey);
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
	free(final);
	return(rc);
}

int
acctproc(int netsock, const char *acctkey, int newacct)
{
	FILE		*f;
	RSA		*r;
	long		 lval;
	enum acctop	 op;
	unsigned char	 rbuf[64];
	BIGNUM		*bne;

	/* Do this before we chroot()? */
	ERR_load_crypto_strings();

	/* 
	 * Next, open our private key file read-only or write-only if
	 * we're creating from scratch.
	 * After this, we're going to go dark.
	 */
	if (NULL == (f = fopen(acctkey, newacct > 1 ? "wx" : "r")))
		doerr("%s", acctkey);

#ifdef __APPLE__
	/*
	 * We would use "pure computation", which is correct, but then
	 * we wouldn't be able to chroot().
	 * This call also can't happen after the chroot(), so we're
	 * stuck with a weaker sandbox.
	 */
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL))
		doerr("sandbox_init");
#endif
	/*
	 * Jails: start with file-system.
	 * Go into the usual place.
	 */
	if (-1 == chroot("/var/empty"))
		doerr("%s: chroot", "/var/empty");
	if (-1 == chdir("/"))
		doerr("/: chdir");

#if defined(__OpenBSD__) && OpenBSD >= 201605
	/* 
	 * On OpenBSD, we won't use anything more than what we've
	 * inherited from our open descriptors.
	 */
	if (-1 == pledge("stdio", NULL))
		doerr("pledge");
#endif

	r = NULL;
	bne = NULL;

	/* 
	 * Ok, now we're dark.
	 * Seed our PRNG with data from arc4random().
	 * Do this until we're told it's ok and use increments of 64
	 * bytes (arbitrarily).
	 */
	while (0 == RAND_status()) {
		dodbg("seeding");
		arc4random_buf(rbuf, sizeof(rbuf));
		RAND_seed(rbuf, sizeof(rbuf));
	}

	if (newacct > 1) {
		if (NULL == (bne = BN_new())) {
			dowarnx("BN_new");
			goto error;
		} else if ( ! BN_set_word(bne, RSA_F4)) {
			dowarnx("BN_set_word");
			goto error;
		} else if (NULL == (r = RSA_new())) {
			dowarnx("RSA_new");
			goto error;
		}
		dodbg("%s: creating private key", acctkey);
		if ( ! RSA_generate_key_ex(r, 4096, bne, NULL)) {
			dowarnx("RSA_generate_key_ex");
			goto error;
		}
		dodbg("%s: serialising private key", acctkey);
		if ( ! PEM_write_RSAPrivateKey
		    (f, r, NULL, 0, 0, NULL, NULL)) {
			dowarnx("PEM_write_RSAPrivateKey");
			goto error;
		}
		BN_free(bne);
	} else {
		dodbg("%s: parsing private key", acctkey);
		r = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
		if (NULL == r) {
			dowarnx("%s", acctkey);
			goto error;
		}
	}

	fclose(f);
	f = NULL;

	/*
	 * Now we wait for requests from the network-facing process.
	 * It might ask us for our thumbprint, for example, or for us to
	 * sign a message.
	 */
	for (;;) {
		if (0 == (lval = readop(SUB, netsock, COMM_ACCT)))
			op = ACCT_STOP;
		else if (LONG_MAX == lval)
			op = ACCT__MAX;
		else
			op = lval;

		if (ACCT_STOP == op)
			break;
		else if (ACCT__MAX == op)
			goto error;

		switch (op) {
		case (ACCT_SIGN):
			dodbg("signing payload");
			if (op_sign(netsock, r))
				break;
			dowarnx("op_sign");
			goto error;
		case (ACCT_THUMBPRINT):
			dodbg("creating thumbprint");
			if (op_thumbprint(netsock, r))
				break;
			dowarnx("op_thumbprint");
			goto error;
		default:
			abort();
		}
	}

	RSA_free(r);
	ERR_free_strings();
	close(netsock);
	dodbg("finished");
	return(1);
error:
	ERR_print_errors_fp(stderr);
	if (NULL != f)
		fclose(f);
	if (NULL != r)
		RSA_free(r);
	if (NULL != bne)
		BN_free(bne);
	ERR_free_strings();
	close(netsock);
	dodbg("finished (error)");
	return(0);
}

