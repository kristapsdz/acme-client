#include <assert.h>
#include <err.h>
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
#include <openssl/engine.h>

#include "extern.h"

static const char b64[] = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static void
dowarn(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn("acctproc", fmt, ap);
	va_end(ap);
}

static void
dowarnx(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarnx("acctproc", fmt, ap);
	va_end(ap);
}

static void
dodbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg("acctproc", fmt, ap);
	va_end(ap);
}

static void
doerr(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverr("acctproc", fmt, ap);
	va_end(ap);
}

/*
 * Compute the maximum buffer required for a base64 encoded string of
 * length "len".
 */
static size_t 
base64len(size_t len)
{

	return(((len + 2) / 3 * 4) + 1);
}

/*
 * Base64 computation.
 * This is heavily "assert"-d because Coverity complains.
 */
static size_t 
base64buf(char *enc, const char *str, size_t len)
{
	size_t 	i, val;
	char 	*p;

	p = enc;

	for (i = 0; i < len - 2; i += 3) {
		val = (str[i] >> 2) & 0x3F;
		assert(val < sizeof(b64));
		*p++ = b64[val];

		val = ((str[i] & 0x3) << 4) | 
			((int)(str[i + 1] & 0xF0) >> 4);
		assert(val < sizeof(b64));
		*p++ = b64[val];

		val = ((str[i + 1] & 0xF) << 2) | 
			((int)(str[i + 2] & 0xC0) >> 6);
		assert(val < sizeof(b64));
		*p++ = b64[val];

		val = str[i + 2] & 0x3F;
		assert(val < sizeof(b64));
		*p++ = b64[val];
	}

	if (i < len) {
		val = (str[i] >> 2) & 0x3F;
		assert(val < sizeof(b64));
		*p++ = b64[val];

		if (i == (len - 1)) {
			val = ((str[i] & 0x3) << 4);
			assert(val < sizeof(b64));
			*p++ = b64[val];
			*p++ = '=';
		} else {
			val = ((str[i] & 0x3) << 4) |
				((int)(str[i + 1] & 0xF0) >> 4);
			assert(val < sizeof(b64));
			*p++ = b64[val];

			val = ((str[i + 1] & 0xF) << 2);
			assert(val < sizeof(b64));
			*p++ = b64[val];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return(p - enc);
}

/*
 * Pass a stream of bytes to be base64 encoded, then converted into
 * base64url format.
 */
static char *
base64buf_url(const char *data, size_t len)
{
	size_t	 i, sz;
	char	*buf;

	sz = base64len(len);
	if (NULL == (buf = malloc(sz))) {
		dowarn("malloc");
		return(NULL);
	}
	base64buf(buf, data, len);

	for (i = 0; i < sz; i++)
		if ('+' == buf[i] || '/' == buf[i])
			buf[i] = '_';
		else if ('=' == buf[i])
			buf[i] = '\0';

	return(buf);
}

/*
 * Write a BIGNUM value in the format expected by JWK, which wants the
 * base64url encoding of their big-endian representations.
 * Reference: RFC 7517 - JSON Web Key (JWK).
 */
static int
writevalue(int netsock, const BIGNUM *bn, const char *name)
{
	int	 len, rc;
	size_t	 sz;
	char	*buf, *bbuf;
	ssize_t	 ssz;

	rc = 0;
	buf = bbuf = NULL;
	
	/* Extract big-endian representation of BIGNUM. */
	len = BN_num_bytes(bn);
	if (NULL == (buf = malloc(len))) {
		dowarn("malloc");
		goto out;
	} else if (len != BN_bn2bin(bn, (unsigned char *)buf)) {
		dowarnx("BN_bn2bin");
		goto out;
	}

	/* Convert to base64url. */
	bbuf = base64buf_url(buf, len);
	sz = strlen(bbuf);

	/* Write length and buffer to stream. */
	if ((ssz = write(netsock, &sz, sizeof(size_t))) < 0) {
		dowarn("write: %s length", name);
		goto out;
	} else if ((size_t)ssz != sizeof(size_t)) {
		dowarnx("short write: %s length", name);
		goto out;
	} else if ((ssz = write(netsock, bbuf, sz)) < 0) {
		dowarn("write: %s", name);
		goto out;
	} else if ((size_t)ssz != sz) {
		dowarnx("short write: %s", name);
		goto out;
	}

	rc = 1;
out:
	/* Clean up. */
	free(buf);
	free(bbuf);
	return(rc);
}

int
acctproc(int netsock, const char *acctkey)
{
	FILE		*f;
	RSA		*r;

	/* Do this before we chroot()? */
	ERR_load_crypto_strings();

	/* 
	 * Next, open our private key file.
	 * After this, we're going to go dark.
	 */
	if (NULL == (f = fopen(acctkey, "r")))
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

#ifdef __OpenBSD__
	/* 
	 * On OpenBSD, we won't use anything more than what we've
	 * inherited from our open descriptors.
	 */
	if (-1 == pledge("stdio", NULL))
		doerr("pledge");
#endif

	dodbg("parsing private key: %s", acctkey);

	/* 
	 * Parse our private key from an already-open steam.
	 * From now on, use the "error" label for errors.
	 */
	r = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	if (NULL == r) {
		dowarnx("%s", acctkey);
		goto error;
	}
	fclose(f);

	dodbg("serialising private key: %s", acctkey);

	/*
	 * Now write the exponent and modulus in the JWK format.
	 */
	if ( ! writevalue(netsock, r->n, "modulus")) {
		dowarnx("writevalue: modulus");
		goto error;
	} else if ( ! writevalue(netsock, r->e, "exponent")) {
		dowarnx("writevalue: exponent");
		goto error;
	}

	RSA_free(r);
	ERR_free_strings();
	dodbg("finished");
	return(1);
error:
	ERR_print_errors_fp(stderr);
	if (NULL != f)
		fclose(f);
	if (NULL != r)
		RSA_free(r);
	ERR_free_strings();
	return(0);
}

