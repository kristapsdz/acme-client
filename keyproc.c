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
#include <openssl/X509.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "extern.h"

/*
 * Create an X509 certificate from the private RSA key we have on file.
 * To do this, we first open the RSA key file, then jail ourselves.
 * We then use the crypto library to create the certificate within the
 * jail and, on success, ship it to "netsock" as an X509 request.
 */
int
keyproc(int netsock, const char *certdir, const unsigned char *domain)
{
	char		 *path;
	FILE		 *f, *sockf;
	RSA		 *r;
	EVP_PKEY	 *evp;
	X509_REQ	 *x;
	X509_NAME 	 *name;
	unsigned char	  rbuf[64];

	/* Do this before we chroot()? */
	ERR_load_crypto_strings();

	if (-1 == asprintf(&path, "%s/privkey.pem", certdir)) 
		err(EXIT_FAILURE, "asprintf");

	/* 
	 * Next, open our private key file.
	 * After this, we're going to go dark.
	 */
	if (NULL == (f = fopen(path, "r")))
		err(EXIT_FAILURE, "%s", path);

#ifdef __APPLE__
	/*
	 * We would use "pure computation", which is correct, but then
	 * we wouldn't be able to chroot().
	 * This call also can't happen after the chroot(), so we're
	 * stuck with a weaker sandbox.
	 */
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL)) {
		warnx("sandbox_init");
		exit(EXIT_FAILURE);
	}
#endif
	/*
	 * Jails: start with file-system.
	 * Go into the usual place.
	 */
	if (-1 == chroot("/var/empty"))
		err(EXIT_FAILURE, "%s: chroot", "/var/empty");
	if (-1 == chdir("/"))
		err(EXIT_FAILURE, "/: chdir");
	if (NULL == (sockf = fdopen(netsock, "a")))
		err(EXIT_FAILURE, "fdopen");

#ifdef __OpenBSD__
	/* 
	 * On OpenBSD, we won't use anything more than what we've
	 * inherited from our open descriptors.
	 */
	if (-1 == pledge("stdio", NULL))
		err(EXIT_FAILURE, "pledge");
#endif

	x = NULL;
	evp = NULL;
	r = NULL;
	name = NULL;

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
		warnx("%s", path);
		goto error;
	}
	fclose(f);
	f = NULL;

	/*
	 * We're going to merge this into an EVP.
	 * Once these succeed, the RSA key will be free'd with the EVP.
	 */
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

	/* 
	 * Now specify the common name that we'll request.
	 * TODO: SAN.
	 */
	if (NULL == (name = X509_NAME_new())) {
		warnx("X509_NAME_new");
		goto error;
	} else if ( ! X509_NAME_add_entry_by_txt(name, "CN", 
	           MBSTRING_ASC, domain, -1, -1, 0)) {
		warnx("X509_NAME_add_entry_by_txt: CN=%s", domain);
		goto error;
	} else if ( ! X509_REQ_set_subject_name(x, name)) {
		warnx("X509_req_set_issuer_name");
		goto error;
	}
	
	/*
	 * Finally, sign the X509 request using SHA256.
	 * Then write it into the netproc()'s socket.
	 */
	if ( ! X509_REQ_sign(x, evp, EVP_sha256())) {
		warnx("X509_sign");
		goto error;
	} else if ( ! PEM_write_X509_REQ(sockf, x)) {
		warnx("PEM_write_X509_REQ");
		goto error;
	}

	/* 
	 * Cleanup: we're finished here.
	 */
	fclose(sockf);
	X509_REQ_free(x);
	EVP_PKEY_free(evp);
	X509_NAME_free(name);
	ERR_free_strings();
	return(1);

error:
	if (NULL != f)
		fclose(f);
	fclose(sockf);
	ERR_print_errors_fp(stderr);
	if (NULL != x)
		X509_REQ_free(x);
	if (NULL != r)
		RSA_free(r);
	if (NULL != name)
		X509_NAME_free(name);
	if (NULL != evp)
		EVP_PKEY_free(evp);
	ERR_free_strings();
	return(0);
}

