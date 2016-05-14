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
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include "extern.h"

#define	PATH_RESOLV "/etc/resolv.conf"
#if 0
# define URL_CA "https://acme-v01.api.letsencrypt.org/directory"
#else
# define URL_CA "https://acme-staging.api.letsencrypt.org/directory"
#endif
#define URL_LICENSE "https://letsencrypt.org" \
		    "/documents/LE-SA-v1.0.1-July-27-2015.pdf"

#define	RETRY_DELAY 5
#define RETRY_MAX 10

struct	buf {
	char	*buf;
	size_t	 sz;
};

/*
 * Clean up the environment.
 * This will only have one file in it (within one directory).
 * This allows for errors and frees "dir" on exit.
 */
static void
netcleanup(char *dir)
{
	char	*tmp;

	if (NULL == dir)
		return;

	/* Start with the jail's resolv.conf. */

	if (-1 == asprintf(&tmp, "%s" PATH_RESOLV, dir)) {
		dowarn("asprintf");
		tmp = NULL;
	} else if (-1 == remove(tmp) && ENOENT != errno) 
		dowarn("%s", tmp);

	free(tmp);

	/* Now the etc directory containing the resolv. */

	if (-1 == asprintf(&tmp, "%s/etc", dir)) {
		dowarn("asprintf");
		tmp = NULL;
	} else if (-1 == remove(tmp) && ENOENT != errno)
		dowarn("%s", tmp);

	free(tmp);

	/* Finally, the jail itself. */

	if (-1 == remove(dir) && ENOENT != errno)
		dowarn("%s", dir);

	free(dir);
}

/*
 * Prepare the file-system jail.
 * This will create a temporary directory and fill it with the
 * /etc/resolv.conf from the host.
 * This file is used by the DNS resolver and is the only file necessary
 * within the chroot.
 * This doesn't work with Mac OS X.
 * Returns NULL on failure, else the new root.
 */
static char *
netprepare(void)
{
	char	*dir, *tmp;
	int	 fd, oflags, fd2;
	char	 dbuf[BUFSIZ];
	ssize_t	 ssz, ssz2;

	fd = fd2 = -1;
	tmp = dir = NULL;

	dir = strdup("/tmp/letskencrypt.XXXXXXXXXX");
	if (NULL == dir) {
		dowarn("strdup");
		goto err;
	} else if (NULL == mkdtemp(dir)) {
		dowarn("mkdtemp");
		goto err;
	}

	/* Create the /etc directory. */

	if (-1 == asprintf(&tmp, "%s/etc", dir)) {
		dowarn("asprintf");
		goto err;
	} else if (-1 == mkdir(tmp, 0755)) {
		dowarn("%s", tmp);
		goto err;
	}

	free(tmp);
	tmp = NULL;

	/* Open /etc/resolv.conf and get ready. */

	fd2 = open(PATH_RESOLV, O_RDONLY, 0);
	if (-1 == fd2) {
		dowarn(PATH_RESOLV);
		goto err;
	}

	oflags = O_CREAT|O_TRUNC|O_WRONLY|O_APPEND;
	if (-1 == asprintf(&tmp, "%s" PATH_RESOLV, dir)) {
		dowarn("asprintf");
		goto err;
	} else if (-1 == (fd = open(tmp, oflags, 0644))) {
		dowarn("%s", tmp);
		goto err;
	}

	/* Copy via a static buffer. */

	while ((ssz = read(fd2, dbuf, sizeof(dbuf))) > 0) {
		if ((ssz2 = write(fd, dbuf, ssz)) < 0) {
			dowarn("%s", tmp);
			goto err;
		} else if (ssz2 != ssz) {
			dowarnx("%s: short write", tmp);
			goto err;
		}
	}
	if (ssz < 0) {
		dowarn(PATH_RESOLV);
		goto err;
	}

	close(fd);
	close(fd2);
	free(tmp);
	return(dir);
err:
	if (-1 != fd)
		close(fd);
	if (-1 != fd2)
		close(fd2);
	free(tmp);
	netcleanup(dir);
	return(NULL);
}

/*
 * Handling non-JSON HTTP body contents.
 * This is, for the time being, a DER-encoded key.
 */
static size_t 
netbody(void *ptr, size_t sz, size_t nm, void *arg)
{
	struct buf	*buf = arg;
	size_t		 nsz;
	void		*pp;

	nsz = sz * nm;
	if (verbose > 1)
		dodbg("received: [%.*s]", (int)nsz, ptr);
	pp = realloc(buf->buf, buf->sz + nsz + 1);
	if (NULL == pp) {
		dowarn("realloc");
		return(0);
	}
	buf->buf = pp;
	memcpy(buf->buf + buf->sz, ptr, nsz);
	buf->sz += nsz;
	buf->buf[buf->sz] = '\0';
	return(nsz);
}

/*
 * Look for, extract, and duplicate the Replay-Nonce header.
 * Ignore all other headers.
 */
static size_t 
netheaders(void *ptr, size_t sz, size_t nm, void *arg)
{
	char		**noncep = arg;
	size_t		  nsz, psz;

	nsz = sz * nm;
	if (strncmp(ptr, "Replay-Nonce: ", 14)) 
		return(nsz);

	if (NULL == (*noncep = strdup((char *)ptr + 14))) {
		dowarn("strdup");
		return(0);
	} else if ((psz = strlen(*noncep)) < 2) {
		dowarnx("short nonce");
		return(0);
	}
	(*noncep)[psz - 2] = '\0';
	return(nsz);
}

/*
 * Send a "regular" HTTP GET message to "addr".
 * On non-zero return, stuffs the HTTP code into "code".
 */
static int
nreq(CURL *c, const char *addr, long *code, struct json *json)
{
	CURLcode	 res;

	json_reset(json);
	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_URL, addr);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	if (verbose > 1)
		curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, jsonbody);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, json);

	if (CURLE_OK != (res = curl_easy_perform(c))) {
	      dowarnx("%s: %s", addr, curl_easy_strerror(res));
	      return(0);
	}

	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, code);
	return(1);
}

/*
 * Create and send a signed communication to the ACME server.
 * On non-zero return, stuffs the HTTP response into "code".
 * If json is non-NULL, it's used to store any response body; if NULL
 * and buf is non-NULL, buf is used as an opaque buffer.
 */
static int
sreq(int fd, CURL *c, const char *addr, const char *req, 
	long *code, struct json *json, struct buf *buf)
{
	char		*nonce, *reqsn;
	CURLcode	 res;

	nonce = NULL;

	/* Grab our nonce by querying the CA. */

	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_URL, URL_CA);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, netheaders);
	curl_easy_setopt(c, CURLOPT_HEADERDATA, &nonce);

	if (CURLE_OK != (res = curl_easy_perform(c))) {
		dowarnx("%s: %s", URL_CA, curl_easy_strerror(res));
		free(nonce);
		return(0);
	} else if (NULL == nonce) {
		dowarnx("%s: no replay nonce", URL_CA);
		return(0);
	}

	/* 
	 * Send the nonce and request payload to the acctproc.
	 * This will create the proper JSON object we need.
	 */

	if ( ! writeop(fd, COMM_ACCT, ACCT_SIGN)) {
		free(nonce);
		return(0);
	} else if ( ! writestr(fd, COMM_PAY, req)) {
		free(nonce);
		return(0);
	} else if ( ! writestr(fd, COMM_NONCE, nonce)) {
		free(nonce);
		return(0);
	}
	free(nonce);
	if (NULL == (reqsn = readstr(fd, COMM_REQ)))
		return(0);

	/* Now send the signed payload to the CA. */

	json_reset(json);
	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_URL, addr);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(c, CURLOPT_POSTFIELDS, reqsn);
	if (verbose > 1)
		curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);
	if (NULL != json) {
		curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, jsonbody);
		curl_easy_setopt(c, CURLOPT_WRITEDATA, json);
	} else if (NULL != buf) {
		curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, netbody);
		curl_easy_setopt(c, CURLOPT_WRITEDATA, buf);
	}

	if (CURLE_OK != (res = curl_easy_perform(c))) {
	      dowarnx("%s: %s", addr, curl_easy_strerror(res));
	      free(reqsn);
	      return(0);
	}

	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, code);
	free(reqsn);
	return(1);
}

/*
 * Send to the CA that we want to authorise a new account.
 * This only happens once for a new account key.
 * Returns non-zero on success.
 */
static int
donewreg(CURL *c, int fd, struct json *json, const struct capaths *p)
{
	int	 cc, rc;
	char	*req;
	long	 lc;

	cc = asprintf(&req, "{\"resource\": \"new-reg\", "
		"\"agreement\": \"%s\"}", URL_LICENSE);
	if (-1 == cc) {
		dowarn("asprintf");
		return(0);
	} 
	
	rc = 0;
	dodbg("%s: new-reg", p->newreg);
	if ( ! sreq(fd, c, p->newreg, req, &lc, json, NULL))
		dowarnx("%s: bad comm", p->newreg);
	else if (200 != lc && 201 != lc)
		dowarnx("%s: bad HTTP: %ld", p->newreg, lc);
	else
		rc = 1;

	free(req);
	return(rc);
}

/*
 * Request a challenge for the given domain name.
 * This must happen for each name "alt".
 * On non-zero exit, fills in "chng" with the challenge.
 */
static int
dochngreq(CURL *c, int fd, struct json *json, 
	const char *alt, struct chng *chng, const struct capaths *p)
{
	int	 cc, rc;
	char	*req;
	long	 lc;

	cc = asprintf(&req, 
		"{\"resource\": \"new-authz\", \"identifier\": "
		"{\"type\": \"dns\", \"value\": \"%s\"}}", alt);
	if (-1 == cc) {
		dowarn("asprintf");
		return(0);
	} 

	rc = 0;
	dodbg("%s: req-auth: %s", p->newauthz, alt);
	if ( ! sreq(fd, c, p->newauthz, req, &lc, json, NULL))
		dowarnx("%s: bad comm", p->newauthz);
	else if (200 != lc && 201 != lc)
		dowarnx("%s: bad HTTP: %ld", p->newauthz, lc);
	else if ( ! json_parse_challenge(json, chng)) 
		dowarnx("%s: bad challenge", p->newauthz);
	else
		rc = 1;

	free(req);
	return(rc);
}

/*
 * Note to the CA that a challenge response is in place.
 */
static int
dochngresp(CURL *c, int fd, struct json *json, 
	const struct chng *chng, const char *th)
{
	int	 cc, rc;
	long	 lc;
	char	*req;

	cc = asprintf(&req, "{\"resource\": \"challenge\", "
		"\"keyAuthorization\": \"%s.%s\"}", chng->token, th);
	if (-1 == cc) {
		dowarn("asprintf");
		return(0);
	}

	rc = 0;
	dodbg("%s: challenge", chng->uri);

	if ( ! sreq(fd, c, chng->uri, req, &lc, json, NULL))
		dowarnx("%s: bad comm", chng->uri);
	else if (200 != lc && 201 != lc && 202 != lc) 
		dowarnx("%s: bad HTTP: %ld", chng->uri, lc);
	else if (-1 == (cc = json_parse_response(json))) 
		dowarnx("%s: bad response", chng->uri);
	else
		rc = 1;

	free(req);
	return(rc);
}

/*
 * Check with the CA whether a challenge has been processed.
 * Note: we'll only do this a limited number of times, and pause for a
 * time between checks, but this happens in the caller.
 */
static int
dochngcheck(CURL *c, struct json *json, struct chng *chng)
{
	int	 cc;
	long	 lc;

	dodbg("%s: status", chng->uri);

	if ( ! nreq(c, chng->uri, &lc, json)) {
		dowarnx("%s: bad comm", chng->uri);
		return(0);
	} else if (200 != lc && 201 != lc && 202 != lc) {
		dowarnx("%s: bad HTTP: %ld", chng->uri, lc);
		return(0);
	} else if (-1 == (cc = json_parse_response(json))) {
		dowarnx("%s: bad response", chng->uri);
		return(0);
	} else if (0 == cc)
		chng->status = 1;

	return(1);
}

/*
 * Submit our certificate to the CA.
 * This, upon success, will return the signed CA.
 */
static int
docert(CURL *c, int fd, const char *addr, 
	struct buf *buf, const char *cert)
{
	char	*req;
	int	 cc, rc;
	long	 lc;

	cc = asprintf(&req, "{\"resource\": \"new-cert\", "
		"\"csr\": \"%s\"}", cert);
	if (-1 == cc) {
		dowarn("asprintf");
		return(0);
	}

	rc = 0;
	dodbg("%s: certificate", addr);

	if ( ! sreq(fd, c, addr, req, &lc, NULL, buf))
		dowarnx("%s: bad comm", addr);
	else if (200 != lc && 201 != lc)
		dowarnx("%s: bad HTTP: %ld", addr, lc);
	else if (0 == buf->sz || NULL == buf->buf)
		dowarnx("%s: empty response", addr);
	else
		rc = 1;

	free(req);
	return(rc);
}

/*
 * Here we communicate with the letsencrypt server.
 * For this, we'll need the certificate we want to upload and our
 * account key information.
 */
int
netproc(int kfd, int afd, int Cfd, int cfd, int newacct, 
	uid_t uid, gid_t gid, const char *const *alts, size_t altsz)
{
	pid_t		 pid;
	int		 st, rc;
	size_t		 i;
	char		*home, *cert, *req, *reqsn, *thumb;
	CURL		*c;
	struct buf	 buf;
	struct json	*json;
	struct capaths	 paths;
	struct chng 	*chngs;
	long		 http, op;
	extern enum comp proccomp;

	proccomp = COMP_NET;
	rc = EXIT_FAILURE;

	/* Prepare our file-system jail. */

	if (NULL == (home = netprepare()))
		return(0);

	/*
	 * Begin by forking.
	 * We need to do this because somebody needs to clean up the
	 * jail, and we can't do that if we're already in it.
	 */
	if (-1 == (pid = fork())) 
		doerr("fork");

	if (pid > 0) {
		/* XXX: keep privileges to netcleanup(). */
		close(kfd);
		close(afd);
		close(Cfd);
		close(cfd);
		if (-1 == waitpid(pid, &st, 0))
			doerr("waitpid");
		netcleanup(home);
		return(WIFEXITED(st) && 
		       EXIT_SUCCESS == WEXITSTATUS(st));
	}

	/*
	 * File-system, user, and sandbox jail.
	 */

#ifdef __APPLE__
	if (-1 == sandbox_init(kSBXProfileNoWrite, 
 	    SANDBOX_NAMED, NULL))
		doerr("sandbox_init");
#endif
#ifndef __APPLE__
	if (-1 == chroot(home))
		doerr("%s: chroot", home);
	else if (-1 == chdir("/"))
		doerr("/: chdir");
#endif
#if defined(__OpenBSD__) && OpenBSD >= 201605
	if (-1 == pledge("stdio dns", NULL))
		doerr("pledge");
#endif
	if ( ! dropprivs(uid, gid))
		doerrx("dropprivs");

	free(home);
	home = NULL;

	/* Zero all the things. */
	memset(&paths, 0, sizeof(struct capaths));
	memset(&buf, 0, sizeof(struct buf));
	reqsn = req = cert = thumb = NULL;
	json = NULL;
	c = NULL;
	chngs = NULL;

	/* Allocate main state. */

	chngs = calloc(altsz, sizeof(struct chng));
	if (NULL == chngs) {
		dowarn("calloc");
		goto out;
	} else if (NULL == (c = curl_easy_init())) {
		dowarn("curl_easy_init");
		goto out;
	} else if (NULL == (json = json_alloc())) {
		dowarnx("json_alloc");
		goto out;
	}

	/* Grab the directory structure from the CA. */

	dodbg("%s: requesting directories", URL_CA);
	if ( ! nreq(c, URL_CA, &http, json)) {
		dowarnx("%s: bad comm", URL_CA);
		goto out;
	} else if (200 != http && 201 != http) {
		dowarnx("%s: bad HTTP: %ld", URL_CA, http);
		goto out;
	} else if ( ! json_parse_capaths(json, &paths)) {
		dowarnx("%s: bad CA paths", URL_CA);
		goto out;
	}

	/* If new, register with the CA server. */

	if (newacct && ! donewreg(c, afd, json, &paths))
		goto out;

	/* Pre-authorise all domains with CA server. */

	for (i = 0; i < altsz; i++)
		if ( ! dochngreq(c, afd, json, 
		    alts[i], &chngs[i], &paths))
			goto out;

	/*
	 * We now have our challenges.
	 * We need to ask the acctproc for the thumbprint.
	 * We'll combine this to the challenge to create our response,
	 * which will be orchestrated by the chngproc.
	 */

	if ( ! writeop(afd, COMM_ACCT, ACCT_THUMBPRINT))
		goto out;
	else if (NULL == (thumb = readstr(afd, COMM_THUMB)))
		goto out;

	/*
	 * We'll now create the challenge area for each request.
	 * Following that, we'll send to the CA that the challenge is
	 * ready to be accessed.
	 */

	for (i = 0; i < altsz; i++)
		if ( ! writeop(Cfd, COMM_CHNG_OP, 1))
			goto out;
		else if ( ! writestr(Cfd, COMM_THUMB, thumb))
			goto out;
		else if ( ! writestr(Cfd, COMM_TOK, chngs[i].token))
			goto out;
		else if (0 == (op = readop(Cfd, COMM_CHNG_ACK)))
			goto out;
		else if (LONG_MAX == op)
			goto out;
		else if ( ! dochngresp(c, afd, json, &chngs[i], thumb))
			goto out;

	/*
	 * We now wait on the ACME server for each domain.
	 * Connect to the server (assume it's the same server) once
	 * every five seconds.
	 */

	for (i = 0; i < altsz; i++) {
		if (1 == chngs[i].status)
			continue;

		if (chngs[i].retry++ >= RETRY_MAX) {
			dowarnx("%s: too many tries", chngs[i].uri);
			goto out;
		}

		/* Sleep before every attempt. */
		sleep(RETRY_DELAY);
		if ( ! dochngcheck(c, json, &chngs[i]))
			goto out;
	}

	/* 
	 * Write our acknowledgement that the challenges are over.
	 * The challenge process will remove all of the files.
	 */

	if ( ! writeop(Cfd, COMM_CHNG_OP, 0))
		goto out;

	/*
	 * Now wait until we've received the certificate we want to send
	 * to the letsencrypt server; and once we have it, we send it to
	 * the CA for signing, download the signed copy, and ship that
	 * into the certificate process for copying.
	 */

	if (NULL == (cert = readstr(kfd, COMM_CERT)))
		goto out;
	else if ( ! docert(c, afd, paths.newcert, &buf, cert)) 
		goto out;
	else if ( ! writebuf(cfd, COMM_CSR, buf.buf, buf.sz))
		goto out;

	rc = EXIT_SUCCESS;
out:
	if (-1 != cfd)
		close(cfd);
	if (-1 != kfd)
		close(kfd);
	if (-1 != afd)
		close(afd);
	if (-1 != Cfd)
		close(Cfd);
	free(cert);
	free(req);
	free(reqsn);
	free(thumb);
	free(buf.buf);
	if (NULL != c)
		curl_easy_cleanup(c);
	curl_global_cleanup();
	json_free(json);
	for (i = 0; i < altsz; i++)
		json_free_challenge(&chngs[i]);
	free(chngs);
	json_free_capaths(&paths);
	exit(rc);
	/* NOTREACHED */
}
