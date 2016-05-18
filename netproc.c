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

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include "extern.h"

#if 0
# define URL_CA "https://acme-v01.api.letsencrypt.org/directory"
#else
# define URL_CA "https://acme-staging.api.letsencrypt.org/directory"
#endif
#define URL_LICENSE "https://letsencrypt.org" \
		    "/documents/LE-SA-v1.0.1-July-27-2015.pdf"

#define	RETRY_DELAY 5
#define RETRY_MAX 10

/*
 * Buffer used when collecting the results of a CURL transfer.
 */
struct	buf {
	char	*buf; /* binary buffer */
	size_t	 sz; /* length of buffer */
};

/*
 * Reset the contents of a buffer prior to transfer.
 * This can be called regardless of whether buf is NULL.
 */
static void
buf_reset(struct buf *buf)
{

	if (NULL == buf) 
		return;

	free(buf->buf);
	buf->buf = NULL;
	buf->sz = 0;
}

/*
 * Extract the domain and port from a URL.
 * The url must be formatted as schema://address[/stuff].
 * This returns NULL on failure.
 */
static char *
url2host(const char *host, short *port)
{
	char	*url, *ep;

	/* We only understand HTTP and HTTPS. */

	if (0 == strncmp(host, "https://", 8)) {
		*port = 443;
		if (NULL == (url = strdup(host + 8))) {
			dowarn("strdup");
			return(NULL);
		}
	} else if (0 == strncmp(host, "http://", 7)) {
		*port = 80;
		if (NULL == (url = strdup(host + 7))) {
			dowarn("strdup");
			return(NULL);
		}
	} else {
		dowarnx("%s: unknown schema", host);
		return(NULL);
	}

	/* Terminate path part. */

	if (NULL != (ep = strchr(url, '/')))
		*ep = '\0';

	return(url);
}

/*
 * Given a url, translate it into a domain, resolve the address of the
 * domain, then fill in a curl_slist in the format CURL wants for its
 * internal resolver lookups.
 */
static struct curl_slist *
urlresolve(int fd, const char *url)
{
	char	  	  *host, *addr, *buf;
	int	  	   rc, cc;
	size_t	  	   i;
	short	  	   port;
	long	  	   lval;
	struct curl_slist *hosts;

	host = buf = addr = NULL;
	hosts = NULL;
	rc = 0;

	if (NULL == (host = url2host(url, &port))) {
		dowarnx("%s: url2host", url);
		goto out;
	}

	dodbg("%s: resolving", host);

	if ( ! writeop(fd, COMM_DNS, DNS_LOOKUP))
		goto out;
	else if ( ! writestr(fd, COMM_DNSQ, host))
		goto out;

	if ((lval = readop(fd, COMM_DNSLEN)) < 0)
		goto out;

	for (i = 0; i < (size_t)lval; i++) {
		if (NULL == (addr = readstr(fd, COMM_DNSA))) 
			goto out;

		/* XXX XXX XXX */
		if (i > 0) {
			free(addr);
			addr = NULL;
			continue;
		}

		cc = asprintf(&buf, "%s:%hd:%s", host, port, addr);
		if (-1 == cc) {
			dowarn("asprintf");
			buf = NULL;
			goto out;
		}

		hosts = curl_slist_append(hosts, buf);
		if (NULL == hosts) {
			dowarnx("curl_slist_append");
			goto out;
		}

		free(buf);
		free(addr);
		buf = addr = NULL;
	}

	rc = 1;
out:
	if (0 == rc) {
		curl_slist_free_all(hosts);
		hosts = NULL;
	}
	free(host);
	free(buf);
	free(addr);
	return(hosts);
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
	/*doddbg("received: [%.*s]", (int)nsz, ptr);*/
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
nreq(CURL *c, const char *addr, long *code, 
	struct json *json, struct buf *buf, struct curl_slist *hosts)
{
	CURLcode	 res;

	buf_reset(buf);
	json_reset(json);
	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_RESOLVE, hosts);
	curl_easy_setopt(c, CURLOPT_URL, addr);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
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
	long *code, struct json *json, struct buf *buf,
	struct curl_slist *hosts)
{
	char		*nonce, *reqsn;
	CURLcode	 res;

	nonce = NULL;

	/* Grab our nonce by querying the CA. */

	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_RESOLVE, hosts);
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

	buf_reset(buf);
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
donewreg(CURL *c, int fd, struct json *json, const struct capaths *p,
	struct curl_slist *hosts)
{
	int	 rc;
	char	*req;
	long	 lc;

	rc = 0;
	dodbg("%s: new-reg", p->newreg);

	if (NULL == (req = json_fmt_newreg(URL_LICENSE)))
		dowarnx("json_fmt_newreg");
	else if ( ! sreq(fd, c, p->newreg, req, &lc, json, NULL, hosts))
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
dochngreq(CURL *c, int fd, struct json *json, const char *alt, 
	struct chng *chng, const struct capaths *p, struct curl_slist *hosts)
{
	int	 rc;
	char	*req;
	long	 lc;

	rc = 0;
	dodbg("%s: req-auth: %s", p->newauthz, alt);

	if (NULL == (req = json_fmt_newauthz(alt)))
		dowarnx("json_fmt_newauthz");
	else if ( ! sreq(fd, c, p->newauthz, req, &lc, json, NULL, hosts))
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
	const struct chng *chng, const char *th, struct curl_slist *hosts)
{
	int	 rc;
	long	 lc;
	char	*req;

	rc = 0;
	dodbg("%s: challenge", chng->uri);

	if (NULL == (req = json_fmt_challenge(chng->token, th)))
		dowarnx("json_fmt_challenge");
	else if ( ! sreq(fd, c, chng->uri, req, &lc, json, NULL, hosts))
		dowarnx("%s: bad comm", chng->uri);
	else if (200 != lc && 201 != lc && 202 != lc) 
		dowarnx("%s: bad HTTP: %ld", chng->uri, lc);
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
dochngcheck(CURL *c, struct json *json, struct chng *chng,
	struct curl_slist *hosts)
{
	int	 cc;
	long	 lc;

	dodbg("%s: status", chng->uri);

	if ( ! nreq(c, chng->uri, &lc, json, NULL, hosts)) {
		dowarnx("%s: bad comm", chng->uri);
		return(0);
	} else if (200 != lc && 201 != lc && 202 != lc) {
		dowarnx("%s: bad HTTP: %ld", chng->uri, lc);
		return(0);
	} else if (-1 == (cc = json_parse_response(json))) {
		dowarnx("%s: bad response", chng->uri);
		return(0);
	} else if (cc > 0)
		chng->status = 1;

	return(1);
}

static int
dorevoke(CURL *c, int fd, const char *addr, 
	const char *cert, struct curl_slist *hosts)
{
	char		*req;
	int		 rc;
	long		 lc;
	struct buf	 buf;

	memset(&buf, 0, sizeof(struct buf));
	lc = 0;
	rc = 0;
	dodbg("%s: revoking", addr);

	if (NULL == (req = json_fmt_revokecert(cert)))
		dowarnx("json_fmt_revokecert");
	else if ( ! sreq(fd, c, addr, req, &lc, NULL, &buf, hosts))
		dowarnx("%s: bad comm", addr);
	else if (200 != lc && 201 != lc && 409 != lc)
		dowarnx("%s: bad HTTP: %ld", addr, lc);
	else
		rc = 1;

	if (409 == lc)
		dowarnx("%s: already revoked", addr);

	free(buf.buf);
	free(req);
	return(rc);
}

/*
 * Submit our certificate to the CA.
 * This, upon success, will return the signed CA.
 */
static int
docert(CURL *c, int fd, const char *addr, struct buf *buf, 
	const char *cert, struct curl_slist *hosts)
{
	char	*req;
	int	 rc;
	long	 lc;

	rc = 0;
	dodbg("%s: certificate", addr);

	if (NULL == (req = json_fmt_newcert(cert)))
		dowarnx("json_fmt_newcert");
	else if ( ! sreq(fd, c, addr, req, &lc, NULL, buf, hosts))
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
netproc(int kfd, int afd, int Cfd, int cfd, int dfd, int rfd,
	int newacct, int revoke, uid_t uid, gid_t gid, 
	const char *const *alts, size_t altsz)
{
	int		 rc;
	size_t		 i;
	char		*cert, *thumb, *url;
	CURL		*c;
	struct buf	 buf;
	struct json	*json;
	struct capaths	 paths;
	struct chng 	*chngs;
	long		 http, lval;
	struct curl_slist *hosts;

	rc = 0;
	memset(&paths, 0, sizeof(struct capaths));
	memset(&buf, 0, sizeof(struct buf));
	url = cert = thumb = NULL;
	json = NULL;
	c = NULL;
	chngs = NULL;
	hosts = NULL;

	/* File-system, user, and sandbox jail. */

	if ( ! sandbox_before()) {
		dowarnx("sandbox_before");
		goto out;
	} else if ( ! dropfs(PATH_VAR_EMPTY)) {
		dowarnx("dropfs");
		goto out;
	} else if ( ! dropprivs(uid, gid)) {
		dowarnx("dropprivs");
		goto out;
	} else if ( ! sandbox_after()) {
		dowarnx("sandbox_after");
		goto out;
	}

	/* 
	 * Wait until the acctproc, keyproc, and revokeproc have started
	 * up and are ready to serve us data.
	 * There's no point in running if these don't work.
	 * Then check whether revokeproc indicates that the certificate
	 * on file (if any) can be updated.
	 */

	if (0 == (lval = readop(afd, COMM_ACCT_STAT))) {
		rc = 1;
		goto out;
	} else if (ACCT_READY != lval) {
		dowarnx("unknown operation from acctproc");
		goto out;
	}

	if (0 == (lval = readop(kfd, COMM_KEY_STAT))) {
		rc = 1;
		goto out;
	} else if (KEY_READY != lval) {
		dowarnx("unknown operation from keyproc");
		goto out;
	}

	if (0 == (lval = readop(rfd, COMM_REVOKE_RESP))) {
		rc = 1;
		goto out;
	} else if (REVOKE_EXP != lval && REVOKE_OK != lval) {
		dowarnx("unknown operation from revokeproc");
		goto out;
	} 

	if (REVOKE_OK == lval) {
		rc = 1;
		goto out;
	}
	
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

	/*
	 * Look up the domain of the ACME server.
	 * We'll use this ourselves instead of having libcurl do the DNS
	 * resolution itself.
	 */
	if (NULL == (hosts = urlresolve(dfd, URL_CA))) 
		goto out;
	dodbg("%s: requesting directories", URL_CA);
	if ( ! nreq(c, URL_CA, &http, json, NULL, hosts)) {
		dowarnx("%s: bad comm", URL_CA);
		goto out;
	} else if (200 != http && 201 != http) {
		dowarnx("%s: bad HTTP: %ld", URL_CA, http);
		goto out;
	} else if ( ! json_parse_capaths(json, &paths)) {
		dowarnx("%s: bad CA paths", URL_CA);
		goto out;
	}

	/*
	 * If we're meant to revoke, then wait for revokeproc to send us
	 * the certificate (if it's found at all).
	 * Following that, submit the request to the CA then notify the
	 * certproc, which will in turn notify the fileproc.
	 */

	if (revoke) {
		if (NULL == (cert = readstr(rfd, COMM_CSR)))
			goto out;

		if ( ! dorevoke(c, afd, paths.revokecert, cert, hosts)) 
			goto out;
		else if (writeop(cfd, COMM_CSR_OP, CERT_REVOKE))
			rc = 1;
		goto out;
	} 


	/* If new, register with the CA server. */

	if (newacct && ! donewreg(c, afd, json, &paths, hosts))
		goto out;

	/* Pre-authorise all domains with CA server. */

	for (i = 0; i < altsz; i++)
		if ( ! dochngreq(c, afd, json, 
		    alts[i], &chngs[i], &paths, hosts))
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

	/* We'll now ask chngproc to build the challenge. */

	for (i = 0; i < altsz; i++) {
		if ( ! writeop(Cfd, COMM_CHNG_OP, CHNG_SYN))
			goto out;
		else if ( ! writestr(Cfd, COMM_THUMB, thumb))
			goto out;
		else if ( ! writestr(Cfd, COMM_TOK, chngs[i].token))
			goto out;

		/* Read that the challenge has been made. */

		if (CHNG_ACK != readop(Cfd, COMM_CHNG_ACK))
			goto out;

		/* Write to the CA that it's ready. */

		if ( ! dochngresp(c, afd, json, &chngs[i], thumb, hosts))
			goto out;
	}

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
		if ( ! dochngcheck(c, json, &chngs[i], hosts))
			goto out;
	}

	/* 
	 * Write our acknowledgement that the challenges are over.
	 * The challenge process will remove all of the files.
	 */

	if ( ! writeop(Cfd, COMM_CHNG_OP, CHNG_STOP))
		goto out;

	/* Wait to receive the certificate itself. */

	if (NULL == (cert = readstr(kfd, COMM_CERT)))
		goto out;

	/*
	 * Otherwise, submit the CA for signing, download the signed
	 * copy, and ship that into the certificate process for copying.
	 */

	if ( ! docert(c, afd, paths.newcert, &buf, cert, hosts)) 
		goto out;
	else if ( ! writeop(cfd, COMM_CSR_OP, CERT_UPDATE))
		goto out;
	else if ( ! writebuf(cfd, COMM_CSR, buf.buf, buf.sz))
		goto out;

	/* 
	 * Read back the issuer from the certproc.
	 * Then contact the issuer to get the certificate chain.
	 * Write this chain directly back to the certproc.
	 */

	if (NULL == (url = readstr(cfd, COMM_ISSUER)))
		goto out;
	curl_slist_free_all(hosts);
	if (NULL == (hosts = urlresolve(dfd, url))) 
		goto out;
	dodbg("%s: requesting full-chain", url);
	if ( ! nreq(c, url, &http, NULL, &buf, hosts)) {
		dowarnx("%s: bad comm", url);
		goto out;
	} else if (200 != http && 201 != http) {
		dowarnx("%s: bad HTTP: %ld", url, http);
		goto out;
	} else if ( ! writebuf(cfd, COMM_CHAIN, buf.buf, buf.sz))
		goto out;

	rc = 1;
out:
	close(cfd);
	close(kfd);
	close(afd);
	close(Cfd);
	close(dfd);
	free(cert);
	free(url);
	free(thumb);
	free(buf.buf);
	if (NULL != c)
		curl_easy_cleanup(c);
	curl_slist_free_all(hosts);
	curl_global_cleanup();
	json_free(json);
	if (NULL != chngs)
		for (i = 0; i < altsz; i++)
			json_free_challenge(&chngs[i]);
	free(chngs);
	json_free_capaths(&paths);
	return(rc);
}
