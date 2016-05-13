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
#include <json-c/json.h>

#include "extern.h"

#define	PATH_RESOLV "/etc/resolv.conf"
#if 0
# define URL_CA "https://acme-v01.api.letsencrypt.org/directory"
#else
# define URL_CA "https://acme-staging.api.letsencrypt.org/directory"
#endif
#define URL_LICENSE "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

#define	SUB "netproc"

/*
 * The ACME server always serves up JSON.
 * This is used to parse the response as it comes over the wire.
 */
struct	json {
	struct json_tokener	*tok; /* tokeniser */
	struct json_object	*obj; /* result (NULL if pending) */
};

/*
 * This contains the URI and token of an ACME-issued challenge.
 * A challenge consists of a token, which we must present on the
 * (presumably!) local machine to an ACME connection; and a URI, to
 * which we must connect to verify the token.
 */
struct challenge {
	char		*uri; /* uri on ACME server */
	char		*token; /* token we must offer */
};

/*
 * This consists of the services offered by the CA.
 * They must all be filled in.
 */
struct	capaths {
	char		*newauthz; /* new authorisation */
	char		*newcert; 
	char		*newreg; /* new acme account */
	char		*revokecert;
};

static void
doerr(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverr(SUB, fmt, ap);
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
dowarn(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn(SUB, fmt, ap);
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

/*
 * Clean up the netproc() environment as created with netprepare().
 * This will only have one file in it (within one directory).
 * This allows for errors and frees "dir" on exit.
 */
static void
netcleanup(char *dir)
{
	char	*tmp;

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
		return(NULL);
	} else if (NULL == mkdtemp(dir)) {
		dowarn("mkdtemp");
		return(NULL);
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

	/* Open /etc/resolv.conf. */
	fd2 = open(PATH_RESOLV, O_RDONLY, 0);
	if (-1 == fd2) {
		dowarn(PATH_RESOLV);
		goto err;
	}

	/* Create the new /etc/resolv.conf file. */
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
 * Pass an HTTP response body directly to the JSON parser.
 * This will fail once the JSON object has been created (which is the
 * correct operation).
 */
static size_t 
jsonbody(void *ptr, size_t sz, size_t nm, void *arg)
{
	struct json	*json = arg;
	enum json_tokener_error er;

	if (NULL != json->obj) {
		dowarnx("data after complete JSON");
		return(0);
	}

	/* This will be non-NULL when we finish. */
	json->obj = json_tokener_parse_ex(json->tok, ptr, nm * sz);
	er = json_tokener_get_error(json->tok);

	if (er == json_tokener_success || 
	    er == json_tokener_continue)
		return(sz * nm);

	dowarnx("json_tokener_parse_ex: %s", 
		json_tokener_error_desc(er));
	return(0);
}

/*
 * Look for, extract, and duplicate the Replay-Nonce header.
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
 * Extract an array from the returned JSON object, making sure that it's
 * the correct type.
 * Returns NULL on failure.
 */
static json_object *
json_getarray(json_object *parent, const char *name)
{
	json_object	*p;

	if ( ! json_object_object_get_ex(parent, name, &p))
		dowarnx("no JSON object: %s", name);
	else if (json_type_array != json_object_get_type(p))
		dowarnx("bad JSON object type: %s", name);
	else
		return(p);

	return(NULL);
}

/*
 * Extract a single string from the returned JSON object, making sure
 * that it's the correct type.
 * Returns NULL on failure.
 */
static char *
json_getstr(json_object *parent, const char *name)
{
	json_object	*p;
	char		*cp;

	if ( ! json_object_object_get_ex(parent, name, &p))
		dowarnx("no JSON object: %s", name);
	else if (json_type_string != json_object_get_type(p))
		dowarnx("bad JSON object type: %s", name);
	else if (NULL == (cp = strdup(json_object_get_string(p))))
		dowarn("strdup");
	else
		return(cp);

	return(NULL);
}

/*
 * Initialise the JSON object we're going to use multiple time in
 * communicating with the ACME server.
 */
static int
json_init(struct json *json)
{

	if (NULL == (json->tok = json_tokener_new())) {
		dowarn("json_tokener_new");
		return(0);
	}
	return(1);
}

/*
 * Reset the JSON object between communications with the ACME server.
 * This should be called prior to each invocation, and can be called
 * multiple times around json_free and json_init.
 */
static void
json_reset(struct json *json)
{

	json_tokener_reset(json->tok);
	if (NULL != json->obj) {
		json_object_put(json->obj);
		json->obj = NULL;
	}
}

/*
 * Completely free the challeng response body.
 */
static void
challenge_free(struct challenge *p)
{

	free(p->uri);
	free(p->token);
	p->uri = p->token = NULL;
}

/*
 * Completely free the paths response body.
 */
static void
json_free(struct json *json)
{

	if (NULL != json->tok)
		json_tokener_free(json->tok);
	if (NULL != json->obj)
		json_object_put(json->obj);
	json->tok = NULL;
	json->obj = NULL;
}

static int
response_parse(struct json *json)
{
	char		*resp;
	int		 rc;

	if (NULL == (resp = json_getstr(json->obj, "status")))
		return(-1);
	rc = 0 == strcmp(resp, "pending");
	free(resp);
	return(rc);
}

/*
 * Parse the response from a new-authz, which consists of challenge
 * information, into a structure.
 * We only care about the HTTP-01 response.
 */
static int
challenge_parse(struct json *json, struct challenge *p)
{
	json_object	*array, *obj;
	int		 sz, i, rc;
	char		*type;

	array = json_getarray(json->obj, "challenges");
	if (NULL == array)
		return(0);
	sz = json_object_array_length(array);
	for (i = 0; i < sz; i++) {
		obj = json_object_array_get_idx(array, i);
		type = json_getstr(obj, "type");
		rc = strcmp(type, "http-01");
		free(type);
		if (rc)
			continue;
		p->uri = json_getstr(obj, "uri");
		p->token = json_getstr(obj, "token");
		return(NULL != p->uri &&
		       NULL != p->token);
	}

	return(0);
}

/*
 * Extract the CA paths from the JSON response object.
 */
static int
capaths_parse(struct json *json, struct capaths *p)
{

	p->newauthz = json_getstr(json->obj, "new-authz");
	p->newcert = json_getstr(json->obj, "new-cert");
	p->newreg = json_getstr(json->obj, "new-reg");
	p->revokecert = json_getstr(json->obj, "revoke-cert");

	return(NULL != p->newauthz &&
	       NULL != p->newcert &&
	       NULL != p->newreg &&
	       NULL != p->revokecert);
}

/*
 * Free up all of our CA-noted paths (which may all be NULL).
 */
static void
capaths_free(struct capaths *p)
{

	free(p->newauthz);
	free(p->newcert);
	free(p->newreg);
	free(p->revokecert);
}

static int
nreq(CURL *c, const char *addr, long *code, struct json *json)
{
	CURLcode	 res;

	dodbg("%s: getting request", addr);

	json_reset(json);
	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_URL, addr);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	/*curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);*/
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
 * We'll use the acctproc to sign the message for us.
 * We'll unconditionally download any returned body (which is always
 * JSON) into the json object.
 */
static int
sreq(int acctsock, CURL *c, const char *addr, 
	const char *req, long *code, struct json *json)
{
	char		*nonce, *reqsn;
	CURLcode	 res;

	dodbg("%s: nonce request", URL_CA);
	nonce = NULL;

	/*
	 * Grab our nonce.
	 * Do this before getting any of our account information.
	 * We specifically do only a HEAD request because all we want to
	 * do is grab a single field.
	 * We'll also grab the JSON content of the message, which has a
	 * directory of all the bits that we want.
	 */
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

	dodbg("%s: replay nonce: %s", URL_CA, nonce);

	/* 
	 * Send the nonce and request payload to the acctproc.
	 * This will create the proper JSON object we need.
	 */
	if ( ! writeop(SUB, acctsock, COMM_ACCT, ACCT_SIGN)) {
		free(nonce);
		return(0);
	} else if ( ! writestr(SUB, acctsock, COMM_PAY, req)) {
		free(nonce);
		return(0);
	} else if ( ! writestr(SUB, acctsock, COMM_NONCE, nonce)) {
		free(nonce);
		return(0);
	}
	free(nonce);
	if (NULL == (reqsn = readstr(SUB, acctsock, COMM_REQ)))
		return(0);

	dodbg("%s: signing request", addr);

	json_reset(json);
	curl_easy_reset(c);
	curl_easy_setopt(c, CURLOPT_URL, addr);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	/*curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);*/
	curl_easy_setopt(c, CURLOPT_POSTFIELDS, reqsn);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, jsonbody);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, json);

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
 * Here we communicate with the letsencrypt server.
 * For this, we'll need the certificate we want to upload and our
 * account key information.
 */
int
netproc(int certsock, int acctsock, 
	int chngsock, const char *domain, int newacct)
{
	pid_t		 pid;
	int		 st, rc, cc;
	size_t		 retry;
	char		*home, *cert, *req, *reqsn, *thumb;
	CURL		*c;
	struct json	 json;
	struct capaths	 paths;
	struct challenge chng;
	long		 http, op;

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
		close(certsock);
		close(acctsock);
		if (-1 == waitpid(pid, &st, 0))
			doerr("waitpid");
		netcleanup(home);
		return(WIFEXITED(st) && 
		       EXIT_SUCCESS == WEXITSTATUS(st));
	}

#ifdef __APPLE__
	/*
	 * Apple's sandbox doesn't help much here.
	 * Ideally, we'd just use pure computation--but again (as in the
	 * keyproc() case), we wouldn't be able to chroot.
	 * So just mark that we can't scribble in our chroot.
	 */
	if (-1 == sandbox_init(kSBXProfileNoWrite, 
 	    SANDBOX_NAMED, NULL))
		doerr("sandbox_init");
#endif

	/*
	 * We're doing the work.
	 * Begin by stuffing ourselves into the jail.
	 */
#ifndef __APPLE__
	/*
	 * This doesn't work on Apple: it uses a socket for DNS
	 * resolution that lives in /var/run and not resolv.conf.
	 */
	if (-1 == chroot(home))
		doerr("%s: chroot", home);
	else if (-1 == chdir("/"))
		doerr("/: chdir");
#endif

	dodbg("%s: started in jail", home);
	free(home);
	home = NULL;

	/* Zero all the things. */
	memset(&json, 0, sizeof(struct json));
	memset(&paths, 0, sizeof(struct capaths));
	memset(&chng, 0, sizeof(struct challenge));
	reqsn = req = cert = thumb = NULL;
	c = NULL;

	if (NULL == (c = curl_easy_init())) {
		dowarn("curl_easy_init");
		goto out;
	} else if ( ! json_init(&json)) {
		dowarnx("json_init");
		goto out;
	}

	/*
	 * Grab the directory structure from the CA.
	 * This initialises our contact with the CA, too.
	 */
	dodbg("%s: requesting directories", URL_CA);

	if ( ! nreq(c, URL_CA, &http, &json)) {
		dowarnx("%s: bad communication", URL_CA);
		goto out;
	} else if (200 != http && 201 != http) {
		dowarnx("%s: bad communication", URL_CA);
		goto out;
	} else if (NULL == json.obj) {
		dowarnx("%s: bad JSON", URL_CA);
		goto out;
	} else if ( ! capaths_parse(&json, &paths)) {
		dowarnx("%s: bad CA paths", URL_CA);
		goto out;
	}

	/*
	 * If we're a new account, register the account with the ACME
	 * server.
	 * This will return an HTTP 201 on success, although we catch an
	 * error 200 as well just in case.
	 */
	if (newacct) {
		cc = asprintf(&req, "{\"resource\": \"new-reg\", "
			"\"agreement\": \"%s\"}", URL_LICENSE);
		if (-1 == cc) {
			dowarn("asprintf");
			goto out;
		} 
		/* Send the request... */
		if ( ! sreq(acctsock, c, paths.newreg, req, &http, &json)) {
			dowarnx("%s: bad communication", paths.newreg);
			goto out;
		} else if (200 != http && 201 != http) {
			dowarnx("%s: bad HTTP: %ld", 
				paths.newreg, http);
			goto out;
		}
	}

	/*
	 * Set up to ask the acme server to authorise a domain.
	 * First, we prepare the request itself.
	 * Then we ask acctproc to sign it for us.
	 * Then we send that to the request server and receive from it
	 * the challenge response.
	 */
	cc = asprintf(&req, 
    		"{\"resource\": \"new-authz\", "
		"\"identifier\": "
		"{\"type\": \"dns\", \"value\": \"%s\"}}",
		domain);
	if (-1 == cc) {
		dowarn("asprintf");
		goto out;
	} 
	
	if ( ! sreq(acctsock, c, paths.newauthz, req, &http, &json)) {
		dowarnx("%s: bad communication", paths.newauthz);
		goto out;
	} else if (200 != http && 201 != http) {
		dowarnx("%s: bad HTTP: %ld", paths.newauthz, http);
		goto out;
	} else if ( ! challenge_parse(&json, &chng)) {
		dowarnx("%s: bad challenge", paths.newauthz);
		goto out;
	}
	free(req);
	req = NULL;

	/*
	 * We now have our challenge.
	 * We need to ask the acctproc for the thumbprint.
	 * We'll combine this to the challenge to create our response,
	 * which will be orchestrated by the chngproc.
	 */
	if ( ! writeop(SUB, acctsock, COMM_ACCT, ACCT_THUMBPRINT))
		goto out;
	else if (NULL == (thumb = readstr(SUB, acctsock, COMM_THUMB)))
		goto out;

	dodbg("thumbprint: %s", thumb);

	/*
	 * We now have our thumbprint and the challenge token.
	 * Write it to the chngproc.
	 */
	if ( ! writeop(SUB, chngsock, COMM_CHNG, 1))
		goto out;
	else if ( ! writestr(SUB, chngsock, COMM_THUMB, thumb))
		goto out;
	else if ( ! writestr(SUB, chngsock, COMM_TOK, chng.token))
		goto out;

	/* Read our acknowledgement that the challenge exists. */

	if (0 == (op = readop(SUB, chngsock, COMM_CHNG_ACK)))
		goto out;
	else if (LONG_MAX == op)
		goto out;

	/* 
	 * Now that our challenge is in place (and the webserver, I
	 * suppose, configured to handle it), we let the ACME server
	 * know that we have the challenge ready.
	 */
	cc = asprintf(&req, "{\"resource\": \"challenge\", "
		"\"keyAuthorization\": \"%s.%s\"}",
		chng.token, thumb);
	if (-1 == cc) {
		dowarn("asprintf");
		goto out;
	}

	if ( ! sreq(acctsock, c, chng.uri, req, &http, &json)) {
		dowarnx("%s: bad communication", chng.uri);
		goto out;
	} else if (200 != http && 201 != http && 202 != http) {
		dowarnx("%s: bad HTTP: %ld", chng.uri, http);
		goto out;
	} else if (-1 == (cc = response_parse(&json))) {
		dowarnx("%s: bad response", chng.uri);
		goto out;
	}

	/*
	 * We now wait on the ACME server.
	 * Try it once every ten seconds.
	 */
	for (retry = 0; 1 == cc && retry < 10; retry++) {
		if ( ! nreq(c, chng.uri, &http, &json)) {
			dowarnx("%s: bad communication", chng.uri);
			goto out;
		} else if (200 != http && 201 != http && 202 != http) {
			dowarnx("%s: bad HTTP: %ld", chng.uri, http);
			goto out;
		} else if (-1 == (cc = response_parse(&json))) {
			dowarnx("%s: bad response", chng.uri);
			goto out;
		} else if (1 == cc) {
			dodbg("%s: sleeping til retry", chng.uri);
			sleep(5);
		}
	}

	/* Write our acknowledgement that the challenge is over. */

	if ( ! writeop(SUB, chngsock, COMM_CHNG_FIN, 1))
		goto out;

	if (10 == retry) {
		dowarnx("%s: timed out (%zu tries)", chng.uri, retry);
		goto out;
	}

	/*
	 * Now wait until we've received the certificate we want to send
	 * to the letsencrypt server.
	 * This will come from our key process.
	 */
	if (NULL == (cert = readstream(SUB, certsock, COMM_CERT)))
		goto out;

	close(certsock);
	certsock = -1;

	dodbg("certificate: %zu bytes", strlen(cert));

	rc = EXIT_SUCCESS;
out:
	if (-1 != certsock)
		close(certsock);
	if (-1 != acctsock)
		close(acctsock);
	if (-1 != chngsock)
		close(chngsock);
	free(cert);
	free(req);
	free(reqsn);
	free(thumb);
	if (NULL != c)
		curl_easy_cleanup(c);
	curl_global_cleanup();
	json_free(&json);
	challenge_free(&chng);
	capaths_free(&paths);
	if (EXIT_SUCCESS == rc)
		dodbg("finished");
	else
		dodbg("finished (error)");
	exit(rc);
	/* NOTREACHED */
}
