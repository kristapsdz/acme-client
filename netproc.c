#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif
#include <stdarg.h>
#include <stdio.h>
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

#define	SUB "netproc"

struct	json {
	struct json_tokener	*tok;
	struct json_object	*obj;
};

struct	capaths {
	char		*newauthz;
	char		*newcert;
	char		*newreg;
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

static char *
readstream(int certsock, const char *name)
{
	ssize_t		 ssz;
	size_t		 sz;
	char		 buf[BUFSIZ];
	void		*pp;
	char		*p;

	p = NULL;
	sz = 0;
	while ((ssz = read(certsock, buf, sizeof(buf))) > 0) {
		if (NULL == (pp = realloc(p, sz + ssz + 1))) {
			dowarn("realloc");
			free(p);
			return(NULL);
		}
		p = pp;
		memcpy(p + sz, buf, ssz);
		sz += ssz;
		p[sz] = '\0';
	}

	if (ssz < 0) {
		dowarn("read: %s", name);
		free(p);
		return(NULL);
	} else if (0 == sz) {
		dowarnx("empty read: %s", name);
		return(NULL);
	}

	return(p);
}

/*
 * Clean up the netproc() environment as created with netprepare().
 * Allows for errors and frees "dir" on exit.
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
 * Prepare netproc()'s jail environment.
 * We only need /etc/resolv.conf from the host.
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

	/*
	 * Create our new home.
	 * This will be in a temporary directory and will consist of
	 * a copied /etc/resolv.conf.
	 */
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

static size_t 
netbody(void *ptr, size_t sz, size_t nm, void *arg)
{
	struct json	*json = arg;
	enum json_tokener_error er;

	if (NULL != json->obj) {
		dowarnx("data after complete JSON");
		return(0);
	}

	json->obj = json_tokener_parse_ex(json->tok, ptr, nm * sz);
	er = json_tokener_get_error(json->tok);
	if (er == json_tokener_success || 
	    er == json_tokener_continue)
		return(sz * nm);

	dowarnx("json_tokener_parse_ex: %s", 
		json_tokener_error_desc(er));
	return(0);
}

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

static char *
json_getstring(json_object *parent, const char *name)
{
	json_object	*p;
	char		*cp;

	/* Verify that the email is sane. */
	if ( ! json_object_object_get_ex(parent, name, &p)) {
		dowarnx("no JSON object: %s", name);
		return(NULL);
	} else if (json_type_string != json_object_get_type(p)) {
		dowarnx("bad JSON object type: %s", name);
		return(NULL);
	} else if (NULL == (cp = strdup(json_object_get_string(p)))) {
		dowarn("strdup");
		return(NULL);
	}

	return(cp);
}

static int
capaths_parse(struct json *json, struct capaths *paths)
{

	paths->newauthz = json_getstring(json->obj, "new-authz");
	paths->newcert = json_getstring(json->obj, "new-cert");
	paths->newreg = json_getstring(json->obj, "new-reg");
	paths->revokecert = json_getstring(json->obj, "revoke-cert");

	return(NULL != paths->newauthz &&
	       NULL != paths->newcert &&
	       NULL != paths->newreg &&
	       NULL != paths->revokecert);
}

static void
capaths_free(struct capaths *p)
{

	free(p->newauthz);
	free(p->newcert);
	free(p->newreg);
	free(p->revokecert);
}

/*
 * Here we communicate with the letsencrypt server.
 * For this, we'll need the certificate we want to upload and our
 * account key information.
 */
int
netproc(int certsock, int acctsock, const char *domain)
{
	pid_t		 pid;
	int		 st, rc, cc;
	char		*home, *cert, *nonce, *req, *reqsn;
	CURL		*c;
	CURLcode	 res;
	struct json	 json;
	struct capaths	 paths;

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
	 * This doesn't work on Apple: it uses a socket for DNS
	 * resolution that lives in /var/run and not resolv.conf.
	 */
#ifndef __APPLE__
	if (-1 == chroot(home))
		doerr("%s: chroot", home);
	else if (-1 == chdir("/"))
		doerr("/: chdir");
#endif

	dodbg("started in jail: %s", home);
	free(home);
	home = NULL;

	/* Zero all the things. */
	memset(&json, 0, sizeof(struct json));
	memset(&paths, 0, sizeof(struct capaths));
	reqsn = req = nonce = cert = NULL;
	c = NULL;

	if (NULL == (c = curl_easy_init())) {
		doerr("curl_easy_init");
		goto out;
	} else if (NULL == (json.tok = json_tokener_new())) {
		doerr("json_tokener_new");
		goto out;
	}

	/*
	 * Grab our nonce.
	 * Do this before getting any of our account information.
	 * We specifically do only a HEAD request because all we want to
	 * do is grab a single field.
	 * We'll also grab the JSON content of the message, which has a
	 * directory of all the bits that we want.
	 */
	dodbg("connecting: %s", URL_CA);

	curl_easy_setopt(c, CURLOPT_URL, URL_CA);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, netbody);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, &json);
	curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, netheaders);
	curl_easy_setopt(c, CURLOPT_HEADERDATA, &nonce);
	if (CURLE_OK != (res = curl_easy_perform(c))) {
	      dowarnx("%s: %s", URL_CA, curl_easy_strerror(res));
	      goto out;
	}

	if (NULL == nonce) {
		dowarnx("replay nonce not found in headers");
		goto out;
	} else if (NULL == json.obj) {
		dowarnx("proper JSON object not found");
		goto out;
	} else if ( ! capaths_parse(&json, &paths)) {
		dowarnx("could not parse CA paths");
		goto out;
	}

	dodbg("replay nonce: %s", nonce);

	/*
	 * Set up to ask the acme server to authorise a domain.
	 * First, we prepare the request itself.
	 * Then we ask acctproc to sign it for us.
	 * Then we send that to the request server.
	 */
	cc = asprintf(&req, 
    		"{\"resource\": \"new-authz\", "
		"\"identifier\": {\"type\": \"dns\", \"value\": \"%s\"}}",
		domain);
	if (-1 == cc) {
		dowarn("asprintf");
		goto out;
	}

	if ( ! writeop(SUB, acctsock, ACCT_SIGN)) {
		dowarnx("writeop");
		goto out;
	} else if ( ! writestring(SUB, acctsock, "payload", req)) {
		dowarnx("writestring: payload");
		goto out;
	} else if ( ! writestring(SUB, acctsock, "nonce", nonce)) {
		dowarnx("writestring: nonce");
		goto out;
	}

	/* Now wait for the acctproc to write back our digest. */

	dodbg("reading response...");
	if (NULL == (reqsn = readstring(SUB, acctsock, "req"))) {
		dowarnx("readstring: req");
		goto out;
	}
	dodbg("read signed digest: %zu bytes", strlen(reqsn));

	/*
	 * Now wait until we've received the certificate we want to send
	 * to the letsencrypt server.
	 * This will come from our key process.
	 */
	if (NULL == (cert = readstream(certsock, "certificate"))) {
		dowarnx("readstream: keyproc");
		goto out;
	}
	close(certsock);
	certsock = -1;
	dodbg("read certificate: %zu bytes", strlen(cert));

	rc = EXIT_SUCCESS;
out:
	if (-1 != certsock)
		close(certsock);
	if (-1 != acctsock)
		close(acctsock);
	free(cert);
	free(req);
	free(nonce);
	free(reqsn);
	if (NULL != c)
		curl_easy_cleanup(c);
	curl_global_cleanup();
	if (NULL != json.tok)
		json_tokener_free(json.tok);
	if (NULL != json.obj)
		json_object_put(json.obj);
	capaths_free(&paths);
	if (EXIT_SUCCESS == rc)
		dodbg("finished");
	else
		dodbg("finished (error)");
	exit(rc);
	/* NOTREACHED */
}
