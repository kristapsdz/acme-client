#include <sys/stat.h>

#include <err.h>
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

#include "extern.h"

#define	PATH_RESOLV "/etc/resolv.conf"
#if 0
# define URL_CA "https://acme-v01.api.letsencrypt.org/directory"
#else
# define URL_CA "https://acme-staging.api.letsencrypt.org/directory"
#endif

struct	buf {
	char	*buf;
	size_t	 sz;
};

static void
doerr(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverr("netproc", fmt, ap);
	va_end(ap);
}

static void
dowarnx(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarnx("netproc", fmt, ap);
	va_end(ap);
}

static void
dowarn(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn("netproc", fmt, ap);
	va_end(ap);
}

static void
dodbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg("netproc", fmt, ap);
	va_end(ap);
}

static char *
readstring(int fd, const char *name)
{
	ssize_t		 ssz;
	size_t		 sz;
	char		*p;

	p = NULL;

	if ((ssz = read(fd, &sz, sizeof(size_t))) < 0)
		warn("read: %s length", name);
	else if ((size_t)ssz != sizeof(size_t))
		dowarnx("short read: %s length", name);
	else if (NULL == (p = calloc(1, sz + 1)))
		dowarn("malloc");
	else if ((ssz = read(fd, p, sz)) < 0)
		dowarn("read: %s", name);
	else if ((size_t)ssz != sz)
		dowarnx("short read: %s", name);
	else
		return(p);

	free(p);
	return(NULL);
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
netheaders(void *ptr, size_t sz, size_t nm, void *arg)
{
	struct buf	*buf = arg;
	size_t		 nsz;

	nsz = sz * nm;
	buf->buf = realloc(buf->buf, buf->sz + nsz + 1);
	if (NULL == buf->buf) {
		dowarn("realloc");
		return(0);
	}
	memcpy(buf->buf + buf->sz, ptr, nsz);
	buf->sz += nsz;
	buf->buf[buf->sz] = '\0';
	return(nsz);
}

/*
 * Here we communicate with the letsencrypt server.
 * For this, we'll need the certificate we want to upload and our
 * account key information.
 */
int
netproc(int certsock, int acctsock)
{
	char		*home, *mod, *exp;
	pid_t		 pid;
	int		 st, rc, cc;
	char		*cert, *token, *string, *nonce, *thumb;
	size_t		 sz;
	CURL		*c;
	CURLcode	 res;
	struct buf	 hbuf;

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
		errx(EXIT_FAILURE, "sandbox_init");
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

	mod = exp = nonce = cert = thumb = NULL;
	memset(&hbuf, 0, sizeof(hbuf));

	if (NULL == (c = curl_easy_init())) 
		errx(EXIT_FAILURE, "curl_easy_init");

	/*
	 * Grab our nonce.
	 * Do this before getting any of our account information.
	 * We specifically do only a HEAD request because all we want to
	 * do is grab a single field.
	 */
	dodbg("connecting: %s", URL_CA);
	curl_easy_setopt(c, CURLOPT_URL, URL_CA);
	curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, netheaders);
	curl_easy_setopt(c, CURLOPT_HEADERDATA, &hbuf);
	if (CURLE_OK != (res = curl_easy_perform(c))) {
	      dowarnx("%s: %s", URL_CA, curl_easy_strerror(res));
	      goto out;
	}

	/* Parse the nonce out of the HTTP headers. */
	string = hbuf.buf;
	while (NULL != (token = strsep(&string, "\r\n"))) {
		if (0 == (sz = strlen(token)))
			continue;
		if (strncmp(token, "Replay-Nonce: ", 14))
			continue;
		if (NULL == (nonce = strdup(token + 14))) {
			dowarn("strdup");
			goto out;
		}
		break;
	}
	if (NULL == nonce) {
		dowarnx("replay nonce not found in headers");
		goto out;
	}
	dodbg("replay nonce: %s", nonce);

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
	dodbg("read certificate: %zu bytes", sz);

	/*
	 * Now we've acquired our certificate.
	 * Move on to acquiring our account key numbers.
	 */
	if (NULL == (mod = readstring(acctsock, "modulus"))) {
		dowarnx("readstring: acctsock");
		goto out;
	} else if (NULL == (exp = readstring(acctsock, "exponent"))) {
		dowarnx("readstring: account socket");
		goto out;
	}
	close(acctsock);
	acctsock = -1;

	dodbg("read modulus: %zu bytes", strlen(mod));
	dodbg("read exponent: %zu bytes", strlen(exp));

	cc = asprintf(&thumb, "{ "
		"\"e\": \"%s\", "
		"\"kty\": \"RSA\", "
		"\"n\": \"%s\" }", exp, mod);
	if (-1 == cc) {
		dowarn("asprintf");
		thumb = NULL;
		goto out;
	}
	printf("%s\n", thumb);

	rc = EXIT_SUCCESS;
out:
	if (-1 != certsock)
		close(certsock);
	if (-1 != acctsock)
		close(acctsock);
	free(hbuf.buf);
	free(cert);
	free(nonce);
	free(mod);
	free(exp);
	free(thumb);
	curl_easy_cleanup(c);
	curl_global_cleanup();
	exit(rc);
	/* NOTREACHED */
}
