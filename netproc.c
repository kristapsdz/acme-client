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
dodbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg("netproc", fmt, ap);
	va_end(ap);
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
		warn("asprintf");
		tmp = NULL;
	} else if (-1 == remove(tmp) && ENOENT != errno) 
		warn("%s", tmp);

	free(tmp);

	/* Now the etc directory containing the resolv. */
	if (-1 == asprintf(&tmp, "%s/etc", dir)) {
		warn("asprintf");
		tmp = NULL;
	} else if (-1 == remove(tmp) && ENOENT != errno)
		warn("%s", tmp);

	free(tmp);

	/* Finally, the jail itself. */
	if (-1 == remove(dir) && ENOENT != errno)
		warn("%s", dir);

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
		warn("strdup");
		return(NULL);
	} else if (NULL == mkdtemp(dir)) {
		warn("mkdtemp");
		return(NULL);
	}

	/* Create the /etc directory. */
	if (-1 == asprintf(&tmp, "%s/etc", dir)) {
		warn("asprintf");
		goto err;
	} else if (-1 == mkdir(tmp, 0755)) {
		warn("%s", tmp);
		goto err;
	}

	free(tmp);
	tmp = NULL;

	/* Open /etc/resolv.conf. */
	fd2 = open(PATH_RESOLV, O_RDONLY, 0);
	if (-1 == fd2) {
		warn(PATH_RESOLV);
		goto err;
	}

	/* Create the new /etc/resolv.conf file. */
	oflags = O_CREAT|O_TRUNC|O_WRONLY|O_APPEND;
	if (-1 == asprintf(&tmp, "%s" PATH_RESOLV, dir)) {
		warn("asprintf");
		goto err;
	} else if (-1 == (fd = open(tmp, oflags, 0644))) {
		warn("%s", tmp);
		goto err;
	}

	/* Copy via a static buffer. */
	while ((ssz = read(fd2, dbuf, sizeof(dbuf))) > 0) {
		if ((ssz2 = write(fd, dbuf, ssz)) < 0) {
			warn("%s", tmp);
			goto err;
		} else if (ssz2 != ssz) {
			warnx("%s: short write", tmp);
			goto err;
		}
	}

	if (ssz < 0) {
		warn(PATH_RESOLV);
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
		warn("realloc");
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
	int		 st, rc;
	char		*cert, *token, *string, *nonce;
	char		 buf[BUFSIZ];
	ssize_t		 ssz;
	size_t		 sz;
	CURL		*c;
	CURLcode	 res;
	struct buf	 hbuf;
	void		*pp;

	dodbg("starting up");

	rc = EXIT_FAILURE;

	/* Prepare our file-system jail. */
	if (NULL == (home = netprepare()))
		return(0);

	dodbg("prepared jail: %s", home);

	/*
	 * Begin by forking.
	 * We need to do this because somebody needs to clean up the
	 * jail, and we can't do that if we're already in it.
	 */
	if (-1 == (pid = fork())) 
		err(EXIT_FAILURE, "fork");

	if (pid > 0) {
		close(certsock);
		close(acctsock);
		if (-1 == waitpid(pid, &st, 0))
			err(EXIT_FAILURE, "waitpid");
		netcleanup(home);
		return(WIFEXITED(st) && 
		       EXIT_SUCCESS == WEXITSTATUS(st));
	}

	dodbg("started child");

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
		err(EXIT_FAILURE, "%s: chroot", home);
	else if (-1 == chdir("/"))
		err(EXIT_FAILURE, "/: chdir");
#endif

	dodbg("sandboxed in jail: %s", home);
	free(home);
	mod = exp = nonce = cert = NULL;
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
	      warnx("%s: %s", URL_CA, curl_easy_strerror(res));
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
			warn("strdup");
			goto out;
		}
		break;
	}
	if (NULL == nonce) {
		warnx("replay nonce not found in headers");
		goto out;
	}
	dodbg("replay nonce: %s", nonce);

	/*
	 * Now wait until we've received the certificate we want to send
	 * to the letsencrypt server.
	 * This will come from our key process.
	 */
	sz = 0;
	while ((ssz = read(certsock, buf, sizeof(buf))) > 0) {
		pp = realloc(cert, sz + ssz + 1);
		if (NULL == pp) {
			warn("realloc");
			goto out;
		}
		cert = pp;
		memcpy(cert + sz, buf, ssz);
		sz += ssz;
		cert[sz] = '\0';
	}
	close(certsock);
	certsock = -1;
	if (ssz < 0) {
		warn("read: certificate socket");
		goto out;
	}
	dodbg("read %zu byte certificate", sz);

	/*
	 * Now we've acquired our certificate.
	 * Move on to acquiring our account key numbers.
	 */
	if ((ssz = read(acctsock, &sz, sizeof(size_t))) < 0) {
		warn("read: account socket");
		goto out;
	} else if ((size_t)ssz != sizeof(size_t)) {
		warnx("short read: account socket");
		goto out;
	} else if (NULL == (mod = calloc(1, sz + 1))) {
		warn("malloc");
		goto out;
	} else if ((ssz = read(acctsock, mod, sz)) < 0) {
		warn("read: account socket");
		goto out;
	} else if ((size_t)ssz != sz) {
		warnx("short read: account socket");
		goto out;
	}
	dodbg("read modulus: %zu bytes", sz);

	if ((ssz = read(acctsock, &sz, sizeof(size_t))) < 0) {
		warn("read: account socket");
		goto out;
	} else if ((size_t)ssz != sizeof(size_t)) {
		warnx("short read: account socket");
		goto out;
	} else if (NULL == (exp = calloc(1, sz + 1))) {
		warn("malloc");
		goto out;
	} else if ((ssz = read(acctsock, exp, sz)) < 0) {
		warn("read: account socket");
		goto out;
	} else if ((size_t)ssz != sz) {
		warnx("short read: account socket");
		goto out;
	}
	dodbg("read exponent: %zu bytes", sz);
	close(acctsock);
	acctsock = -1;

	rc = EXIT_SUCCESS;
out:
	if (-1 != certsock)
		close(certsock);
	free(hbuf.buf);
	free(cert);
	free(nonce);
	free(mod);
	free(exp);
	curl_easy_cleanup(c);
	curl_global_cleanup();
	exit(rc);
	/* NOTREACHED */
}
