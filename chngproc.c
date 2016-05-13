#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
# include <sandbox.h>
#endif

#include "extern.h"

#define SUB "challengeproc"

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

int
chngproc(int netsock, const char *root)
{
	int		 rc;
	long		 op;
	char		*tok, *thumb, *file;
	FILE		*f;

	rc = 0;
	file = thumb = tok = NULL;
	f = NULL;

#ifdef __APPLE__
	/*
	 * We would use "pure computation", which is correct, but then
	 * we wouldn't be able to chroot().
	 * This call also can't happen after the chroot(), so we're
	 * stuck with a weaker sandbox.
	 */
	if (-1 == sandbox_init(kSBXProfileNoNetwork, 
 	    SANDBOX_NAMED, NULL)) {
		dowarn("sandbox_init");
		goto out;
	}
#endif
	/*
	 * Jails: start with file-system.
	 */
	if (-1 == chroot(root)) {
		dowarn("%s: chroot", root);
		goto out;
	} else if (-1 == chdir("/")) {
		dowarn("/: chdir");
		goto out;
	}

#ifdef __OpenBSD__
	/* 
	 * On OpenBSD, we won't use anything more than what we've
	 * inherited from our open descriptors.
	 */
	if (-1 == pledge("stdio cpath wpath", NULL)) {
		dowarn("pledge");
		goto out;
	}
#endif

	/*
	 * The root URI that the ACME server will access is
	 * .acme-challenges, so make sure we already have that.
	 */
	if (-1 == mkdir(".acme-challenges", 0755) && EEXIST != errno) {
		dowarn(".acme-challenges");
		goto out;
	}

	if (0 == (op = readop(SUB, netsock, "chngop"))) 
		goto out;
	else if (LONG_MAX == op)
		goto out;

	if (NULL == (thumb = readstring(SUB, netsock, "thumb"))) {
		dowarnx("readstring: thumb");
		goto out;
	} else if (NULL == (tok = readstring(SUB, netsock, "token"))) {
		dowarnx("readstring: token");
		goto out;
	}

	if (-1 == asprintf(&file, ".acme-challenges/%s", tok)) {
		tok = NULL;
		dowarn("asprintf");
		goto out;
	} else if (NULL == (f = fopen(file, "w"))) {
		dowarn("%s", file);
		goto out;
	} else if (-1 == fprintf(f, "%s.%s", tok, thumb)) {
		dowarn("%s", file);
		goto out;
	} else if (-1 == fclose(f)) {
		dowarn("%s", file);
		goto out;
	}
	f = NULL;

	if ( ! writeop(SUB, netsock, "chngreq", 1))
		goto out;

	rc = 1;
	dodbg("finished");
out:
	if (NULL != f)
		fclose(f);
	free(file);
	free(thumb);
	free(tok);
	close(netsock);
	return(rc);
}
