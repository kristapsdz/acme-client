#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static	volatile sig_atomic_t sig;

static void
sigpipe(int code)
{

	(void)code;
	sig = 1;
}

/*
 * This will read a long-sized operation.
 * Operations are usually enums, so this should be alright.
 * We return 0 on EOF and LONG_MAX on failure.
 */
long
readop(const char *sub, int fd, const char *name)
{
	ssize_t	 	 ssz;
	long		 op;

	ssz = read(fd, &op, sizeof(long));
	if (ssz < 0) {
		doxwarn(sub, "read: %s", name);
		return(LONG_MAX);
	} else if (ssz && ssz != sizeof(long)) {
		doxwarnx(sub, "short read: %s", name);
		return(LONG_MAX);
	} else if (0 == ssz)
		return(0);

	return(op);
}

char *
readstring(const char *sub, int fd, const char *name)
{
	ssize_t		 ssz;
	size_t		 sz;
	char		*p;

	p = NULL;

	if ((ssz = read(fd, &sz, sizeof(size_t))) < 0)
		doxwarn(sub, "read: %s length", name);
	else if ((size_t)ssz != sizeof(size_t))
		doxwarnx(sub, "short read: %s length", name);
	else if (NULL == (p = calloc(1, sz + 1)))
		doxwarn(sub, "malloc");
	else if ((ssz = read(fd, p, sz)) < 0)
		doxwarn(sub, "read: %s", name);
	else if ((size_t)ssz != sz)
		doxwarnx(sub, "short read: %s", name);
	else
		return(p);

	free(p);
	return(NULL);
}

/*
 * Wring a long-value to a communication pipe.
 * Returns zero if the write failed or the pipe is not open, otherwise
 * return non-zero.
 */
int
writeop(const char *sub, int fd, const char *name, long op)
{
	ssize_t	 ssz;
	sig_t	 sig;
	int	 rc;

	rc = 0;
	/* Catch a closed pipe. */
	sig = signal(SIGPIPE, sigpipe);

	if ((ssz = write(fd, &op, sizeof(long))) < 0) 
		doxwarn(sub, "write: %s", name);
	else if ((size_t)ssz != sizeof(long))
		doxwarnx(sub, "short write: %s", name);
	else
		rc = 1;

	/* Reinstate signal handler. */
	signal(SIGPIPE, sig);
	sig = 0;
	return(rc);
}

int
writestring(const char *sub, int fd, const char *name, const char *v)
{
	size_t	 sz;
	ssize_t	 ssz;
	int	 rc;
	sig_t	 sig;

	sz = strlen(v);
	rc = 0;
	/* Catch a closed pipe. */
	sig = signal(SIGPIPE, sigpipe);

	if ((ssz = write(fd, &sz, sizeof(size_t))) < 0) 
		doxwarn(sub, "write: %s length", name);
	else if ((size_t)ssz != sizeof(size_t))
		doxwarnx(sub, "short write: %s length", name);
	else if ((ssz = write(fd, v, sz)) < 0)
		doxwarn(sub, "write: %s", name);
	else if ((size_t)ssz != sz)
		doxwarnx(sub, "short write: %s", name);
	else
		rc = 1;

	/* Reinstate signal handler. */
	signal(SIGPIPE, sig);
	sig = 0;
	return(rc);
}

char *
readstream(const char *sub, int fd, const char *name)
{
	ssize_t		 ssz;
	size_t		 sz;
	char		 buf[BUFSIZ];
	void		*pp;
	char		*p;

	p = NULL;
	sz = 0;
	while ((ssz = read(fd, buf, sizeof(buf))) > 0) {
		if (NULL == (pp = realloc(p, sz + ssz + 1))) {
			doxwarn(sub, "realloc");
			free(p);
			return(NULL);
		}
		p = pp;
		memcpy(p + sz, buf, ssz);
		sz += ssz;
		p[sz] = '\0';
	}

	if (ssz < 0) {
		doxwarn(sub, "read: %s", name);
		free(p);
		return(NULL);
	} else if (0 == sz) {
		doxwarnx(sub, "empty read: %s", name);
		return(NULL);
	}

	return(p);
}
