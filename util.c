#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

enum acctop
readop(const char *sub, int fd)
{
	ssize_t	 	 ssz;
	enum acctop	 op;

	ssz = read(fd, &op, sizeof(enum acctop));
	if (ssz < 0) {
		doxwarn(sub, "read: acctop");
		return(ACCT__MAX);
	} else if (ssz && ssz != sizeof(enum acctop)) {
		doxwarnx(sub, "short read: acctop");
		return(ACCT__MAX);
	} else if (0 == ssz)
		return(ACCT_STOP);

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

int
writeop(const char *sub, int fd, enum acctop op)
{
	ssize_t	 ssz;

	if ((ssz = write(fd, &op, sizeof(enum acctop))) < 0) 
		doxwarn(sub, "write: acctop");
	else if ((size_t)ssz != sizeof(enum acctop))
		doxwarnx(sub, "short write: acctop");
	else
		return(1);

	return(0);
}

int
writestring(const char *sub, int fd, const char *name, const char *v)
{
	size_t	 sz;
	ssize_t	 ssz;

	sz = strlen(v);

	if ((ssz = write(fd, &sz, sizeof(size_t))) < 0) 
		doxwarn(sub, "write: %s length", name);
	else if ((size_t)ssz != sizeof(size_t))
		doxwarnx(sub, "short write: %s length", name);
	else if ((ssz = write(fd, v, sz)) < 0)
		doxwarn(sub, "write: %s", name);
	else if ((size_t)ssz != sz)
		doxwarnx(sub, "short write: %s", name);
	else
		return(1);

	return(0);
}
