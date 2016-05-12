#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

void
dovdbg(const char *name, const char *fmt, va_list ap)
{
	extern int	 verbose;

	if ( ! verbose)
		return;
	printf("%s(%u): DEBUG: ", name, getpid());
	vprintf(fmt, ap);
	putchar('\n');
}

void
dovwarnx(const char *name, const char *fmt, va_list ap)
{

	fprintf(stderr, "%s(%u): WARN: ", name, getpid());
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

void
doverr(const char *name, const char *fmt, va_list ap)
{
	int		 er = errno;

	fprintf(stderr, "%s(%u): ERROR: ", name, getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(er));
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}

void
dovwarn(const char *name, const char *fmt, va_list ap)
{
	int		 er = errno;

	fprintf(stderr, "%s(%u): WARN: ", name, getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(er));
}

