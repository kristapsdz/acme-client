#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

void
dovdbg(const char *sub, const char *fmt, va_list ap)
{
	extern int	 verbose;

	if ( ! verbose)
		return;
	printf("%s(%u): DEBUG: ", sub, getpid());
	vprintf(fmt, ap);
	putchar('\n');
}

void
dovwarnx(const char *sub, const char *fmt, va_list ap)
{

	fprintf(stderr, "%s(%u): WARN: ", sub, getpid());
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

void
doverr(const char *sub, const char *fmt, va_list ap)
{
	int		 er = errno;

	fprintf(stderr, "%s(%u): ERROR: ", sub, getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(er));
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}

void
dovwarn(const char *sub, const char *fmt, va_list ap)
{
	int		 er = errno;

	fprintf(stderr, "%s(%u): WARN: ", sub, getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(er));
}

void
doxerr(const char *sub, const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverr(sub, fmt, ap);
	va_end(ap);
}

void
doxwarnx(const char *sub, const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarnx(sub, fmt, ap);
	va_end(ap);
}

void
doxwarn(const char *sub, const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn(sub, fmt, ap);
	va_end(ap);
}

void
doxdbg(const char *sub, const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg(sub, fmt, ap);
	va_end(ap);
}
