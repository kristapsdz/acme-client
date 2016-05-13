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
	fprintf(stderr, "%s(%u): DEBUG: ", sub, getpid());
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
