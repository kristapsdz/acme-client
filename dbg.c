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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static	const char *const comps[COMP__MAX + 1] = {
	"netproc", /* COMP_NET */
	"keyproc", /* COMP_KEY */
	"certproc", /* COMP_CERT */
	"acctproc", /* COMP_ACCOUNT */
	"challengeproc", /* COMP_CHALLENGE */
	"fileproc", /* COMP_FILE */
	"dnsproc", /* COMP_DNS */
	"revokeproc", /* COMP_REVOKE */
	"master", /* COMP__MAX */
};

static void
dovddbg(const char *fmt, va_list ap)
{
	extern int	 verbose;
	extern enum comp proccomp;

	if (verbose < 2)
		return;
	fprintf(stderr, "%s(%u): TRACE: ", comps[proccomp], getpid());
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

static void
dovdbg(const char *fmt, va_list ap)
{
	extern int	 verbose;
	extern enum comp proccomp;

	if ( ! verbose)
		return;
	fprintf(stderr, "%s(%u): DEBUG: ", comps[proccomp], getpid());
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

static void
dovwarnx(const char *fmt, va_list ap)
{
	extern enum comp proccomp;

	fprintf(stderr, "%s(%u): WARN: ", comps[proccomp], getpid());
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

static void
doverrx(const char *fmt, va_list ap)
{
	extern enum comp proccomp;

	fprintf(stderr, "%s(%u): ERROR: ", comps[proccomp], getpid());
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}


static void
doverr(const char *fmt, va_list ap)
{
	int		 er = errno;
	extern enum comp proccomp;

	fprintf(stderr, "%s(%u): ERROR: ", comps[proccomp], getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(er));
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}

static void
dovwarn(const char *fmt, va_list ap)
{
	int		 er = errno;
	extern enum comp proccomp;

	fprintf(stderr, "%s(%u): WARN: ", comps[proccomp], getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(er));
}

void
doerrx(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverrx(fmt, ap);
	va_end(ap);
}

void
doerr(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	doverr(fmt, ap);
	va_end(ap);
}

void
dowarnx(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarnx(fmt, ap);
	va_end(ap);
}

void
dowarn(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovwarn(fmt, ap);
	va_end(ap);
}

void
doddbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovddbg(fmt, ap);
	va_end(ap);
}

void
dodbg(const char *fmt, ...)
{
	va_list	 	 ap;

	va_start(ap, fmt);
	dovdbg(fmt, ap);
	va_end(ap);
}

const char *
compname(enum comp comp)
{

	return(comps[comp]);
}
