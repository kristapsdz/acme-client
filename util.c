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
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static	volatile sig_atomic_t sig;

static	const char *const comms[COMM__MAX] = {
	"req", /* COMM_REQ */
	"thumbprint", /* COMM_THUMB */
	"cert", /* COMM_CERT */
	"payload", /* COMM_PAY */
	"nonce", /* COMM_NONCE */
	"token", /* COMM_TOK */
	"challenge", /* COMM_CHNG */
	"challenge-ack", /* COMM_CHNG_ACK */
	"challenge-fin", /* COMM_CHNG_FIN */
	"account", /* COMM_SIGN */
	"csr", /* COMM_CSR */
};

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
readop(const char *sub, int fd, enum comm comm)
{
	ssize_t	 	 ssz;
	long		 op;

	ssz = read(fd, &op, sizeof(long));
	if (ssz < 0) {
		doxwarn(sub, "read: %s", comms[comm]);
		return(LONG_MAX);
	} else if (ssz && ssz != sizeof(long)) {
		doxwarnx(sub, "short read: %s", comms[comm]);
		return(LONG_MAX);
	} else if (0 == ssz)
		return(0);

	return(op);
}

char *
readstr(const char *sub, int fd, enum comm comm)
{
	size_t	 sz;

	return(readbuf(sub, fd, comm, &sz));
}

char *
readbuf(const char *sub, int fd, enum comm comm, size_t *sz)
{
	ssize_t		 ssz;
	char		*p;

	p = NULL;

	if ((ssz = read(fd, sz, sizeof(size_t))) < 0)
		doxwarn(sub, "read: %s length", comms[comm]);
	else if ((size_t)ssz != sizeof(size_t))
		doxwarnx(sub, "short read: %s length", comms[comm]);
	else if (NULL == (p = calloc(1, *sz + 1)))
		doxwarn(sub, "malloc");
	else if ((ssz = read(fd, p, *sz)) < 0)
		doxwarn(sub, "read: %s", comms[comm]);
	else if ((size_t)ssz != *sz)
		doxwarnx(sub, "short read: %s", comms[comm]);
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
writeop(const char *sub, int fd, enum comm comm, long op)
{
	void	(*sig)(int);
	ssize_t	 ssz;
	int	 rc;

	rc = 0;
	/* Catch a closed pipe. */
	sig = signal(SIGPIPE, sigpipe);

	if ((ssz = write(fd, &op, sizeof(long))) < 0) 
		doxwarn(sub, "write: %s", comms[comm]);
	else if ((size_t)ssz != sizeof(long))
		doxwarnx(sub, "short write: %s", comms[comm]);
	else
		rc = 1;

	/* Reinstate signal handler. */
	signal(SIGPIPE, sig);
	sig = 0;
	return(rc);
}

int
writebuf(const char *sub, int fd, enum comm comm, const void *v, size_t sz)
{
	ssize_t	 ssz;
	int	 rc;
	void	(*sig)(int);

	rc = 0;
	/* Catch a closed pipe. */
	sig = signal(SIGPIPE, sigpipe);

	if ((ssz = write(fd, &sz, sizeof(size_t))) < 0) 
		doxwarn(sub, "write: %s length", comms[comm]);
	else if ((size_t)ssz != sizeof(size_t))
		doxwarnx(sub, "short write: %s length", comms[comm]);
	else if ((ssz = write(fd, v, sz)) < 0)
		doxwarn(sub, "write: %s", comms[comm]);
	else if ((size_t)ssz != sz)
		doxwarnx(sub, "short write: %s", comms[comm]);
	else
		rc = 1;

	/* Reinstate signal handler. */
	signal(SIGPIPE, sig);
	sig = 0;
	return(rc);
}

int
writestr(const char *sub, int fd, enum comm comm, const char *v)
{

	return(writebuf(sub, fd, comm, v, strlen(v)));
}
