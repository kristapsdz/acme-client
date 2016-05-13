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
#include <sys/socket.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

int
main(int argc, char *argv[])
{
	const char	 *domain, *certdir, *acctkey, *chngdir;
	int		  key_fds[2], acct_fds[2], chng_fds[2], cert_fds[2];
	pid_t		  pids[COMP__MAX];
	int		  c, rc, newacct;
	extern int	  verbose;
	size_t		  i, altsz;
	char		**alts;

	alts = NULL;
	newacct = 0;
	verbose = 0;
	certdir = "/etc/letsencrypt/public";
	acctkey = "/etc/letsencrypt/private/privkey.pem";
	chngdir = "/var/www/letsencrypt";

	while (-1 != (c = getopt(argc, argv, "nNf:c:vC:"))) 
		switch (c) {
		case ('n'):
			newacct = 1;
			break;
		case ('N'):
			newacct = 2;
			break;
		case ('C'):
			chngdir = optarg;
			break;
		case ('c'):
			certdir = optarg;
			break;
		case ('f'):
			acctkey = optarg;
			break;
		case ('v'):
			verbose = verbose ? 2 : 1;
			break;
		default:
			goto usage;
		}

	argc -= optind;
	argv += optind;
	if (0 == argc)
		goto usage;

	domain = argv[0];
	argc--;
	argv++;

	if (0 != getuid())
		errx(EXIT_FAILURE, "must be run as root");

	altsz = argc;
	alts = calloc(altsz, sizeof(char *));
	for (i = 0; i < altsz; i++)
		alts[i] = argv[i];

	/* 
	 * Open channels between our components. 
	 * We exclusively use UNIX domain socketpairs.
	 */
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, key_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, acct_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, chng_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, cert_fds))
		err(EXIT_FAILURE, "socketpair");

	/* Start with the network-touching process. */

	if (-1 == (pids[COMP_NET] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_NET]) {
		close(key_fds[0]);
		close(acct_fds[0]);
		close(chng_fds[0]);
		close(cert_fds[0]);
		c = netproc(key_fds[1], acct_fds[1], 
			chng_fds[1], cert_fds[1], domain, newacct);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(key_fds[1]);
	close(acct_fds[1]);
	close(chng_fds[1]);
	close(cert_fds[1]);

	/* Now the key-touching component. */

	if (-1 == (pids[COMP_KEY] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_KEY]) {
		close(acct_fds[0]);
		close(chng_fds[0]);
		c = keyproc(key_fds[0], certdir, domain,
			(const char **)alts, altsz);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(key_fds[0]);

	/* Finally, the account-touching component. */

	if (-1 == (pids[COMP_ACCOUNT] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_ACCOUNT]) {
		close(chng_fds[0]);
		c = acctproc(acct_fds[0], acctkey, newacct);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(acct_fds[0]);

	/* Finally, the challenge-accepting component. */

	if (-1 == (pids[COMP_CHALLENGE] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_CHALLENGE]) {
		c = chngproc(chng_fds[0], chngdir);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(chng_fds[0]);

	/* The certificate-handling component. */

	if (-1 == (pids[COMP_CERT] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_CERT]) {
		c = certproc(cert_fds[0], certdir);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(cert_fds[0]);

	/*
	 * Collect our subprocesses.
	 * Require that they both have exited cleanly.
	 */
	rc = checkexit(pids[COMP_KEY], COMP_KEY) +
	     checkexit(pids[COMP_CERT], COMP_CERT) +
	     checkexit(pids[COMP_NET], COMP_NET) +
	     checkexit(pids[COMP_ACCOUNT], COMP_ACCOUNT) +
	     checkexit(pids[COMP_CHALLENGE], COMP_CHALLENGE);

	free(alts);
	return(COMP__MAX == rc ? EXIT_SUCCESS : EXIT_FAILURE);
usage:
	fprintf(stderr, "usage: %s "
		"[-vnN] "
		"[-C challengedir] "
		"[-c certdir] "
		"[-f accountkey] "
		"domain\n", 
		getprogname());
	return(EXIT_FAILURE);
}
