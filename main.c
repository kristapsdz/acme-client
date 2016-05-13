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
#include <sys/wait.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * Make sure that the given process exits properly.
 */
static int
checkexit(pid_t pid, const char *name)
{
	int	 c;

	if (-1 == waitpid(pid, &c, 0)) {
		warn("waitpid");
		return(0);
	}

	if ( ! WIFEXITED(c)) 
		warnx("%s(%u): bad exit", name, pid);
	else if (EXIT_SUCCESS != WEXITSTATUS(c))
		warnx("%s(%u): bad exit code", name, pid);
	else
		return(1);

	return(0);
}

int
main(int argc, char *argv[])
{
	const char	*domain, *certdir, *acctkey, *chngdir;
	int		 key_fds[2], acct_fds[2], chng_fds[2];
	int		 c, rc1, rc2, rc3, rc4, newacct;
	pid_t		 pid_net, pid_keys, pid_acct, pid_chng;
	extern int	 verbose;

	newacct = 0;
	verbose = 0;
	certdir = "/etc/ssl/letsencrypt";
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
			verbose = 1;
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

	/* Start with the network-touching process. */

	if (-1 == (pid_net = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pid_net) {
		close(key_fds[0]);
		close(acct_fds[0]);
		close(chng_fds[0]);
		c = netproc(key_fds[1], acct_fds[1], 
			chng_fds[1], domain, newacct);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(key_fds[1]);
	close(acct_fds[1]);
	close(chng_fds[1]);

	/* Now the key-touching component. */

	if (-1 == (pid_keys = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pid_keys) {
		close(acct_fds[0]);
		close(chng_fds[0]);
		c = keyproc(key_fds[0], certdir, 
			(const unsigned char *)domain);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(key_fds[0]);

	/* Finally, the account-touching component. */

	if (-1 == (pid_acct = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pid_acct) {
		close(chng_fds[0]);
		c = acctproc(acct_fds[0], acctkey, newacct);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(acct_fds[0]);

	/* Finally, the challenge-accepting component. */

	if (-1 == (pid_chng = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pid_chng) {
		c = chngproc(chng_fds[0], chngdir);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(chng_fds[0]);

	/*
	 * Collect our subprocesses.
	 * Require that they both have exited cleanly.
	 */
	rc1 = checkexit(pid_keys, "keyproc");
	rc2 = checkexit(pid_net, "netproc");
	rc3 = checkexit(pid_acct, "acctproc");
	rc4 = checkexit(pid_chng, "chngproc");

	return(rc1 && rc2 && rc3 && rc4 ? 
		EXIT_SUCCESS : EXIT_FAILURE);
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
