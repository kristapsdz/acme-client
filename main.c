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

#include <sys/socket.h>
#include <sys/param.h>

#include <err.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

#define NOBODY_USER "nobody"

int
main(int argc, char *argv[])
{
	const char	 *domain, *certdir, *acctkey, 
	     		 *chngdir, *keyfile, *nobody;
	int		  key_fds[2], acct_fds[2], chng_fds[2], 
			  cert_fds[2], file_fds[2], dns_fds[2],
			  rvk_fds[2];
	pid_t		  pids[COMP__MAX];
	int		  c, rc, newacct, remote, revoke, force,
			  staging;
	extern int	  verbose;
	extern enum comp  proccomp;
	size_t		  i, altsz, ne;
	const char	**alts;
	struct passwd	 *passent;
	uid_t		  nobody_uid;
	gid_t		  nobody_gid;

	alts = NULL;
	nobody = NOBODY_USER;
	newacct = remote = revoke = verbose = force = staging = 0;
	certdir = "/etc/ssl/letsencrypt";
	keyfile = "/etc/ssl/letsencrypt/private/privkey.pem";
	acctkey = "/etc/letsencrypt/privkey.pem";
	chngdir = "/var/www/letsencrypt";

	while (-1 != (c = getopt(argc, argv, "Fnrstvf:c:C:k:u:"))) 
		switch (c) {
		case ('c'):
			certdir = optarg;
			break;
		case ('C'):
			chngdir = optarg;
			break;
		case ('f'):
			acctkey = optarg;
			break;
		case ('F'):
			force = 1;
			break;
		case ('k'):
			keyfile = optarg;
			break;
		case ('n'):
			newacct = 1;
			break;
		case ('r'):
			revoke = 1;
			break;
		case ('s'):
			staging = 1;
			break;
		case ('t'):
			/*
			 / Undocumented feature.
			 * Don't use it.
			 */
			remote = 1;
			break;
		case ('u'):
			nobody = optarg;
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

	/*
	 * Look up our privilege-separated users.
	 * We care about "nobody" for key and network operations and the
	 * web user for the challenge operations.
	 */

	passent = getpwnam(nobody);
	if (NULL == passent)
		errx(EXIT_FAILURE, "%s: bad user", nobody);
	nobody_uid = passent->pw_uid;
	nobody_gid = passent->pw_gid;

	/* 
	 * Do some quick checks to see if our paths exist. 
	 * This will be done in the children, but we might as well check
	 * now before the fork.
	 */

	ne = 0;

	if (-1 == access(certdir, R_OK)) {
		warnx("%s: -c directory must exist", certdir);
		ne++;
	}
	if (-1 == access(keyfile, R_OK)) {
		warnx("%s: -k file must exist", keyfile);
		ne++;
	}
	if (-1 == access(chngdir, R_OK)) {
		warnx("%s: -C directory must exist", chngdir);
		ne++;
	}
	if (0 == newacct && -1 == access(acctkey, R_OK)) {
		warnx("%s: -f file must exist", acctkey);
		ne++;
	}

	if (ne > 0)
		exit(EXIT_FAILURE);

	/* Set the zeroth altname as our domain. */

	altsz = argc + 1;
	alts = calloc(altsz, sizeof(char *));
	if (NULL == alts)
		err(EXIT_FAILURE, "calloc");
	alts[0] = domain;
	for (i = 0; i < (size_t)argc; i++)
		alts[i + 1] = argv[i];

	/* 
	 * Open channels between our components. 
	 */

	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, key_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, acct_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, chng_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, cert_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, file_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, dns_fds))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, rvk_fds))
		err(EXIT_FAILURE, "socketpair");

	/* Start with the network-touching process. */

	if (-1 == (pids[COMP_NET] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_NET]) {
		proccomp = COMP_NET;
		close(key_fds[0]);
		close(acct_fds[0]);
		close(chng_fds[0]);
		close(cert_fds[0]);
		close(file_fds[0]);
		close(file_fds[1]);
		close(dns_fds[0]);
		close(rvk_fds[0]);
		c = netproc(key_fds[1], acct_fds[1], 
			chng_fds[1], cert_fds[1], 
			dns_fds[1], rvk_fds[1], 
			newacct, revoke, staging,
			nobody_uid, nobody_gid,
			(const char *const *)alts, altsz);
		free(alts);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(key_fds[1]);
	close(acct_fds[1]);
	close(chng_fds[1]);
	close(cert_fds[1]);
	close(dns_fds[1]);
	close(rvk_fds[1]);

	/* Now the key-touching component. */

	if (-1 == (pids[COMP_KEY] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_KEY]) {
		proccomp = COMP_KEY;
		close(cert_fds[0]);
		close(dns_fds[0]);
		close(rvk_fds[0]);
		close(acct_fds[0]);
		close(chng_fds[0]);
		close(file_fds[0]);
		close(file_fds[1]);
		c = keyproc(key_fds[0], keyfile, 
			nobody_uid, nobody_gid, 
			(const char **)alts, altsz);
		free(alts);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(key_fds[0]);

	/* The account-touching component. */

	if (-1 == (pids[COMP_ACCOUNT] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_ACCOUNT]) {
		proccomp = COMP_ACCOUNT;
		free(alts);
		close(cert_fds[0]);
		close(dns_fds[0]);
		close(rvk_fds[0]);
		close(chng_fds[0]);
		close(file_fds[0]);
		close(file_fds[1]);
		c = acctproc(acct_fds[0], acctkey, 
			newacct, nobody_uid, nobody_gid);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(acct_fds[0]);

	/* The challenge-accepting component. */

	if (-1 == (pids[COMP_CHALLENGE] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_CHALLENGE]) {
		proccomp = COMP_CHALLENGE;
		free(alts);
		close(cert_fds[0]);
		close(dns_fds[0]);
		close(rvk_fds[0]);
		close(file_fds[0]);
		close(file_fds[1]);
		c = chngproc(chng_fds[0], chngdir, remote);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(chng_fds[0]);

	/* The certificate-handling component. */

	if (-1 == (pids[COMP_CERT] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_CERT]) {
		proccomp = COMP_CERT;
		free(alts);
		close(dns_fds[0]);
		close(rvk_fds[0]);
		close(file_fds[1]);
		c = certproc(cert_fds[0], file_fds[0],
			nobody_uid, nobody_gid);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(cert_fds[0]);
	close(file_fds[0]);

	/* The certificate-handling component. */

	if (-1 == (pids[COMP_FILE] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_FILE]) {
		proccomp = COMP_FILE;
		free(alts);
		close(dns_fds[0]);
		close(rvk_fds[0]);
		c = fileproc(file_fds[1], certdir);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(file_fds[1]);

	/* The DNS lookup component. */

	if (-1 == (pids[COMP_DNS] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_DNS]) {
		proccomp = COMP_DNS;
		free(alts);
		close(rvk_fds[0]);
		c = dnsproc(dns_fds[0], nobody_uid, nobody_gid);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(dns_fds[0]);

	/* The expiration component. */

	if (-1 == (pids[COMP_REVOKE] = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == pids[COMP_REVOKE]) {
		proccomp = COMP_REVOKE;
		c = revokeproc(rvk_fds[0], certdir, 
			nobody_uid, nobody_gid, force, revoke,
			(const char *const *)alts, altsz);
		free(alts);
		exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(rvk_fds[0]);

	/* Jail: sandbox, file-system, user. */

	if ( ! sandbox_before())
		exit(EXIT_FAILURE);
	else if ( ! dropfs(PATH_VAR_EMPTY))
		exit(EXIT_FAILURE);
	else if ( ! dropprivs(nobody_uid, nobody_gid))
		exit(EXIT_FAILURE);
	else if ( ! sandbox_after())
		exit(EXIT_FAILURE);

	/*
	 * Collect our subprocesses.
	 * Require that they both have exited cleanly.
	 */

	rc = checkexit(pids[COMP_KEY], COMP_KEY) +
	     checkexit(pids[COMP_CERT], COMP_CERT) +
	     checkexit(pids[COMP_NET], COMP_NET) +
	     checkexit(pids[COMP_FILE], COMP_FILE) +
	     checkexit(pids[COMP_ACCOUNT], COMP_ACCOUNT) +
	     checkexit(pids[COMP_CHALLENGE], COMP_CHALLENGE) +
	     checkexit(pids[COMP_DNS], COMP_DNS) +
	     checkexit(pids[COMP_REVOKE], COMP_REVOKE);

	free(alts);
	return(COMP__MAX == rc ? EXIT_SUCCESS : EXIT_FAILURE);
usage:
	fprintf(stderr, "usage: %s "
		"[-nrsv] "
		"[-C challengedir] "
		"[-c certdir] "
		"[-f accountkey] "
		"[-k domainkey] "
		"[-u user] "
		"domain [altnames...]\n", 
		getprogname());
	return(EXIT_FAILURE);
}
