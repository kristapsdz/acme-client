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
#include <sys/stat.h>
#include <sys/param.h>

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

#define MAX_SERVERS_DNS 8

/*
 * This is a modified version of host_dns in config.c of OpenBSD's ntpd.
 */
/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static ssize_t
host_dns(const char *s, char vec[MAX_SERVERS_DNS][INET6_ADDRSTRLEN]) 
{
	struct addrinfo		 hints, *res0, *res;
	int			 error;
	ssize_t			 vecsz;
	struct sockaddr		*sa;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /* DUMMY */
	/* ntpd MUST NOT use AI_ADDRCONFIG here */

	error = getaddrinfo(s, NULL, &hints, &res0);

	if (error == EAI_AGAIN || 
	    error == EAI_NODATA || 
	    error == EAI_NONAME)
		return(0);

	if (error) {
		dowarnx("%s: parse error: %s", 
			s, gai_strerror(error));
		return(-1);
	}

	for (vecsz = 0, res = res0; 
	     NULL != res && vecsz < MAX_SERVERS_DNS; 
	     res = res->ai_next) {
		/* 
		 * FIXME.
		 * libcurl only seems to support a single address per
		 * host in its list of resolutions.
		 * This needs further examination.
		 */
		if (res->ai_family != AF_INET)
			continue;
		/*if (res->ai_family != AF_INET &&
		    res->ai_family != AF_INET6)
			continue;*/

		sa = res->ai_addr;

		if (AF_INET == res->ai_family)
			inet_ntop(AF_INET, 
				&(((struct sockaddr_in *)sa)->sin_addr), 
				vec[vecsz], INET6_ADDRSTRLEN);
		else
			inet_ntop(AF_INET6, 
				&(((struct sockaddr_in6 *)sa)->sin6_addr), 
				vec[vecsz], INET6_ADDRSTRLEN);

		dodbg("%s: DNS: %s", s, vec[vecsz]);
		vecsz++;
		break;
	}

	freeaddrinfo(res0);
	return(vecsz);
}

int
dnsproc(int nfd, uid_t uid, gid_t gid)
{
	int		 rc;
	char		*look;
	char		 v[MAX_SERVERS_DNS][INET6_ADDRSTRLEN];
	long		 lval;
	size_t		 i;
	ssize_t		 vsz;
	enum dnsop	 op;

	rc = 0;
	look = NULL;

	/*
	 * Why don't we chroot() here?
	 * On OpenBSD, the pledge(2) takes care of our constraining the
	 * environment to DNS resolution only, so the chroot(2) is
	 * unnecessary.
	 * On Mac OS X, we can't chroot(2): we'd need to have an mdns
	 * responder thing in each jail.
	 * On Linux, forget it.  getaddrinfo(2) pulls on all sorts of
	 * mystery meat.
	 */

	if ( ! sandbox_before()) {
		dowarnx("sandbox_before");
		goto out;
	} else if ( ! dropprivs(uid, gid)) {
		dowarnx("dropprivs");
		goto out;
	} else if ( ! sandbox_after()) {
		dowarnx("sandbox_after");
		goto out;
	}

	/*
	 * This is simple: just loop on a request operation, and each
	 * time we write back zero or more entries.
	 */

	for (;;) {
		op = DNS__MAX;
		if (0 == (lval = readop(nfd, COMM_DNS)))
			op = DNS_STOP;
		else if (DNS_LOOKUP == lval)
			op = lval;

		if (DNS__MAX == op) {
			dowarnx("unknown operation from netproc");
			goto out;
		} else if (DNS_STOP == op)
			break;

		if (NULL == (look = readstr(nfd, COMM_DNSQ)))
			goto out;
		if ((vsz = host_dns(look, v)) < 0)
			goto out;
		if ( ! writeop(nfd, COMM_DNSLEN, vsz)) 
			goto out;
		for (i = 0; i < (size_t)vsz; i++) 
			if ( ! writestr(nfd, COMM_DNSA, v[i]))
				goto out;

		free(look);
		look = NULL;
	}

	rc = 1;
out:
	close(nfd);
	free(look);
	return(rc);
}
