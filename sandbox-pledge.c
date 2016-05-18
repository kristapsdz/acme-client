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

int
sandbox_before(void)
{

	return(1);
}

int
sandbox_after(void)
{

	switch (proccomp) {
	case (COMP_ACCOUNT):
	case (COMP_CERT):
	case (COMP_KEY):
	case (COMP_REVOKE):
	case (COMP__MAX):
		if (-1 == pledge("stdio", NULL)) {
			dowarn("pledge");
			return(0);
		}
		break;
	case (COMP_CHALLENGE):
		if (-1 == pledge("stdio cpath wpath", NULL)) {
			dowarn("pledge");
			return(0);
		}
		break;
	case (COMP_DNS):
		if (-1 == pledge("stdio dns", NULL)) {
			dowarn("pledge");
			return(0);
		}
		break;
	case (COMP_FILE):
		/* 
		 * XXX: rpath shouldn't be here, but it's tripped by the
		 * rename(2) despite that pledge(2) specifically says
		 * rename(2) is cpath.
		 */
		if (-1 == pledge("stdio cpath wpath rpath", NULL)) {
			dowarn("pledge");
			return(0);
		}
		break;
	case (COMP_NET):
		/* rpath required by libcurl */
		if (-1 == pledge("stdio inet rpath", NULL)) {
			dowarn("pledge");
			return(0);
		}
		break;
	}
	return(1);
}
