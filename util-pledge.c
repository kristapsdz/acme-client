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

#include <unistd.h>

#include "extern.h"

int
dropfs(const char *path)
{

	(void)path;

	/*
	 * On OpenBSD with pledge(2), we don't need to chroot(2), so we
	 * don't need to run as root.
	 * Why?  As said by deraadt@, "Embrace the pledge."
	 */
	return(1);
}

int
checkprivs(void)
{

	/*
	 * No need for root privileges.
	 */
	return(1);
}

int
dropprivs(uid_t uid, gid_t gid)
{

	(void)uid;
	(void)gid;

	/*
	 * No need to drop privileges?
	 * What is the point of dropping root privileges if root can't
	 * do anything?
	 */
	return(1);
}
