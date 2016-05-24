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
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "extern.h"

struct	http;

struct	source {
	int	 family; /* 4 (PF_INET) or 6 (PF_INET6) */
	char	*ip; /* IPV4 or IPV6 address */
};

typedef	ssize_t (*writefp)(const void *, size_t, const struct http *);
typedef	ssize_t (*readfp)(char *, size_t, const struct http *);

/* 
 * HTTP/S header pair.
 * There's also a cooked-up pair, "Status", with the status code.
 * Both strings are nil-terminated.
 */
struct	httphead {
	const char	*key;
	const char	*val;
};

/*
 * A buffer for transferring HTTP/S data.
 */
struct	httpxfer {
	char		*hbuf; /* header transfer buffer */
	size_t		 hbufsz; /* header buffer size */
	int		 headok; /* header has been parsed */
	char		*bbuf; /* body transfer buffer */
	size_t		 bbufsz; /* body buffer size */
	int		 bodyok; /* body has been parsed */
	char		*headbuf;
	struct httphead	*head;
	size_t		 headsz;
};

/*
 * An HTTP/S connection object.
 */
struct	http {
	int	 	   fd; /* connected socket */
	short	 	   port; /* port number */
	struct source	   src; /* endpoint (raw) host */
	char		  *path; /* path to request */
	char		  *host; /* name of endpoint host */
	struct tls_config *cfg; /* if TLS */
	struct tls	  *ctx; /* if TLS */
	writefp		   writer; /* write function */
	readfp		   reader; /* read function */
};

static ssize_t
dosysread(char *buf, size_t sz, const struct http *http)
{
	ssize_t	 rc;

	rc = read(http->fd, buf, sz);
	if (rc < 0)
		warn("%s: read", http->src.ip);
	return(rc);
}

static ssize_t
dosyswrite(const void *buf, size_t sz, const struct http *http)
{
	ssize_t	 rc;

	rc = write(http->fd, buf, sz);
	if (rc < 0)
		warn("%s: write", http->src.ip);
	return(rc);
}

static ssize_t
dotlsread(char *buf, size_t sz, const struct http *http)
{
	int	 rc;

	rc = tls_read(http->ctx, buf, sz);
	if (rc < 0)
		warn("%s: tls_read", http->src.ip);
	return(rc);
}

static ssize_t
dotlswrite(const void *buf, size_t sz, const struct http *http)
{
	int	 rc;

	do
		rc = tls_write(http->ctx, buf, sz);
	while (TLS_WANT_POLLIN == rc ||
	       TLS_WANT_POLLOUT == rc);

	if (rc < 0)
		warnx("%s: tls_write: %s", 
			http->src.ip, tls_error(http->ctx));
	return(rc);
}

static ssize_t
http_read(char *buf, size_t sz, const struct http *http)
{
	ssize_t	 ssz, xfer;

	xfer = 0;
	do {
		if ((ssz = http->reader(buf, sz, http)) < 0)
			return(-1);
		if (0 == ssz)
			break;
		xfer += ssz;
		sz -= ssz;
		buf += ssz;
	} while (ssz > 0 && sz > 0);

	return(xfer);
}

static int
http_write(const void *buf, size_t sz, const struct http *http)
{
	ssize_t	 ssz, xfer;

	xfer = sz;
	while (sz > 0) {
		if ((ssz = http->writer(buf, sz, http)) < 0)
			return(-1);
		sz -= ssz;
		buf += ssz;
	}
	return(xfer);
}

void
http_free(struct http *http)
{

	if (NULL == http)
		return;
	if (NULL != http->cfg)
		tls_config_free(http->cfg);
	if (NULL != http->ctx)
		tls_close(http->ctx);
	if (NULL != http->ctx)
		tls_free(http->ctx);
	if (-1 != http->fd)
		close(http->fd);
	free(http->host);
	free(http->path);
	free(http->src.ip);
	free(http);
}

struct http *
http_alloc(const struct source *addrs, size_t addrsz, 
	const char *host, short port, const char *path)
{
	struct sockaddr_storage ss;
	int		 family, fd, c;
	socklen_t	 len;
	size_t		 cur, i = 0;
	struct http	*http;

	/* Do this while we still have addresses to connect. */
again:
	if (i == addrsz)
		return(NULL);
	cur = i++;

	/* Convert to PF_INET or PF_INET6 address from string. */

	memset(&ss, 0, sizeof(struct sockaddr_storage));

	if (4 == addrs[cur].family) {
		family = PF_INET;
		((struct sockaddr_in *)&ss)->sin_family = AF_INET;
		((struct sockaddr_in *)&ss)->sin_port = htons(port);
		c = inet_pton(AF_INET, addrs[cur].ip, 
			&((struct sockaddr_in *)&ss)->sin_addr);
		len = sizeof(struct sockaddr_in);
	} else if (6 == addrs[cur].family) {
		family = PF_INET6;
		((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&ss)->sin6_port = htons(port);
		c = inet_pton(AF_INET6, addrs[cur].ip, 
			&((struct sockaddr_in6 *)&ss)->sin6_addr);
		len = sizeof(struct sockaddr_in6);
	} else {
		warnx("%s: unknown family", addrs[cur].ip);
		goto again;
	}

	if (c < 0) {
		warn("%s: inet_ntop", addrs[cur].ip);
		goto again;
	} else if (0 == c) {
		warnx("%s: inet_ntop", addrs[cur].ip);
		goto again;
	}

	/* Create socket and connect. */

	fd = socket(family, SOCK_STREAM, 0);
	if (-1 == fd) {
		warn("%s: socket", addrs[cur].ip);
		goto again;
	} else if (-1 == connect(fd, (struct sockaddr *)&ss, len)) {
		warn("%s: connect", addrs[cur].ip);
		close(fd);
		goto again;
	}

	/* Allocate the communicator. */

	http = calloc(1, sizeof(struct http));
	if (NULL == http) {
		warn("calloc");
		close(fd);
		return(NULL);
	}
	http->fd = fd;
	http->port = port;
	http->src.family = addrs[cur].family;
	http->src.ip = strdup(addrs[cur].ip);
	http->host = strdup(host);
	http->path = strdup(path);
	if (NULL == http->src.ip ||
	    NULL == http->host ||
	    NULL == http->path) {
		warn("strdup");
		goto err;
	}

	/* If necessary, do our TLS setup. */

	if (443 != port) {
		http->writer = dosyswrite;
		http->reader = dosysread;
		return(http);
	}

	http->writer = dotlswrite;
	http->reader = dotlsread;

	if (-1 == tls_init()) {
		warn("tls_init");
		goto err;
	}

	http->cfg = tls_config_new();
	if (NULL == http->cfg) {
		warn("tls_config_new");
		goto err;
	}

	tls_config_set_protocols(http->cfg, TLS_PROTOCOLS_ALL);

	if (-1 == tls_config_set_ciphers(http->cfg, "compat")) {
	        warn("tls_config_set_ciphers");
		goto err;
	} else if (NULL == (http->ctx = tls_client())) {
		warn("tls_client");
		goto err;
	} else if (-1 == tls_configure(http->ctx, http->cfg)) {
		warnx("%s: tls_configure: %s",
			http->src.ip, tls_error(http->ctx));
		goto err;
	}

	if (0 != tls_connect_socket
	     (http->ctx, http->fd, http->host)) {
		warnx("%s: tls_connect_socket: %s", 
			http->src.ip, tls_error(http->ctx));
		goto err;
	}

	return(http);
err:
	http_free(http);
	return(NULL);
}

struct httpxfer *
http_open(const struct http *http)
{
	char		*req;
	int		 c;
	struct httpxfer	*trans;

	c = asprintf(&req, 
		"GET %s HTTP/1.0\r\n"
		"Host: %s\r\n"
		"\r\n",
		http->path, http->host);
	if (-1 == c) {
		warn("asprintf");
		return(NULL);
	} else if ( ! http_write(req, c, http)) {
		free(req);
		return(NULL);
	}

	free(req);

	trans = calloc(1, sizeof(struct httpxfer));
	if (NULL == trans) 
		warn("calloc");
	return(trans);
}

void
http_close(struct httpxfer *x)
{

	if (NULL == x)
		return;
	free(x->hbuf);
	free(x->bbuf);
	free(x->headbuf);
	free(x->head);
	free(x);
}

/*
 * Read the HTTP body from the wire.
 * If invoked multiple times, this will return the same pointer with the
 * same data (or NULL, if the original invocation returned NULL).
 * Returns NULL if read or allocation errors occur.
 * You must not free the returned pointer.
 */
char *
http_body_read(const struct http *http, 
	struct httpxfer *trans, size_t *sz)
{
	char		 buf[BUFSIZ];
	ssize_t		 ssz;
	void		*pp;

	/* Have we already parsed this? */

	if (trans->bodyok > 0) {
		*sz = trans->bbufsz;
		return(trans->bbuf);
	} else if (trans->bodyok < 0)
		return(NULL);

	*sz = 0;
	trans->bodyok = -1;

	do {
		/* If less than sizeof(buf), at EOF. */
		if ((ssz = http_read(buf, sizeof(buf), http)) < 0)
			return(NULL);
		pp = realloc(trans->bbuf, trans->bbufsz + ssz);
		if (NULL == pp) {
			warn("realloc");
			return(NULL);
		}
		trans->bbuf = pp;
		memcpy(trans->bbuf + trans->bbufsz, buf, ssz);
		trans->bbufsz += ssz;
	} while (sizeof(buf) == ssz);

	trans->bodyok = 1;
	*sz = trans->bbufsz;
	return(trans->bbuf);
}

/*
 * Parse headers from the transfer.
 * Malformed headers are skipped.
 * A special "Status" header is added for the HTTP status line.
 * This can only happen once http_head_read has been called with
 * success.
 * This can be invoked multiple times: it will only parse the headers
 * once and after that it will just return the cache.
 * You must not free the returned pointer.
 * If the original header parse failed, or if memory allocation fails
 * internally, this returns NULL.
 */
struct httphead *
http_head_parse(struct httpxfer *trans, size_t *sz)
{
	size_t		 hsz;
	struct httphead	*h;
	char		*cp, *ep, *ccp, *buf;

	/*
	 * If we've already parsed the headers, return the
	 * previously-parsed buffer now.
	 * If we have errors on the stream, return NULL now.
	 */

	if (NULL != trans->head) {
		*sz = trans->headsz;
		return(trans->head);
	} else if (trans->headok <= 0)
		return(NULL);

	if (NULL == (buf = strdup(trans->hbuf))) {
		warn("strdup");
		return(NULL);
	}
	hsz = 0;
	cp = buf;

	do { 
		if (NULL != (cp = strstr(cp, "\r\n")))
			cp += 2;
		hsz++;
	} while (NULL != cp);

	/*
	 * Allocate headers, then step through the data buffer, parsing
	 * out headers as we have them.
	 * We know at this point that the buffer is nil-terminated in
	 * the usual way.
	 */

	h = calloc(hsz, sizeof(struct httphead));
	if (NULL == h) {
		warn("calloc");
		free(buf);
		return(NULL);
	}

	*sz = hsz;
	hsz = 0;
	cp = buf;

	do { 
		if (NULL != (ep = strstr(cp, "\r\n"))) {
			*ep = '\0';
			ep += 2;
		}
		if (0 == hsz) {
			h[hsz].key = "Status";
			h[hsz++].val = cp;
			continue;
		}

		/* Skip bad headers. */
		if (NULL == (ccp = strchr(cp, ':')))
			continue;

		*ccp++ = '\0';
		while (isspace((int)*ccp))
			ccp++;
		h[hsz].key = cp;
		h[hsz++].val = ccp;
	} while (NULL != (cp = ep));

	trans->headbuf = buf;
	trans->head = h;
	trans->headsz = hsz;
	return(h);
}

/*
 * Read the HTTP headers from the wire.
 * If invoked multiple times, this will return the same pointer with the
 * same data (or NULL, if the original invocation returned NULL).
 * Returns NULL if read or allocation errors occur.
 * You must not free the returned pointer.
 */
char *
http_head_read(const struct http *http, 
	struct httpxfer *trans, size_t *sz)
{
	char		 buf[BUFSIZ];
	ssize_t		 ssz;
	char		*ep;
	void		*pp;

	/* Have we already parsed this? */

	if (trans->headok > 0) {
		*sz = trans->hbufsz;
		return(trans->hbuf);
	} else if (trans->headok < 0)
		return(NULL);

	*sz = 0;
	ep = NULL;
	trans->headok = -1;

	/*
	 * Begin by reading by BUFSIZ blocks until we reach the header
	 * termination marker (two CRLFs).
	 * We might read into our body, but that's ok: we'll copy out
	 * the body parts into our body buffer afterward.
	 */

	do {
		/* If less than sizeof(buf), at EOF. */
		if ((ssz = http_read(buf, sizeof(buf), http)) < 0)
			return(NULL);
		pp = realloc(trans->hbuf, trans->hbufsz + ssz);
		if (NULL == pp) {
			warn("realloc");
			return(NULL);
		}
		trans->hbuf = pp;
		memcpy(trans->hbuf + trans->hbufsz, buf, ssz);
		trans->hbufsz += ssz;
		/* Search for end of headers marker. */
		ep = memmem(trans->hbuf, trans->hbufsz, "\r\n\r\n", 4);
	} while (NULL == ep && sizeof(buf) == ssz);

	if (NULL == ep) {
		warnx("%s: partial transfer", http->src.ip);
		return(NULL);
	}
	*ep = '\0';

	/*
	 * The header data is invalid if it has any binary characters in
	 * it: check that now.
	 * This is important because we want to guarantee that all
	 * header keys and pairs are properly nil-terminated.
	 */

	if (strlen(trans->hbuf) != (uintptr_t)(ep - trans->hbuf)) {
		warnx("%s: binary data in header", http->src.ip);
		return(NULL);
	}

	/*
	 * Copy remaining buffer into body buffer.
	 */

	ep += 4;
	trans->bbufsz = (trans->hbuf + trans->hbufsz) - ep;
	trans->bbuf = malloc(trans->bbufsz);
	if (NULL == trans->bbuf) {
		warn("malloc");
		return(NULL);
	}
	memcpy(trans->bbuf, ep, trans->bbufsz);

	trans->headok = 1;
	*sz = trans->hbufsz;
	return(trans->hbuf);
}

#if 0
int
main(void)
{
	struct http	*h;
	struct httpxfer	*x;
	char		*body, *head;
	size_t		 bodysz, headsz;
	struct source	 addrs[2];

	/*addrs[0].ip = "2a00:1450:400a:806::2004";
	addrs[0].family = 6;
	addrs[1].ip = "193.135.3.123";
	addrs[1].family = 4;*/
	addrs[0].ip = "127.0.0.1";
	addrs[0].family = 4;

	h = http_alloc(addrs, 1, 
		"localhost", 80, "/index.html");

	if (NULL == h) 
		errx(EXIT_FAILURE, "http_alloc");

	if (NULL == (x = http_open(h))) {
		warnx("http_open");
		http_free(h);
		return(EXIT_FAILURE);
	}

	if (NULL == (head = http_head_read(h, x, &headsz))) {
		warnx("http_head_read");
		http_close(x);
		http_free(h);
		return(EXIT_FAILURE);
	} else if (NULL == (body = http_body_read(h, x, &bodysz))) {
		warnx("http_body_read");
		http_close(x);
		http_free(h);
		return(EXIT_FAILURE);
	}

	warnx("head: [%.*s]", (int)headsz, head);
	warnx("body: [%.*s]", (int)bodysz, body);

	http_close(x);
	http_free(h);
	return(EXIT_SUCCESS);
}
#endif
