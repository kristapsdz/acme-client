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
#ifndef EXTERN_H
#define EXTERN_H

enum	acctop {
	ACCT_STOP,
	ACCT_SIGN,
	ACCT_THUMBPRINT,
	ACCT__MAX
};

enum	comm {
	COMM_REQ,
	COMM_THUMB,
	COMM_CERT,
	COMM_PAY,
	COMM_NONCE,
	COMM_TOK,
	COMM_CHNG,
	COMM_CHNG_ACK,
	COMM_CHNG_FIN,
	COMM_ACCT,
	COMM__MAX
};

/*
 * This contains the URI and token of an ACME-issued challenge.
 * A challenge consists of a token, which we must present on the
 * (presumably!) local machine to an ACME connection; and a URI, to
 * which we must connect to verify the token.
 */
struct challenge {
	char		*uri; /* uri on ACME server */
	char		*token; /* token we must offer */
};

/*
 * This consists of the services offered by the CA.
 * They must all be filled in.
 */
struct	capaths {
	char		*newauthz; /* new authorisation */
	char		*newcert; 
	char		*newreg; /* new acme account */
	char		*revokecert;
};

struct	json;

__BEGIN_DECLS

/*
 * Start with our components.
 * These are all isolated and talk to each other using sockets.
 */
int		 netproc(int, int, int, const char *, int);
int		 acctproc(int, const char *, int);
int		 keyproc(int, const char *, const unsigned char *);
int		 chngproc(int, const char *);

/*
 * Warning and logging functions.
 * They should be used instead of err.h because they print the process
 * component and pid.
 * XXX: or we could use setproctitle()...?  (Is that portable?)
 */
void		 dovwarnx(const char *, const char *, va_list);
void		 dovwarn(const char *, const char *, va_list);
void		 doverr(const char *, const char *, va_list);
void		 dovdbg(const char *, const char *, va_list);
void		 doxwarnx(const char *, const char *, ...);
void		 doxwarn(const char *, const char *, ...);
void		 doxerr(const char *, const char *, ...);
void		 doxdbg(const char *, const char *, ...);

/*
 * Read and write things from the wire.
 * The readers behave differently with respect to EOF.
 */
long		 readop(const char *, int, enum comm);
char		*readstr(const char *, int, enum comm);
char		*readstream(const char *, int, enum comm);
int		 writestr(const char *, int, enum comm, const char *);
int		 writeop(const char *, int, enum comm, long);

/*
 * Base64 and URL encoding.
 * Returns a buffer or NULL on allocation error.
 */
char		*base64buf_url(const char *, size_t);

/*
 * JSON parsing routines.
 * Keep this all in on place, though it's only used by one file.
 */
struct json	*json_alloc(void);
void		 json_reset(struct json *);
void		 json_free(struct json *);
size_t		 jsonbody(void *, size_t, size_t, void *);
int		 json_parse_response(struct json *);
void		 json_free_challenge(struct challenge *);
int		 json_parse_challenge(struct json *, struct challenge *);
void		 json_free_capaths(struct capaths *);
int		 json_parse_capaths(struct json *, struct capaths *);

/*
 * Should we print debugging messages?
 */
int		 verbose;

__END_DECLS

#endif /* EXTERN_H */
