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
 * Should we print debugging messages?
 */
int		 verbose;

__END_DECLS

#endif /* EXTERN_H */
