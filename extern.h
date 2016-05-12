#ifndef EXTERN_H
#define EXTERN_H

enum	acctop {
	ACCT_STOP,
	ACCT_SIGN,
	ACCT__MAX
};

__BEGIN_DECLS

/*
 * Start with our three components.
 * These are all isolated and talk to each other using sockets.
 */
int		 netproc(int, int, const char *);
int		 acctproc(int, const char *);
int		 keyproc(int, const char *, const unsigned char *);

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
char		*readstring(const char *, int, const char *);
enum acctop	 readop(const char *, int);
int		 writestring(const char *, int, const char *, const char *);
int		 writeop(const char *, int, enum acctop);

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
