#ifndef EXTERN_H
#define EXTERN_H

__BEGIN_DECLS

int	netproc(int, int);
int	acctproc(int, const char *);
int	keyproc(int, const char *, const unsigned char *);

int	verbose;

void	dovwarnx(const char *, const char *, va_list);
void	dovwarn(const char *, const char *, va_list);
void	doverr(const char *, const char *, va_list);
void	dovdbg(const char *, const char *, va_list);

__END_DECLS

#endif /* EXTERN_H */
