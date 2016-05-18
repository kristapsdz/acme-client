#ifdef __linux__
# define _GNU_SOURCE
# include <bsd/stdlib.h>
# include <grp.h>
#endif

#ifdef __APPLE__
# include <sandbox.h>
#endif
