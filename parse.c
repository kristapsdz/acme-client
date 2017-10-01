/*	$Id$ */
/*
 * Copyright (c) 2017 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <sys/stat.h>
#include <sys/queue.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * A point in the parse sequence.
 * Used for remembering individual locations (for errors).
 */
struct	point {
	size_t		 line;
	size_t		 col;
};

/*
 * A file being parsed.
 */
struct	curparse {
	char		*b; /* file contents */
	size_t		 bsz; /* length of "b" */
	char		*filename; /* filename */
	size_t		 pos; /* current position */
	struct point	 point; /* current point */
};

/*
 * A macro pair.
 */
struct	macro {
	char		*key; /* lhs */
	char		*value; /* rhs */
	TAILQ_ENTRY(macro) entries;
};

/*
 * The current parse situation.
 * This maintains the stack of parsing files.
 */
struct	parse {
	TAILQ_HEAD(, macro) macros; /* current macros */
	struct curparse	*stack; /* parsed file stack */
	size_t		 stacksz; /* position in stack < max */
	size_t		 stackmax; /* stack memory size */
	struct curparse	*cur; /* current parsing file */
	struct cfgfile	*cfg; /* parsed configuration */
};

static void
logwarnx(const struct parse *p, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
static void
logdbg(const struct parse *p, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void
logwarnx(const struct parse *p, const char *fmt, ...)
{
	va_list	 ap;

	if (NULL != p && NULL != p->cur)
		fprintf(stderr, "%s:%zu:%zu: ",
			p->cur->filename,
			p->cur->point.line + 1,
			p->cur->point.col + 1);

	fputs("warning: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void
logdbg(const struct parse *p, const char *fmt, ...)
{
	va_list	 ap;

	if ( ! verbose)
		return;

	if (NULL != p && NULL != p->cur)
		fprintf(stderr, "%s:%zu:%zu: ",
			p->cur->filename,
			p->cur->point.line + 1,
			p->cur->point.col + 1);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/*
 * This isn't RFC1035 compliant, but does the bare minimum in making
 * sure that we don't get bogus domain names on the command line, which
 * might otherwise screw up our directory structure.
 * Also check to make sure that the domain name hasn't already appeared
 * as either an altname or top-level domain name.
 * Returns zero on failure, non-zero on success.
 */
static int
domain_valid(const struct parse *p, const char *cp)
{
	struct domain	*d;
	struct altname	*an;

	for ( ; '\0' != *cp; cp++)
		if (!('.' == *cp || '-' == *cp ||
		    '_' == *cp || isalnum((unsigned char)*cp))) {
			logwarnx(p, "invalid domain syntax");
			return (0);
		}

	TAILQ_FOREACH(d, &p->cfg->domains, entries) {
		if (0 == strcasecmp(d->name, cp)) {
			logwarnx(p, "duplicate domain name");
			return (0);
		}
		TAILQ_FOREACH(an, &d->altnames, entries)
			if (0 == strcasecmp(an->alt, cp)) {
				logwarnx(p, "duplicate domain name");
				return (0);
			}
	}

	return (1);
}

/*
 * Push the given "file" onto our stack of files to parse.
 * If this returns non-zero, the stack is clean of the new entry, but an
 * error has occurred and the system should exit.
 * This allows for zero-length files.
 * If the file has trailing slashes, the slashes are removed.
 */
static int
curparse_push(struct parse *p, const char *file)
{
	int	 	 fd = -1;
	struct stat	 st;
	char		*buf = NULL, *fn = NULL;
	ssize_t		 ssz;
	size_t		 i;
	void		*pp;

	assert((p->stacksz && NULL != p->cur) ||
	       (0 == p->stacksz && NULL == p->cur));

	for (i = 0; i < p->stacksz; i++)
		if (0 == strcmp(p->stack[i].filename, file)) {
			logwarnx(p, "%s: recursive parse", file);
			return(0);
		}

	if (-1 == (fd = open(file, O_RDONLY, 0))) {
		warn("%s", file);
		goto out;
	} else if (NULL == (fn = strdup(file))) {
		err(EXIT_FAILURE, NULL);
	} else if (-1 == fstat(fd, &st)) {
		warn("%s", file);
		goto out;
	} else if ((unsigned long long)st.st_size >= SIZE_MAX) {
		warnx("%s: too large", file);
		goto out;
	} else if (NULL == (buf = malloc(st.st_size))) {
		err(EXIT_FAILURE, NULL);
	} else if ((ssz = read(fd, buf, st.st_size)) < 0) {
		warn("%s", file);
		goto out;
	} else if (ssz != st.st_size) {
		warnx("%s: short read", file);
		goto out;
	}

	if (p->stacksz + 1 > p->stackmax) {
		pp = reallocarray(p->stack, 
			p->stackmax + 1, sizeof(struct curparse));
		if (NULL == pp) {
			warn(NULL);
			goto out;
		}
		p->stack = pp;
		p->stackmax++;
	}

	p->stack[p->stacksz].bsz = st.st_size;
	p->stack[p->stacksz].pos = 0;
	p->stack[p->stacksz].b = buf;
	p->stack[p->stacksz].filename = fn;
	p->cur = &p->stack[p->stacksz++];

	/* Don't let us have a terminating escape at eof. */

	while (p->cur->bsz &&
	    '\\' == p->cur->b[p->cur->bsz - 1]) {
		logwarnx(p, "%s: ignoring escape(s) at EOF", fn);
		p->cur->bsz--;
	}

	close(fd);
	return(1);
out:
	close(fd);
	free(buf);
	free(fn);
	return(0);
}

/*
 * Reverses a curparse_push().
 * Must not be called without any current parses.
 */
static void
curparse_pop(struct parse *p)
{

	assert(p->stacksz);
	assert(p->cur);
	p->stacksz--;
	free(p->stack[p->stacksz].b);
	free(p->stack[p->stacksz].filename);
	p->cur = 0 == p->stacksz ? 
		NULL : &p->stack[p->stacksz - 1];
}

/*
 * Advance to the next character in the current parse.
 * This DOES NOT touch the parse buffer, nor does it handle going after
 * the end of the current file.
 */
static void
parse_nextchar(struct parse *p)
{

	assert(NULL != p->cur);
	assert(p->cur->pos < p->cur->bsz);
	if ('\n' == p->cur->b[p->cur->pos++]) {
		p->cur->point.col = 0;
		p->cur->point.line++;
	} else
		p->cur->point.col++;
}

/*
 * See parse_nextchar() for a given number of invocations.
 */
static void
parse_nextchars(struct parse *p, size_t sz)
{
	size_t	 i;

	for (i = 0; i < sz; i++)
		parse_nextchar(p);
}

/*
 * Advance to the end of the current line.
 * This takes into account escaped newlines.
 * This will pop included files off the stack if we end at a file
 * boundary.
 */
static void
parse_eoln(struct parse *p)
{

	if (NULL == p->cur)
		return;

	while (p->cur->pos < p->cur->bsz)
		if ('\n' == p->cur->b[p->cur->pos] &&
		    (0 == p->cur->pos ||
		     '\\' != p->cur->b[p->cur->pos - 1])) {
			parse_nextchar(p);
			break;
		} else
			parse_nextchar(p);

	/* Collapse upward, if necessary. */

	while (NULL != p->cur && 
	       p->cur->pos == p->cur->bsz)
		curparse_pop(p);
}

/*
 * Advance past all white-space.
 * This includes escaped newlines and all interstitial comments.
 * This will pop included files off the stack as it goes.
 * This guarantees that it will be left in a valid non-comment state
 * (with bytes left in the curproc buffer) or with a NULL curpror.
 */
static void
parse_advance(struct parse *p)
{
	struct curparse	*cp;

again:
	while (NULL != (cp = p->cur)) {
		while (cp->pos < cp->bsz)
			/* 
			 * Note: we're guaranteed not to have a trailing
			 * escape w/o anything after, so no need to
			 * check for end of file.
			 */
			if (isspace((unsigned char)cp->b[cp->pos]))
				parse_nextchar(p);
			else if ('\\' == cp->b[cp->pos] &&
			         '\n' == cp->b[cp->pos + 1])
				parse_nextchars(p, 2);
			else
				break;
		if (cp->pos < cp->bsz)
			break;
		curparse_pop(p);
	}

	if (NULL == (cp = p->cur))
		return;
	assert(cp->pos < cp->bsz);

	/* 
	 * If we're at a comment, then run through the comment and make
	 * sure there's no trailing spaces.
	 */

	if ('#' == cp->b[cp->pos]) {
		parse_nextchar(p);
		parse_eoln(p);
		goto again;
	}
}

/*
 * Parse an identifier (non-quoted name) ending in "delim", whitespace,
 * or comment.
 * Returns the value, which may be zero-length, else NULL on failure.
 */
static char *
parse_ident(struct parse *p, char delim)
{
	struct curparse	*cp;
	size_t		 i, start, end;
	char		*val;

	cp = p->cur;
	assert(NULL != cp);
	assert(cp->pos < cp->bsz);

	start = cp->pos;
	while (cp->pos < cp->bsz &&
	       delim != cp->b[cp->pos] &&
	       '#' != cp->b[cp->pos] &&
	       (! isspace((unsigned char)cp->b[cp->pos]) ||
		('\n' == cp->b[cp->pos] && 
		 '\\' == cp->b[cp->pos - 1])))
		parse_nextchar(p);
	end = cp->pos;

	if (NULL == (val = malloc((end - start) + 1)))
		err(EXIT_FAILURE, NULL);

	for (i = 0; start < end; start++) {
		if ('\\' == cp->b[start] &&
		    '\n' == cp->b[start + 1]) {
			start++;
			continue;
		}
		val[i++] = cp->b[start];
	}
	val[i] = '\0';
	return(val);
}

/*
 * Parse an identifier (possibly-quoted name) ending, if not quoted, in
 * "delim" (or EOF if not wishing a delim), whitespace, or comment.
 * If "expand" is set, non-quoted strings starting with a '$' are
 * replaced, if found, with the macro value.
 * Returns the value, which may be zero-length, else NULL on failure.
 */
static char *
parse_value(struct parse *p, char delim, int expand)
{
	struct curparse	*cp;
	struct macro	*m;
	size_t		 i, start, end;
	char		*val;
	int		 quoted = 0, macro = 0;

	if (NULL == (cp = p->cur)) {
		logwarnx(p, "expected quoted string or identifier");
		return(NULL);
	}
	assert(cp->pos < cp->bsz);

	quoted = '"' == cp->b[cp->pos];
	macro = '$' == cp->b[cp->pos];

	if (macro && ! expand) {
		logwarnx(p, "macro expansion prohibited");
		return(NULL);
	}

	if ('"' == cp->b[cp->pos]) {
		parse_nextchar(p);
		start = cp->pos;
		while (cp->pos < cp->bsz && '"' != cp->b[cp->pos])
			parse_nextchar(p);
		if (cp->pos == cp->bsz) {
			logwarnx(p, "unexpected eof");
			return(NULL);
		}
		end = cp->pos;
		parse_nextchar(p);
	} else if (EOF != delim) {
		start = cp->pos;
		while (cp->pos < cp->bsz &&
		       delim != cp->b[cp->pos] &&
		       '#' != cp->b[cp->pos] &&
		       (! isspace((unsigned char)cp->b[cp->pos]) ||
			('\n' == cp->b[cp->pos] && 
			 '\\' == cp->b[cp->pos - 1])))
			parse_nextchar(p);
		end = cp->pos;
	} else {
		start = cp->pos;
		while (cp->pos < cp->bsz &&
		       '#' != cp->b[cp->pos] &&
		       (! isspace((unsigned char)cp->b[cp->pos]) ||
			('\n' == cp->b[cp->pos] && 
			 '\\' == cp->b[cp->pos - 1])))
			parse_nextchar(p);
		end = cp->pos;
	}

	if (0 == (end - start) ||
	    (macro && 1 == (end - start))) {
		logwarnx(p, "zero-length value");
		return(NULL);
	}

	if (NULL == (val = malloc((end - start) + 1)))
		err(EXIT_FAILURE, NULL);

	for (i = 0; start < end; start++) {
		if ('\\' == cp->b[start] &&
		    '\n' == cp->b[start + 1]) {
			start++;
			continue;
		}
		val[i++] = cp->b[start];
	}
	val[i] = '\0';

	/* Look us up in our macro queue, if applicable. */

	if (macro && expand) {
		assert( ! quoted);
		TAILQ_FOREACH(m, &p->macros, entries)
			if (0 == strcmp(m->key, val + 1))
				break;
		free(val);
		val = NULL;
		if (NULL == m)
			logwarnx(p, "macro not found");
		else if (NULL == (val = strdup(m->value)))
			err(EXIT_FAILURE, NULL);
	}

	return(val);
}

/*
 * Try to match "key" in the current parse file.
 * Return zero if the match fails (including that there's no current
 * file being parsed) or non-zero on success.
 * On success, the current position is advance to the end of the matched
 * token.
 */
static int
parse_match(struct parse *p, const char *key)
{
	size_t		 sz, len;
	struct curparse	*cp;

	if (NULL == (cp = p->cur))
		return(0);

	sz = strlen(key);

	if ((len = cp->bsz - cp->pos) < sz)
		return(0);

	if (strncasecmp(&cp->b[cp->pos], key, sz))
		return(0);

	if (len == sz || 
	    isspace((unsigned char)cp->b[cp->pos + sz])) {
		parse_nextchars(p, sz);
		return(1);
	}

	return(0);
}

/*
 * Parse a block of alternative names from the '{' (must be at the
 * buffer point) up to and including the terminating '}';
 * Return zero on failure and non-zero on success.
 */
static int
parse_altnames(struct parse *p, struct domain *d)
{
	struct curparse	*cp;
	struct altname	*an;
	char		*v;

	if (NULL == (cp = p->cur) || '{' != cp->b[cp->pos]) {
		logwarnx(p, "expected \'{\'");
		return(0);
	}

	parse_nextchar(p);
	parse_advance(p);
	while (NULL != p->cur && '}' != p->cur->b[p->cur->pos]) {
		if (NULL == (v = parse_value(p, '}', 1))) {
			return(0);
		} else if ( ! domain_valid(p, v)) {
			free(v);
			return(0);
		}
		logdbg(p, "altname for %s: %s", d->name, v);
		if (NULL == (an = calloc(1, sizeof(struct altname))))
			err(EXIT_FAILURE, NULL);
		TAILQ_INSERT_TAIL(&d->altnames, an, entries);
		an->alt = v;
		parse_advance(p);
	}
	if (NULL == p->cur) {
		logwarnx(p, "expected \'}\'");
		return(0);
	}

	parse_nextchar(p);
	return(1);
}

/*
 * Parse a domain block.
 * Expects a valid domain block statement.
 * Return zero on failure and non-zero on succes.
 */
static int
parse_domain_block(struct parse *p, struct domain *d)
{
	struct altname	*an;

	if (parse_match(p, "alternative")) {
		parse_advance(p);
		if ( ! parse_match(p, "names")) {
			logwarnx(p, "expected \'names\'");
			return(0);
		} 
		parse_advance(p);
		if ( ! TAILQ_EMPTY(&d->altnames))
			logwarnx(p, "alternative names redefined");
		while (NULL != (an = TAILQ_FIRST(&d->altnames))) {
			TAILQ_REMOVE(&d->altnames, an, entries);
			free(an->alt);
			free(an);
		}
		if ( ! parse_altnames(p, d))
			return(0);
	} else if (parse_match(p, "domain")) {
		parse_advance(p);
		if (parse_match(p, "key")) {
			parse_advance(p);
			if (NULL == (d->key = parse_value(p, '}', 1)))
				return(0);
		} else if (parse_match(p, "certificate")) {
			parse_advance(p);
			if (NULL != d->cert)
				logwarnx(p, "certificate redefined");
			free(d->cert);
			if (NULL == (d->cert = parse_value(p, '}', 1)))
				return(0);
			logdbg(p, "certificate: %s", d->key);
		} else if (parse_match(p, "chain")) {
			parse_advance(p);
			if ( ! parse_match(p, "certificate")) {
				logwarnx(p, "expected \'certificate\'");
				return(0);
			}
			parse_advance(p);
			if (NULL != d->chain)
				logwarnx(p, "chain "
					"certificate redefined");
			free(d->chain);
			if (NULL == (d->chain = parse_value(p, '}', 1)))
				return(0);
			logdbg(p, "chain: %s", d->chain);
		} else if (parse_match(p, "full")) {
			parse_advance(p);
			if ( ! parse_match(p, "chain")) {
				logwarnx(p, "expected \'chain\'");
				return(0);
			}
			parse_advance(p);
			if ( ! parse_match(p, "certificate")) {
				logwarnx(p, "expected \'certificate\'");
				return(0);
			}
			parse_advance(p);
			if (NULL != d->full)
				logwarnx(p, "full chain "
					"certificate redefined");
			free(d->full);
			if (NULL == (d->full = parse_value(p, '}', 1)))
				return(0);
			logdbg(p, "full: %s", d->full);
		} else {
			logwarnx(p, "expected key type");
			return(0);
		}
	} else if (parse_match(p, "sign")) {
		parse_advance(p);
		if ( ! parse_match(p, "with")) {
			logwarnx(p, "expected \'with\'");
			return(0);
		} 
		parse_advance(p);
		if (NULL != d->authname)
			logwarnx(p, "sign with redefined");
		free(d->authname);
		if (NULL == (d->authname = parse_value(p, '}', 1)))
			return(0);
		logdbg(p, "auth: %s", d->authname);
	} else if (parse_match(p, "challengedir")) {
		parse_advance(p);
		if (NULL != d->cdir)
			logwarnx(p, "challengedir redefined");
		free(d->cdir);
		if (NULL == (d->cdir = parse_value(p, '}', 1)))
			return(0);
		logdbg(p, "challengedir: %s", d->cdir);
	} else {
		logwarnx(p, "expected domain entry");
		return(0);
	}

	parse_advance(p);
	return(1);
}

/*
 * Parse the domain block-level element:
 *   "domain" name "{" ... "}" 
 *  The domain name must be well-formed and not be a duplicate of a
 *  prior domain name invocation.
 */
static int
parse_domain(struct parse *p)
{
	struct curparse	*cp;
	struct domain	*d;
	char		*name, *v;

	parse_advance(p);

	if (NULL == (cp = p->cur)) {
		logwarnx(p, "expected domain name");
		return(0);
	} else if (NULL == (name = parse_ident(p, '{'))) {
		return(0);
	} else if ( ! domain_valid(p, name)) {
		free(name);
		return(0);
	}

	parse_advance(p);
	if (NULL == (cp = p->cur) || '{' != cp->b[cp->pos]) {
		logwarnx(p, "expected \'{\'");
		free(name);
		return(0);
	}

	logdbg(p, "parsing domain: %s", name);

	if (NULL == (d = calloc(1, sizeof(struct domain))))
		err(EXIT_FAILURE, NULL);
	d->name = name;
	TAILQ_INSERT_TAIL(&p->cfg->domains, d, entries);
	TAILQ_INIT(&d->altnames);

	parse_nextchar(p);
	parse_advance(p);

	/* Parse domain name block. */

	while (NULL != p->cur && '}' != p->cur->b[p->cur->pos])
		if ( ! parse_domain_block(p, d))
			return(0);

	if (NULL == p->cur) {
		logwarnx(p, "expected \'}\'");
		return(0);
	}
	parse_nextchar(p);

	if (NULL == d->authname) {
		logwarnx(p, "sign as required");
		return(0);
	} else if (NULL == d->cdir) {
		logwarnx(p, "challengedir required");
		return(0);
	} else if (NULL == d->key) {
		logwarnx(p, "domain key required");
		return(0);
	} else if (NULL == d->cert) {
		logwarnx(p, "domain certificate required");
		return(0);
	} else if ('/' != d->cert[0]) {
		logwarnx(p, "domain certificate not an absolute path");
		return(0);
	} else if ('/' == d->cert[strlen(d->cert) - 1]) {
		logwarnx(p, "domain certificate is a directory");
		return(0);
	} else if (NULL == d->chain) {
		logwarnx(p, "domain chain certificate required");
		return(0);
	} else if (NULL == d->full) {
		logwarnx(p, "domain full chain certificate required");
		return(0);
	}

	/* 
	 * Get the directory part of our certificate file.
	 * Then re-write our certificate to be relative. 
	 */

	assert(NULL == d->dir);
	if (NULL == (d->dir = strdup(d->cert)))
		err(EXIT_FAILURE, NULL);

	v = strrchr(d->dir, '/');
	assert(NULL != v);
	*v = '\0';

	free(d->cert);
	if (NULL == (d->cert = strdup(&v[1])))
		err(EXIT_FAILURE, NULL);

	logdbg(p, "certificate directory: %s", d->dir);
	logdbg(p, "certificate (relative): %s", d->cert);

	/*
	 * If not already relative paths, re-write the chain and full
	 * chain components to be relative to the certificate directory.
	 * Validate them along the way.
	 */

	if ('/' == d->chain[0] &&
   	    strncmp(d->chain, d->dir, strlen(d->dir))) {
		logwarnx(p, "certificate chain "
			"not in certificate directory");
		return(0);
	} else if ('/' == d->chain[0]) {
		v = strdup(d->chain + strlen(d->dir) + 1);
		if (NULL == v)
			err(EXIT_FAILURE, NULL);
		free(d->chain);
		d->chain = v;
		logdbg(p, "certificate chain (relative): %s", d->chain);
	}

	if ('/' == d->full[0] &&
   	    strncmp(d->full, d->dir, strlen(d->dir))) {
		logwarnx(p, "certificate full chain "
			"not in certificate directory");
		return(0);
	} else if ('/' == d->full[0]) {
		v = strdup(d->full + strlen(d->dir) + 1);
		if (NULL == v)
			err(EXIT_FAILURE, NULL);
		free(d->full);
		d->full = v;
		logdbg(p, "certificate full (relative): %s", d->full);
	}

	return(1);
}

static int
parse_macro(struct parse *p)
{
	struct curparse	*cp;
	struct macro	*m;
	int		 repl;
	char		*key, *value;

	cp = p->cur;
	assert(NULL != cp);

	if (NULL == (key = parse_ident(p, '=')))
		return(0);

	TAILQ_FOREACH(m, &p->macros, entries)
		if (0 == strcmp(m->key, key))
			break;

	repl = NULL != m;

	/* 
	 * Look up the macro.
	 * If it already exists, then use its entry; otherwise, create
	 * and install a new one.
	 */

	if (NULL == m) {
		if (NULL == (m = calloc(1, sizeof(struct macro))))
			err(EXIT_FAILURE, NULL);
		TAILQ_INSERT_TAIL(&p->macros, m, entries);
		m->key = key;
	} else
		free(key);

	parse_advance(p);
	if (NULL == (cp = p->cur) || '=' != cp->b[cp->pos]) {
		logwarnx(p, "expected \'=\'");
		return(0);
	}

	parse_nextchar(p);
	parse_advance(p);
	if (NULL == (value = parse_value(p, EOF, 0)))
		return(0);

	free(m->value);
	m->value = value;

	logdbg(p, "%s macro: [%s]=[%s]", repl ? 
		"replace" : "new", m->key, m->value);
	return(1);
}

/*
 * Parse an authority block.
 * Expects a valid authority block statement.
 * Return zero on failure and non-zero on succes.
 */
static int
parse_authority_block(struct parse *p, struct auth *a)
{

	if (parse_match(p, "account")) {
		parse_advance(p);
		if ( ! parse_match(p, "key")) {
			logwarnx(p, "expected \'key\'");
			return(0);
		}
		parse_advance(p);
		if (NULL != a->accountkey)
			logwarnx(p, "account key redefined");
		free(a->accountkey);
		if (NULL == (a->accountkey = parse_value(p, '}', 1)))
			return(0);
		logdbg(p, "account key: %s", a->accountkey);
	} else if (parse_match(p, "agreement")) {
		parse_advance(p);
		if ( ! parse_match(p, "url")) {
			logwarnx(p, "expected \'url\'");
			return(0);
		}
		parse_advance(p);
		if (NULL != a->agreement)
			logwarnx(p, "agreement url redefined");
		free(a->agreement);
		if (NULL == (a->agreement = parse_value(p, '}', 1)))
			return(0);
		logdbg(p, "agreement: %s", a->agreement);
	} else if (parse_match(p, "api")) {
		parse_advance(p);
		if ( ! parse_match(p, "url")) {
			logwarnx(p, "expected \'url\'");
			return(0);
		}
		parse_advance(p);
		if (NULL != a->api)
			logwarnx(p, "api url redefined");
		free(a->api);
		if (NULL == (a->api = parse_value(p, '}', 1)))
			return(0);
		logdbg(p, "api: %s", a->api);
	} else {
		logwarnx(p, "expected authority entry");
		return(0);
	}

	parse_advance(p);
	return(1);
}

/*
 * Parse a top-level authority block:
 *   "authority" name "{" ... "}"
 */
static int
parse_authority(struct parse *p)
{
	struct curparse	*cp;
	struct auth	*a;

	parse_advance(p);

	if (NULL == (cp = p->cur)) {
		logwarnx(p, "expected authority name");
		return(0);
	}

	if (NULL == (a = calloc(1, sizeof(struct auth))))
		err(EXIT_FAILURE, NULL);
	TAILQ_INSERT_TAIL(&p->cfg->auths, a, entries);

	if (NULL == (a->name = parse_ident(p, '{')))
		return(0);

	logdbg(p, "new authority: %s", a->name);

	parse_advance(p);
	if (NULL == (cp = p->cur) || '{' != cp->b[cp->pos]) {
		logwarnx(p, "expected \'{\'");
		return(0);
	}

	parse_nextchar(p);
	parse_advance(p);

	while (NULL != p->cur && '}' != p->cur->b[p->cur->pos])
		if ( ! parse_authority_block(p, a))
			return(0);

	if (NULL == p->cur) {
		logwarnx(p, "expected \'}\'");
		return(0);
	}
	parse_nextchar(p);

	if (NULL == a->accountkey)
		logwarnx(p, "account key required");
	else if (NULL == a->agreement)
		logwarnx(p, "agreement url required");
	else if (NULL == a->api)
		logwarnx(p, "api url required");
	else
		return(1);

	return(0);
}

static int
parse_include(struct parse *p)
{
	char		*v;
	int		 rc;

	parse_advance(p);
	if (NULL == (v = parse_value(p, EOF, 0)))
		return(0);

	logdbg(p, "new inclusion: %s", v);
	rc = curparse_push(p, v);
	free(v);
	return(rc);
}

/*
 * Top-level parse.
 * This can either be a macro (assignment), a domain, or an authority.
 * Calls through to the completion of each block.
 * Return zero if the current block parse fails, otherwise non-zero.
 * Returns non-zero on end of file.
 */
static int
parse_block(struct parse *p)
{

	parse_advance(p);

	if (NULL == p->cur)
		return(1);

	if (parse_match(p, "domain"))
		return(parse_domain(p));
	else if (parse_match(p, "authority"))
		return(parse_authority(p));
	else if (parse_match(p, "include"))
		return(parse_include(p));

	return(parse_macro(p));
}

/*
 * Free a configuration parsed with cfg_parse().
 * This is safe to call with a NULL value.
 */
void
cfg_free(struct cfgfile *p)
{
	struct auth	*a;
	struct domain	*d;
	struct altname	*an;

	if (NULL == p)
		return;

	while (NULL != (a = TAILQ_FIRST(&p->auths))) {
		TAILQ_REMOVE(&p->auths, a, entries);
		free(a->name);
		free(a->accountkey);
		free(a->agreement);
		free(a->api);
		free(a);
	}

	while (NULL != (d = TAILQ_FIRST(&p->domains))) {
		TAILQ_REMOVE(&p->domains, d, entries);
		while (NULL != (an = TAILQ_FIRST(&d->altnames))) {
			TAILQ_REMOVE(&d->altnames, an, entries);
			free(an->alt);
			free(an);
		}
		free(d->dir);
		free(d->name);
		free(d->authname);
		free(d->cdir);
		free(d->key);
		free(d->cert);
		free(d->chain);
		free(d->full);
		free(d);
	}

	free(p);
}

/*
 * Deallocate the resources used during a parse.
 * This does not touch the "cfg" pointer.
 */
static void
parse_free(struct parse *p)
{
	struct macro	*m;

	while (NULL != (m = TAILQ_FIRST(&p->macros))) {
		TAILQ_REMOVE(&p->macros, m, entries);
		free(m->key);
		free(m->value);
		free(m);
	}

	while (p->stacksz)
		curparse_pop(p);

	free(p->stack);
}

const struct domain *
cfg_domain(const struct cfgfile *p, const char *name)
{
	const struct domain *d;

	TAILQ_FOREACH(d, &p->domains, entries) 
		if (0 == strcasecmp(d->name, name))
			return(d);

	return(NULL);
}

/*
 * Parse the file "file" and all of its nested inclusions.
 * Returns the parsed configuration contents or NULL on error.
 * This must be freed with cfg_free().
 */
struct cfgfile *
cfg_parse(const char *file)
{
	struct parse	 p;
	struct domain	*d;
	struct auth	*a;

	memset(&p, 0, sizeof(struct parse));

	TAILQ_INIT(&p.macros);

	if (NULL == (p.cfg = calloc(1, sizeof(struct cfgfile))))
		err(EXIT_FAILURE, NULL);

	TAILQ_INIT(&p.cfg->domains);
	TAILQ_INIT(&p.cfg->auths);

	/* Start with the given file. */

	if ( ! curparse_push(&p, file))
		goto out;

	assert(NULL != p.cur);
	while (NULL != p.cur)
		if ( ! parse_block(&p))
			goto out;

	/* On proper exit, we should have no file in our buffer. */

	assert(NULL == p.cur && 0 == p.stacksz);

	TAILQ_FOREACH(d, &p.cfg->domains, entries) {
		TAILQ_FOREACH(a, &p.cfg->auths, entries) {
			if (0 == strcmp(a->name, d->authname)) {
				d->auth = a;
				break;
			}
		}
		if (NULL == a) {
			logwarnx(NULL, "authority not found");
			goto out;
		}
		assert(NULL != d->auth);
	}

	parse_free(&p);
	return(p.cfg);
out:
	parse_free(&p);
	cfg_free(p.cfg);
	return(NULL);
}

#if 0
/*
 * TESTING UTILITY.
 */
int
main(int argc, char *argv[])
{
	int	 	 i;
	struct cfgfile  *p;

	for (i = 1; i < argc; i++) {
		if (NULL == (p = cfg_parse(argv[i]))) {
			warnx("BAD");
			return(EXIT_FAILURE);
		}
		cfg_free(p);
	}

	return(EXIT_SUCCESS);
}
#endif
