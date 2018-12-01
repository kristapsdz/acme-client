**Attention: *acme-client* has moved permanently into OpenBSD.  It is
not maintained here any more.  If you're using this repository---which
is intended for OpenBSD anyway---you're using old code.  Please use the
local version instead!**

If you'd like to contribute to *acme-client*, please submit patches to
the OpenBSD tree.

## Synopsis

*acme-client* is yet another
[ACME](https://letsencrypt.github.io/acme-spec/) client, specifically
for [Let's Encrypt](https://letsencrypt.org), but one with a strong
focus on security. 

It was originally named *letskencrypt* until version 0.1.11.

Please see
[kristaps.bsd.lv/acme-client](https://kristaps.bsd.lv/acme-client) for
stable releases: this repository is for current development of the
[OpenBSD](http://www.openbsd.org) version, requiring OpenBSD 5.9 or
greater.  For the portable version (Mac OS X, Linux, FreeBSD, NetBSD) see
[acme-client-portable](https://github.com/kristapsdz/acme-client-portable).

**Note**: this is *not* the same as the OpenBSD version of *acme-client*.

This repository mirrors the master CVS repository: any source changes
will occur in the master and be pushed periodically to GitHub.  If you
have bug reports or patches, either file them here or e-mail them to me.

**Feature requests will be ignored unless joined by a patch.**  If
there's something you need, I'm happy to work with you to make it
happen.  If you really need it, I'm available for contract (contact me
by e-mail).

## License

Sources use the ISC (like OpenBSD) license.
See the [LICENSE.md](LICENSE.md) file for details.

The [jsmn.c](jsmn.c) and [jsmn.h](jsmn.h) files use the MIT license.
See [https://github.com/zserge/jsmn](https://github.com/zserge/jsmn) for
details.
