## Synopsis

*letskencrypt* is yet another [Let's Encrypt](https://letsencrypt.org)
client, but one with a strong focus on security.  **It is still under
development**.

Please see
[kristaps.bsd.lv/letskencrypt](https://kristaps.bsd.lv/letskencrypt) for
stable releases: this repository is for current development of the the
[OpenBSD](http://www.openbsd.org) version, requiring requires OpenBSD
5.9 or greater.  For the portable version (Mac OS X, Linux, FreeBSD,
older OpenBSD) see
[letskencrypt-portable](https://github.com/kristapsdz/letskencrypt-portable).

This repository mirrors the master CVS repository: any source changes
will occur on the master and be pushed periodically to GitHub.  If you
have bug reports or patches, either file them here or e-mail them to me.
Feature requests will be ignored unless joined by a patch.

## License

Sources use the ISC (like OpenBSD) license.
See the [LICENSE.md](LICENSE.md) file for details.

The [jsmn.c](jsmn.c) and [jsmn.h](jsmn.h) files use the MIT license.
See [https://github.com/zserge/jsmn](https://github.com/zserge/jsmn) for
details.
