## Synopsis

letskencrypt is a [Let's Encrypt](https://letsencrypt.org) client with a
strong focus on security.
This repository mirrors the master CVS repository: any changes will
occur on the master and be pushed periodically to GitHub.

See [letsencrypt.1](blob/master/letsencrypt.1) for complete documentation.

## Installation

To use letskencrypt, just download and run `make` and `make install` in
the usual way.
The software has been designed with [OpenBSD](http://www.openbsd.org) in
mind, though it works with reduced security on Mac OS X and
on Linux with even more reduced security.
This is due to the weaknesses or complexities, respectively, of these
systems' sandboxing mechanisms.

I can't recommend using any platform but OpenBSD.

If you're running on Linux, youll need to edit the
[Makefile](blob/master/Makefile) as noted.  I only tested this on
Debian.

The software has several compile-time dependencies:
[OpenSSL](https://openssl.org) or [LibreSSL](http://www.libressl.org), 
[libcurl](https://curl.haxx.se/libcurl), and
[json-c](https://github.com/json-c/json-c).
For Linux, you'll also need 
[libbsd](https://libbsd.freedesktop.org).

## License

All sources use the ISC (like OpenBSD) license.
See the [LICENSE.md](LICENSE.md) file for details.
