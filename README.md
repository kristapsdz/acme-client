## Synopsis

letskencrypt is a [Let's Encrypt](https://letsencrypt.org) client with a
strong focus on security: file-system jails, privilege separation, and
sandboxing.
See [letskencrypt.1](letskencrypt.1) for complete documentation.
This repository mirrors the master CVS repository: any source changes
will occur on the master and be pushed periodically to GitHub.

By default, this talks only to the [staging
server](https://community.letsencrypt.org/t/testing-against-the-lets-encrypt-staging-environment/6763).
You'll need to edit netproc.c if you'd prefer the real deal, but the
system is still a little young to be doing so.

## Installation

To use this tool, just download and run `make` and `make install` in
the usual way.  The software has been designed with
[OpenBSD](http://www.openbsd.org) in mind, though it works with reduced
security on Mac OS X and Linux.  
This is due to the chroot-unfriendly way that DNS lookups occur in both
systems.
Moreover, the sandbox facility in Mac OS X is very weak; and while it
exists on Linux, it's too complicated to use.  Caveat emptor.

In short, I don't recommend using any platform but OpenBSD.

If you're trying to run on Linux, you'll need to edit the
[Makefile](Makefile) as noted.  I only tested this on Debian.

The software has several compile-time dependencies:
[OpenSSL](https://openssl.org) or [LibreSSL](http://www.libressl.org),
[libcurl](https://curl.haxx.se/libcurl), and
[json-c](https://github.com/json-c/json-c).  For Linux, you'll also need
[libbsd](https://libbsd.freedesktop.org).

The json-c part needs [this
patch](https://marc.info/?l=openbsd-ports&m=146282275327867&w=2).

## License

All sources use the ISC (like OpenBSD) license.
See the [LICENSE.md](LICENSE.md) file for details.
