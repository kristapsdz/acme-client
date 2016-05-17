## Synopsis

*letskencrypt* is yet another [Let's Encrypt](https://letsencrypt.org)
client, but one with a strong focus on security.  **It is still under
development**.  See
[letskencrypt.1](http://kristaps.bsd.lv/letskencrypt/letskencrypt.1.html)
for complete documentation and functionality.

It supports the following operations:

* Account registration (see the -**n** flag).
* Domain certificate signing.

This repository mirrors the master CVS repository: any source changes
will occur on the master and be pushed periodically to GitHub.  If you
have bug reports or patches, either file them here or e-mail them to me.
Feature requests will be ignored unless joined by a patch.

The system is registered as a [Coverity
project](https://scan.coverity.com/projects/letskencrypt).

## Installation

To use *letskencrypt*, just download and run `make` and `make install`
in the usual way.  

If you're running on Linux, you'll need to edit the [Makefile](Makefile)
as noted.  I only tested this on Debian.  It compiles on both OpenBSD
and Mac OS X without any modifications.

The software has several compile-time dependencies:
[OpenSSL](https://openssl.org) or [LibreSSL](http://www.libressl.org),
[libcurl](https://curl.haxx.se/libcurl), and
[json-c](https://github.com/json-c/json-c).  For Linux, you'll also need
[libbsd](https://libbsd.freedesktop.org).

The json-c part needs [this
patch](https://marc.info/?l=openbsd-ports&m=146282275327867&w=2).

## Implementation

When *letskencrypt* starts, it forks itself (in [main.c](main.c)) into
several isolated components, each with a specific job to do, each
communicating with other components over socketpairs.  This separation
protects your system and your account and domain private keys.

Each component is isolated as per its function and resource
requirements.  Sandbox, in this regard, refers to using
[pledge(2)](http://man.openbsd.org/pledge.2) on OpenBSD or
sandbox\_init(3) on Mac OS X.  Jailing changes the file-system with
[chroot(2)](http://man.openbsd.org/chroot.2).  Unless otherwise noting,
jailing is usually to an empty, harmless directory.  Privilege-dropping
is changing from root to a "less-priviledged" user, usually user
"nobody".

![graph](http://kristaps.bsd.lv/letskencrypt/letskencrypt.png)

The account and key processes manage your account and domain private
keys, respectively.  The former, [acctproc.c](acctproc.c), uses the key
to sign messages; the latter, [keyproc.c](keyproc.c), produces the X509
certificate request.  Both of these are sandboxed, jailed, and
privilege-dropped after opening the keys.

The network processor, [netproc.c](netproc.c), actually interfaces with
the Let's Encrypt server.  It's also sandboxed, jailed, and
privilege-dropped, though allowed to make network connections.  It talks
to the DNS process, [dnsproc.c](dnsproc.c), to resolve names.  The DNS
process is also sandboxed and privilege-dropped, but not jailed.

The challenge processor, [chngproc.c](chngproc.c), coordinates challenge
responses made by the Let's Encrypt server.  It is jailed in the
challenge response directory, sandboxed except for touching files, and
not privilege separated.  The certificate and file processor,
[certproc.c](certproc.c) and [fileproc.c](fileproc.c), are a pipeline to
serialise signed certificates to your file-system.  The former is
jailed, sandboxed, and privilege-separated; the latter is only jailed to
the certificate directory.

Lastly, the poorly-named revocation process,
[revokeproc.c](revokeproc.c), attempts to read the certificate on file
and determine its expected expiration.

The software has been designed with [OpenBSD](http://www.openbsd.org) in
mind, though it works with reduced security on Mac OS X and Linux.  This
is due to the security-hostile focus of both systems: the sandbox
facility in Mac OS X is very weak (and getting weaker); and while it
exists on Linux, it's too complicated to use.  Moreover, the DNS
resolution on both systems is run almost no protection but for dropping
privileges.

In short, I strongly discourage using any systems but OpenBSD.

By default, *letskencrypt* talks only to the [staging
server](https://community.letsencrypt.org/t/testing-against-the-lets-encrypt-staging-environment/6763).
You'll need to edit [netproc.c](netproc.c) if you'd prefer the real
deal, but the system is still kinda young to be doing so.

It's getting there...

## License

All sources use the ISC (like OpenBSD) license.
See the [LICENSE.md](LICENSE.md) file for details.
