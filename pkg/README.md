# Packaging

The upstream `Makefile` is BSD make and takes `PREFIX`, `LOCALBASE`,
`SYSCONFDIR`, `SBINDIR`, `RCDDIR`, `EXAMPLESDIR`, `VARBASE` and `DESTDIR`, so
each collection's package is thin.

| Collection | Directory | Category |
| --- | --- | --- |
| pkgsrc (NetBSD) | [`pkgsrc/security/stnsd`](pkgsrc/security/stnsd) | `security` |
| FreeBSD ports | [`ports/security/stnsd`](ports/security/stnsd) | `security` |
| DragonFly DPorts | the FreeBSD port, unchanged | |

Four details are worth knowing.

**There is no `MESSAGE` file.** pkgsrc has retired them — `pkglint` now calls
one an error, not a style point — so a package no longer gets to lecture the
administrator at install time. What used to go there (enable it in `rc.conf`,
keep the configuration mode 0600) lives in the README and the runbook instead.

**The rc.d script is built, not shipped twice.** `rc.d/stnsd.in` is the only
copy; `make` substitutes the paths into it, and — because the two systems
disagree about what the rc.conf switch is called — the name of the variable as
well, `stnsd` on NetBSD and `stnsd_enable` on FreeBSD. It is then installed
where each system keeps such things: `share/examples/rc.d` on NetBSD, which is
exactly where pkgsrc's `RCD_SCRIPTS` looks for it, and `etc/rc.d` on FreeBSD,
which is where a port's script belongs. Neither package needs a `files/`
directory.

**The configuration is installed mode 0600, root owned.** It holds password
hashes. pkgsrc has `CONF_FILES_PERMS` for exactly this; the port relies on
`@sample`, whose copy inherits the sample's mode, so the sample itself carries
no secret and the message tells the administrator what to do.

**`PKG_SYSCONFSUBDIR` is `stns/server`,** where
[nss_stns](https://github.com/zakinko/nss_stns) uses `stns/client`, so that one
machine can be both without the two files colliding.

## Checksums

Both `distinfo` files are checked in and describe the release tarball github
builds from the `v0.1.0` tag. Without them neither package can be installed at
all, which makes "installable" a thing to test rather than to assert: the
Packaging workflow fetches that tarball in a VM, checks it against these
checksums, builds the package, installs it, starts the daemon through rc.d and
deinstalls it again.

Regenerate them after a version bump, from inside each collection's tree:

```sh
cd pkgsrc/security/stnsd && make makesum        # pkgsrc
cd ports/security/stnsd  && make makesum        # ports and DPorts
```

The two disagree about everything except the idea: pkgsrc records BLAKE2s,
SHA512 and a size for `stnsd-0.1.0.tar.gz`, ports records a timestamp, a
SHA256 and a size for `zakinko-stnsd-v0.1.0_GH0.tar.gz`, which is the same
bytes under the name each framework gives it.
