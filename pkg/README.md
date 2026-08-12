# Packaging

The upstream `Makefile` is BSD make and takes `PREFIX`, `LOCALBASE`,
`SYSCONFDIR`, `SBINDIR`, `RCDDIR`, `EXAMPLESDIR`, `VARBASE` and `DESTDIR`, so
each collection's package is thin.

| Collection | Directory | Category |
| --- | --- | --- |
| pkgsrc (NetBSD) | [`pkgsrc/security/stnsd`](pkgsrc/security/stnsd) | `security` |
| FreeBSD ports | [`freebsd/security/stnsd`](freebsd/security/stnsd) | `security` |
| DragonFly DPorts | the FreeBSD port, unchanged | |

Three details are worth knowing.

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

Neither `distinfo` is checked in, because both are generated from a release
tarball:

```sh
cd pkgsrc/security/stnsd && make makesum        # pkgsrc
cd freebsd/security/stnsd && make makesum       # ports and DPorts
```
