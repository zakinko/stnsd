# stnsd

A small [STNS](https://stns.jp) API server for **NetBSD**, **FreeBSD** and
**DragonFly BSD**. It serves users, groups and their SSH public keys from a
TOML file, over the same v1 API upstream STNS serves, in C, over HTTP or TLS,
with nothing outside the base system behind it.

```console
# stnsd -t
/usr/pkg/etc/stns/server/stns.conf: 12 users, 4 groups, port 1104
# stnsd
# curl -s localhost:1104/v1/users?name=alice
[{"id":1001,"name":"alice","password":"","group_id":1001,"directory":"/home/alice","shell":"/bin/sh","gecos":"","keys":["ssh-ed25519 AAAA... alice"]}]
```

## Why, when upstream exists

Upstream's server is Go, it is portable Go, and it builds and runs on NetBSD
unmodified — I checked before writing a line of this. If Go suits you, use it:
it has backends this does not, and it is the definition of the protocol.

This exists for the machines where that is not an option. Go has been taught
about `netbsd/amd64`, `arm64`, `386` and `arm`; NetBSD itself runs on some
sixty ports, and on the rest — vax, m68k, sparc, sh3, alpha, hppa — there is no
Go and there will not be one. A directory client that runs everywhere and a
directory server that runs on four architectures is an odd pairing. This closes
it, at 40KB instead of 40MB, with a C compiler as the only thing you need to
build it.

The client side is [nss_stns](https://github.com/zakinko/nss_stns).

## Compatibility

The API is upstream's, and "compatible" here is a claim under test rather than
an intention. `make compat` starts this server and upstream's side by side on
the same `stns.conf` and compares every answer — status, body and headers,
byte for byte — including the parts nobody would think to write down:

- `"keys":null` for a user with no key list against `"keys":[]` for an empty
  one, which is a Go nil slice against an empty slice, visible on the wire
- `<`, `>` and `&` escaped as `<`, `>`, `&`, which is Go's
  encoder being cautious about HTML rather than anything JSON requires
- the order of a merged key list, which comes out sorted because upstream's
  `uniqStrings` sorts, while an unmerged one keeps the file's order
- `{}` for a lookup that found nothing, `{"message":"Not Found"}` for a path
  that does not exist — one is STNS's error type, the other is the router's

44 comparisons pass, six of them over TLS, which upstream serves from the
same two configuration keys. Two disagreements are deliberate and listed in
[`tests/compat.sh`](tests/compat.sh): upstream's `400` for a malformed id
quotes the id back in the body, and we do not repeat input into an error; and
upstream skips authentication entirely whenever the environment variable `CI`
is set, which we do not copy, because a server that stops checking credentials
because of an inherited variable is a trap.

What is not implemented: the LDAP interface, the Redis, etcd and DynamoDB
backends, the password-change endpoint, and `include`, YAML and S3
configuration. The TOML backend is the one this is for.

| | upstream STNS | stnsd |
| --- | --- | --- |
| TOML backend | yes | yes |
| `link_users` / `link_groups` | yes | yes |
| token and basic auth | yes | yes |
| id range headers | yes | yes |
| LDAP, Redis, etcd, DynamoDB | yes | no |
| TLS, and client certificates | yes | yes |
| architectures | where Go runs | where NetBSD runs |

## Installing

### From pkgsrc or ports

Neither collection carries this yet, so the package is dropped into a tree you
already have. Both fetch the release tarball from github and check it against
the `distinfo` in [`pkg/`](pkg).

```sh
# NetBSD, pkgsrc
cp -R pkg/pkgsrc/security/stnsd /usr/pkgsrc/security/stnsd
cd /usr/pkgsrc/security/stnsd && make install

# FreeBSD or DragonFly, ports
cp -R pkg/ports/security/stnsd /usr/ports/security/stnsd
cd /usr/ports/security/stnsd && make install
```

That gives you `sbin/stnsd`, an rc.d script and a sample configuration
installed root-owned and mode 0600 at `${PKG_SYSCONFDIR}/stns/server/stns.conf`
— it is where password hashes go. CI builds and installs both packages in a VM
on every change to `pkg/`, then starts the daemon through rc.d, so this path is
tested rather than described.

### From the source tree

```sh
make
make test          # unit tests, then the daemon on a real socket
make install       # PREFIX defaults to /usr/pkg on NetBSD, /usr/local elsewhere
```

There is nothing to install beyond the binary, the rc.d script and the sample
configuration, and nothing to build them with but cc and the base system's
OpenSSL — or not even that, with `make WITHOUT_TLS=yes`.

## Running it

```sh
cp /usr/pkg/share/examples/stnsd/stns.conf /usr/pkg/etc/stns/server/stns.conf
chmod 600 /usr/pkg/etc/stns/server/stns.conf
$EDITOR /usr/pkg/etc/stns/server/stns.conf
stnsd -t                            # say so before the daemon finds out
echo stnsd=YES >> /etc/rc.conf
/etc/rc.d/stnsd start
```

```text
usage: stnsd [-fvV] [-c config] [-l [address:]port] [-p pidfile]
       stnsd -t [-c config]
```

`-t` reads the configuration, reports what it found and exits — the rc.d
script runs it before every start and every reload, so a typo is caught while
the old configuration is still serving. A `HUP` rereads the file; if the new
one does not parse, the running one is kept and the refusal goes to syslog.

The configuration is the same `stns.conf` upstream reads, and lives at
`${SYSCONFDIR}/stns/server/stns.conf` — beside the client's
`stns/client/stns.conf`, so one machine can be both. See
[`stns.conf.example`](stns.conf.example).

## How it is built

**One fork per connection**, capped at 64 children. A name service back end
answers small questions from an in-memory table, so the fork costs more than
the work — and buys what is worth buying: a request that goes wrong takes one
child with it, and the tables are read-only after the fork, shared by copy on
write, so there is no lock anywhere in the program.

**Everything is decided at start up.** The file is parsed, the links resolved,
the id range computed, and duplicates and impossible ids refused, before the
socket is opened. A request does no allocation beyond the response it builds.

**The parser is deliberately dull.** This process has every password hash in
its address space. It accepts `GET`, a request line, headers and nothing else;
the request is bounded at 16KB, the connection at a 30 second timeout, and
credentials are compared in constant time.

**TLS is two configuration keys, and one of them changes the shape of the
system.** `tls.cert` and `tls.key` serve HTTPS; adding `tls.ca` additionally
requires the client to present a certificate signed by it, which is upstream's
behaviour and the reason to want it here. A bearer token travels with every
request and is worth stealing; a client certificate stays on the machine that
holds it. This matters more than usual for a server whose replies contain
password hashes.

```toml
[tls]
cert = "/usr/pkg/etc/stns/server/server.pem"
key  = "/usr/pkg/etc/stns/server/server-key.pem"
ca   = "/usr/pkg/etc/stns/server/ca.pem"   # optional: demand client certificates
```

Half a configuration is refused at start up rather than at the first
handshake — a `ca` on its own especially, which reads like "require client
certificates" and would otherwise require nothing at all. The certificate is
loaded once, before the socket opens, so an unreadable one stops the daemon
instead of producing failed handshakes nobody is watching.

OpenSSL comes from the base system on all three platforms, so this costs no
package dependency; in pkgsrc the package goes through
`security/openssl/buildlink3.mk`, which is what makes `PREFER_PKGSRC=yes` get
the pkgsrc one instead. `make WITHOUT_TLS=yes` builds without any of it, for a
machine that terminates TLS elsewhere and would rather not have the library
mapped into a process holding every password hash it serves. Such a build
refuses to start on a configuration that asks for TLS rather than quietly
serving it in the clear.

## Testing

```sh
make test       # 60 unit checks, then 40 against the running daemon
make compat     # 44 answers compared against upstream STNS itself
make asan       # the unit tests under AddressSanitizer and UBSan
make external   # the bundled tomlc99 still matches external/MANIFEST
make plist      # a staged install still matches the packaging lists
```

`make compat` needs the upstream binary in `$STNS` or `$PATH`. It skips when
nobody named one, and fails when somebody named one that is not there — a
comparison that quietly declines to run and reports success is worth less than
no comparison at all. It needs nothing else: the listings, whose order
upstream shuffles, are compared with `awk` and `sort` rather than a JSON
parser, so the test runs wherever the daemon does.

CI builds upstream from source on NetBSD and runs the comparison there, so it
is made on the platform this exists for rather than only on a developer's
machine.

## Licence

BSD 2-Clause. See [LICENSE](LICENSE). `external/mit/tomlc99` is bundled
verbatim from [tomlc99](https://github.com/cktan/tomlc99) and is MIT;
[`external/MANIFEST`](external/MANIFEST) records the exact revision, and
`make external` checks it has not been touched.

The API this implements is STNS's, designed by
[pyama86](https://github.com/STNS/STNS).
