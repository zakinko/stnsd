#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Functional tests for stnsd itself: the things upstream is not there to
# compare against -- how it starts, what it refuses to start on, what it does
# with a HUP, and whether a connection can be reused.
#
# tests/compat.sh is the one that decides whether the answers are right.  This
# one decides whether the daemon is a daemon.
#
# usage: functional.sh [path to stnsd]

set -u

STNSD=${1:-./stnsd}
PORT=${PORT:-11114}
SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/stnsd_functional.$$}

case "$STNSD" in
/*)	;;
*)	STNSD=$(pwd)/${STNSD#./} ;;
esac

rm -rf "$WORK"
mkdir -p "$WORK"

failures=0
checks=0

ok() {
	checks=$((checks + 1))
	echo "ok   - $1"
}

fail() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	echo "FAIL - $1"
}

expect() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		fail "$1"
		echo "       expected: $2"
		echo "       actual:   $3"
	fi
}

contains() {
	case "$3" in
	*"$2"*)	ok "$1" ;;
	*)	fail "$1"; echo "       expected to contain: $2"; echo "       actual: $3" ;;
	esac
}

# succeeds <description> <command...>
succeeds() {
	desc=$1; shift
	if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc"; fi
}

# denies <description> <command...>
denies() {
	desc=$1; shift
	if "$@" >/dev/null 2>&1; then fail "$desc"; else ok "$desc"; fi
}

server_pid=""

stop_server() {
	if [ -n "$server_pid" ]; then
		kill "$server_pid" 2>/dev/null
		wait "$server_pid" 2>/dev/null
		server_pid=""
	fi
}

cleanup() {
	stop_server
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_for_port() {
	i=0
	while [ $i -lt 100 ]; do
		curl -sf -o /dev/null "http://127.0.0.1:$PORT/v1/status" && return 0
		i=$((i + 1))
		sleep 0.2
	done
	echo "stnsd did not come up" >&2
	cat "$WORK/stnsd.log" >&2 2>/dev/null || true
	exit 1
}

start_server() {
	stop_server
	"$STNSD" -f -c "$WORK/stns.conf" -l "127.0.0.1:$PORT" > "$WORK/stnsd.log" 2>&1 &
	server_pid=$!
	wait_for_port
}

status_of() {
	curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT$1"
}

sed "s/^port = .*/port = $PORT/" "$SRCDIR/tests/stns.conf" > "$WORK/stns.conf"

echo "== the configuration test =="
"$STNSD" -V > "$WORK/version" 2>&1
contains "-V prints a version" "stnsd 0" "$(cat "$WORK/version")"
if "$STNSD" -t -c "$WORK/stns.conf" >/dev/null 2>&1; then
	ok "-t accepts a good configuration"
else
	fail "-t accepts a good configuration"
fi
echo 'not = = toml' > "$WORK/broken.conf"
if "$STNSD" -t -c "$WORK/broken.conf" >/dev/null 2>&1; then
	fail "-t rejects a broken configuration"
else
	ok "-t rejects a broken configuration"
fi
if "$STNSD" -t -c "$WORK/nonexistent.conf" >/dev/null 2>&1; then
	fail "-t rejects a missing configuration"
else
	ok "-t rejects a missing configuration"
fi
# The point of -t is that the refusal happens before the daemon replaces a
# running one, so it has to say what is wrong on stderr.
contains "and says what was wrong" "$WORK/broken.conf" \
	"$("$STNSD" -t -c "$WORK/broken.conf" 2>&1 || true)"

echo
echo "== refusing to start =="
if "$STNSD" -f -c "$WORK/broken.conf" -l "127.0.0.1:$PORT" >/dev/null 2>&1; then
	fail "a broken configuration is not served"
else
	ok "a broken configuration is not served"
fi

echo
echo "== serving =="
start_server
expect "GET /v1/status" "OK" "$(curl -s "http://127.0.0.1:$PORT/v1/status")"
expect "a known user is 200" "200" "$(status_of '/v1/users?name=alice')"
expect "an unknown user is 404" "404" "$(status_of '/v1/users?name=nobody')"
expect "an unknown path is 404" "404" "$(status_of '/v1/nope')"
expect "an unknown query parameter is 400" "400" "$(status_of '/v1/users?bogus=1')"
expect "a non-numeric id is 400" "400" "$(status_of '/v1/users?id=abc')"

headers=$(curl -sD - -o /dev/null "http://127.0.0.1:$PORT/v1/users?name=alice")
contains "the highest id is advertised" "User-Highest-Id: 1005" "$headers"
contains "the lowest id is advertised" "User-Lowest-Id: 1001" "$headers"
contains "and the server names itself" "Server: stnsd/" "$headers"
headers=$(curl -sD - -o /dev/null "http://127.0.0.1:$PORT/v1/users?name=nobody")
contains "a 404 carries the id range too, which is when it is most useful" \
	"User-Highest-Id: 1005" "$headers"

echo
echo "== a listing is served in the order the file wrote it =="
# Upstream cannot promise this -- it ranges over a Go map -- and a client that
# enumerates twice should not see two different orders.
first=$(curl -s "http://127.0.0.1:$PORT/v1/users")
same=1
i=0
while [ $i -lt 5 ]; do
	[ "$(curl -s "http://127.0.0.1:$PORT/v1/users")" = "$first" ] || same=0
	i=$((i + 1))
done
expect "six enumerations agree" "1" "$same"
contains "and alice comes first, as she does in the file" '"name":"alice"' \
	"$(echo "$first" | cut -c1-80)"

echo
echo "== one connection, several requests =="
# curl reuses the connection for both; a server that mishandled keep-alive
# would hang here rather than answer twice.
both=$(curl -s "http://127.0.0.1:$PORT/v1/users?name=alice" "http://127.0.0.1:$PORT/v1/users?name=bob")
contains "the first answer arrives" '"name":"alice"' "$both"
contains "the second answer arrives on the same connection" '"name":"bob"' "$both"

echo
echo "== reload =="
cat >> "$WORK/stns.conf" <<'EOF'

[users.frank]
id = 1006
group_id = 1001
EOF
expect "the new user is not there yet" "404" "$(status_of '/v1/users?name=frank')"
kill -HUP "$server_pid"
sleep 1
expect "and is there after a HUP" "200" "$(status_of '/v1/users?name=frank')"
contains "the id range moved with it" "User-Highest-Id: 1006" \
	"$(curl -sD - -o /dev/null "http://127.0.0.1:$PORT/v1/users?name=frank")"

echo
echo "== a broken reload keeps the running configuration =="
cp "$WORK/stns.conf" "$WORK/good.conf"
echo 'and now = = broken' >> "$WORK/stns.conf"
kill -HUP "$server_pid"
sleep 1
expect "the server is still up" "200" "$(status_of '/v1/users?name=alice')"
expect "and still knows what it knew" "200" "$(status_of '/v1/users?name=frank')"
contains "and said so" "keeping the running configuration" "$(cat "$WORK/stnsd.log")"
cp "$WORK/good.conf" "$WORK/stns.conf"

echo
echo "== the pid file =="
stop_server
"$STNSD" -f -c "$WORK/stns.conf" -l "127.0.0.1:$PORT" -p "$WORK/stnsd.pid" > "$WORK/stnsd.log" 2>&1 &
server_pid=$!
wait_for_port
if [ -f "$WORK/stnsd.pid" ]; then
	expect "the pid file holds the pid" "$server_pid" "$(cat "$WORK/stnsd.pid")"
else
	fail "the pid file is written"
fi
kill -TERM "$server_pid"
wait "$server_pid" 2>/dev/null
server_pid=""
if [ -f "$WORK/stnsd.pid" ]; then
	fail "the pid file is removed on exit"
else
	ok "the pid file is removed on exit"
fi

echo
echo "== a request that is not HTTP =="
start_server
garbage=$(printf 'not http at all\r\n\r\n' | nc 127.0.0.1 $PORT 2>/dev/null | head -1)
contains "is answered with 400 rather than a crash" "400" "$garbage"
expect "and the server is still serving" "200" "$(status_of '/v1/users?name=alice')"

echo
echo "== TLS =="
sed "s/^port = .*/port = $PORT/" "$SRCDIR/tests/stns.conf" > "$WORK/probe.conf"
printf '\n[tls]\ncert = "/nonexistent.pem"\nkey = "/nonexistent-key.pem"\n' >> "$WORK/probe.conf"
case "$("$STNSD" -t -c "$WORK/probe.conf" 2>&1)" in
*"built without TLS"*)
	echo "skip - this stnsd was built with WITHOUT_TLS"
	echo
	echo "$checks checks, $failures failures"
	[ "$failures" -eq 0 ]
	exit $?
	;;
esac

# A machine with no openssl(1) at all is a skip; one where the command fails
# is a failure, printed in full.  Silently skipping is how a suite comes to
# report success for tests it never ran.
if ! command -v openssl >/dev/null 2>&1; then
	echo "skip - no openssl(1) here to make a certificate with"
else
	cat > "$WORK/openssl.cnf" <<'CNFEOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = localhost
[server_ext]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = critical,CA:FALSE
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
CNFEOF
fi
# openssl(1) wants a configuration file and NetBSD's base OpenSSL ships none at
# the path it looks in, so one is written above and named explicitly.  That
# also avoids -addext, which is younger than some of the LibreSSL in use here.
if [ ! -f "$WORK/openssl.cnf" ]; then
	:
elif certerr=$(openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/server-key.pem" \
    -out "$WORK/server.pem" -days 1 -subj "/CN=localhost" \
    -config "$WORK/openssl.cnf" -extensions server_ext 2>&1); then

	sed "s/^port = .*/port = $PORT/" "$SRCDIR/tests/stns.conf" > "$WORK/tls.conf"
	printf '\n[tls]\ncert = "%s"\nkey  = "%s"\n' \
		"$WORK/server.pem" "$WORK/server-key.pem" >> "$WORK/tls.conf"

	contains "-t says the server will speak TLS" ", TLS" \
		"$("$STNSD" -t -c "$WORK/tls.conf" 2>&1 || true)"

	# A certificate that cannot be read must stop the server starting, not
	# turn into a run of failed handshakes nobody is watching.
	sed 's|^cert = .*|cert = "/nonexistent.pem"|' "$WORK/tls.conf" > "$WORK/badtls.conf"
	if "$STNSD" -t -c "$WORK/badtls.conf" >/dev/null 2>&1; then
		fail "an unreadable certificate is refused"
	else
		ok "an unreadable certificate is refused"
	fi

	stop_server
	"$STNSD" -f -c "$WORK/tls.conf" -l "127.0.0.1:$PORT" > "$WORK/stnsd.log" 2>&1 &
	server_pid=$!
	i=0
	while [ $i -lt 100 ]; do
		curl -sf --cacert "$WORK/server.pem" -o /dev/null \
			"https://localhost:$PORT/v1/status" && break
		i=$((i + 1))
		sleep 0.2
	done

	expect "an https lookup answers" \
		"200" "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/server.pem" \
			"https://localhost:$PORT/v1/users?name=alice")"
	contains "and answers with the user" '"name":"alice"' \
		"$(curl -s --cacert "$WORK/server.pem" "https://localhost:$PORT/v1/users?name=alice")"
	# Without the CA the certificate is untrusted, so curl must refuse: the
	# point of TLS here is that the client checks, not that bytes are hidden.
	denies "an untrusted certificate is refused by the client" \
		curl -sf -m 5 -o /dev/null "https://localhost:$PORT/v1/status"
	denies "plain http against a TLS port gets nowhere" \
		curl -sf -m 5 -o /dev/null "http://localhost:$PORT/v1/status"
	succeeds "and the server is still serving" \
		curl -sf -m 5 -o /dev/null --cacert "$WORK/server.pem" "https://localhost:$PORT/v1/status"

	echo
	echo "== TLS with client certificates =="
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca-key.pem" -out "$WORK/ca.pem" \
		-days 1 -subj "/CN=stnsd test CA" \
		-config "$WORK/openssl.cnf" -extensions ca_ext >/dev/null 2>&1
	openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/client-key.pem" \
		-out "$WORK/client.csr" -subj "/CN=client" \
		-config "$WORK/openssl.cnf" >/dev/null 2>&1
	openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca-key.pem" \
		-CAcreateserial -out "$WORK/client.pem" -days 1 >/dev/null 2>&1

	cp "$WORK/tls.conf" "$WORK/mtls.conf"
	printf 'ca   = "%s"\n' "$WORK/ca.pem" >> "$WORK/mtls.conf"
	contains "-t says client certificates will be required" "client certificates" \
		"$("$STNSD" -t -c "$WORK/mtls.conf" 2>&1 || true)"

	stop_server
	"$STNSD" -f -c "$WORK/mtls.conf" -l "127.0.0.1:$PORT" > "$WORK/stnsd.log" 2>&1 &
	server_pid=$!
	# The exemption /v1/status has from authentication is an HTTP-level one,
	# and the handshake comes first, so even it needs the certificate here.
	# Bounded at ten seconds: if the wait runs out the checks below say why,
	# which is more use than waiting longer.
	i=0
	while [ $i -lt 50 ]; do
		curl -sf -m 5 --cacert "$WORK/server.pem" --cert "$WORK/client.pem" \
			--key "$WORK/client-key.pem" -o /dev/null \
			"https://localhost:$PORT/v1/status" 2>/dev/null && break
		i=$((i + 1))
		sleep 0.2
	done

	denies "a client with no certificate is refused" \
		curl -sf -m 5 -o /dev/null --cacert "$WORK/server.pem" \
			"https://localhost:$PORT/v1/users?name=alice"

	# Some clients cannot present a certificate under TLS 1.3 -- LibreSSL was
	# a while catching up -- so a failure is retried at 1.2 before being
	# called one.  Which version it took is reported either way: it is the
	# client's limitation, not the server's, but it is worth knowing.
	mtls=$(curl -s -m 10 --cacert "$WORK/server.pem" --cert "$WORK/client.pem" \
		--key "$WORK/client-key.pem" "https://localhost:$PORT/v1/users?name=alice" 2>&1)
	case "$mtls" in
	*'"name":"alice"'*)
		ok "a client with one is served"
		;;
	*)
		mtls12=$(curl -s -m 10 --tls-max 1.2 --cacert "$WORK/server.pem" \
			--cert "$WORK/client.pem" --key "$WORK/client-key.pem" \
			"https://localhost:$PORT/v1/users?name=alice" 2>&1)
		case "$mtls12" in
		*'"name":"alice"'*)
			ok "a client with one is served (this client needs TLS 1.2 to send it)"
			;;
		*)
			fail "a client with one is served"
			echo "       at 1.3: $mtls"
			echo "       at 1.2: $mtls12"
			curl -v -m 10 --cacert "$WORK/server.pem" --cert "$WORK/client.pem" \
				--key "$WORK/client-key.pem" \
				"https://localhost:$PORT/v1/status" 2>&1 |
				sed -n 's/^/       curl: /p' | tail -12
			sed -n 's/^/       stnsd: /p' "$WORK/stnsd.log" | tail -5
			;;
		esac
		;;
	esac
else
	fail "openssl(1) can make a certificate"
	echo "$certerr" | sed 's/^/       /'
fi

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
