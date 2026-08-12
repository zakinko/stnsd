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
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
