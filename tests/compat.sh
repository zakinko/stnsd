#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Differential test: serve tests/stns.conf from stnsd and from upstream STNS at
# the same time, ask both the same questions, and require the same answers.
#
# This is the test that makes "compatible" mean something.  A hand written list
# of expected responses only ever encodes what its author believed the protocol
# to be; upstream, running right there on the same file, encodes what it
# actually is.  Where the two disagree the difference is printed in full, and
# the small number of disagreements we accept on purpose are listed below and
# nowhere else.
#
# Needs the upstream binary in $STNS or in $PATH as "stns", plus curl and
# python3 (to compare listings, whose order upstream draws from a Go map and
# therefore shuffles on every request).
#
# usage: compat.sh [path to stnsd]

set -u

STNSD=${1:-./stnsd}
STNS=${STNS:-stns}
PORT_A=${PORT_A:-11104}		# stnsd
PORT_B=${PORT_B:-11105}		# upstream
SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/stnsd_compat.$$}

case "$STNSD" in
/*)	;;
*)	STNSD=$(pwd)/${STNSD#./} ;;
esac

if ! command -v "$STNS" >/dev/null 2>&1; then
	echo "compat.sh: no upstream STNS binary (set \$STNS); skipping" >&2
	exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "compat.sh: python3 is needed to compare listings; skipping" >&2
	exit 0
fi

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

pids=""

stop_servers() {
	[ -n "$pids" ] && kill $pids 2>/dev/null
	wait $pids 2>/dev/null
	pids=""
}

cleanup() {
	stop_servers
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_for() {
	i=0
	while [ $i -lt 100 ]; do
		curl -sf -o /dev/null "http://127.0.0.1:$1/v1/status" && return 0
		i=$((i + 1))
		sleep 0.2
	done
	echo "the server on port $1 did not come up" >&2
	cat "$WORK/$1.log" >&2 2>/dev/null || true
	exit 1
}

# start_servers <config>  - the same file, served by both, on two ports.
start_servers() {
	stop_servers
	sed "s/^port = .*/port = $PORT_A/" "$1" > "$WORK/a.conf"
	sed "s/^port = .*/port = $PORT_B/" "$1" > "$WORK/b.conf"

	"$STNSD" -f -c "$WORK/a.conf" > "$WORK/$PORT_A.log" 2>&1 &
	pids="$pids $!"
	# CI is cleared deliberately: upstream skips authentication entirely
	# when it finds that variable set, so the auth comparisons below would
	# agree for the wrong reason on a CI runner.
	CI= "$STNS" --config "$WORK/b.conf" --pidfile "$WORK/b.pid" server > "$WORK/$PORT_B.log" 2>&1 &
	pids="$pids $!"
	wait_for $PORT_A
	wait_for $PORT_B
}

# fetch <port> <path> [curl args...] - status, headers and body, in one file.
fetch() {
	port=$1; path=$2; shift 2
	curl -s -o "$WORK/body" -D "$WORK/head" "$@" "http://127.0.0.1:$port$path"
	status=$(head -1 "$WORK/head" | awk '{print $2}')
	ids=$(grep -i '^\(user\|group\)-\(highest\|lowest\)-id:' "$WORK/head" |
		tr 'A-Z' 'a-z' | tr -d '\r' | sort)
}

# same <description> <path> [curl args...]
#
# Compares the status, the four id headers and the body, byte for byte.
same() {
	desc=$1; path=$2; shift 2

	fetch $PORT_A "$path" "$@"
	a_status=$status; a_ids=$ids
	cp "$WORK/body" "$WORK/a.body"
	fetch $PORT_B "$path" "$@"
	b_status=$status; b_ids=$ids
	cp "$WORK/body" "$WORK/b.body"

	if [ "$a_status" != "$b_status" ]; then
		fail "$desc (status $a_status vs $b_status)"
		return
	fi
	if [ "$a_ids" != "$b_ids" ]; then
		fail "$desc (id headers)"
		echo "       stnsd:    $a_ids"
		echo "       upstream: $b_ids"
		return
	fi
	if ! cmp -s "$WORK/a.body" "$WORK/b.body"; then
		fail "$desc (body)"
		echo "       stnsd:    $(cat "$WORK/a.body")"
		echo "       upstream: $(cat "$WORK/b.body")"
		return
	fi
	ok "$desc [$a_status]"
}

# same_set <description> <path>
#
# For the listings.  Upstream builds them by ranging over a Go map, so the
# order is different on every request and only the set can be compared.
same_set() {
	desc=$1; path=$2

	for port in $PORT_A $PORT_B; do
		curl -s "http://127.0.0.1:$port$path" |
			python3 -c 'import json,sys; print(json.dumps(sorted(json.load(sys.stdin), key=lambda e: e["id"]), sort_keys=True))' \
			> "$WORK/$port.set" 2>/dev/null || echo PARSE_ERROR > "$WORK/$port.set"
	done
	if cmp -s "$WORK/$PORT_A.set" "$WORK/$PORT_B.set"; then
		ok "$desc"
	else
		fail "$desc"
		echo "       stnsd:    $(cat "$WORK/$PORT_A.set")"
		echo "       upstream: $(cat "$WORK/$PORT_B.set")"
	fi
}

echo "== the same configuration, served by both =="
"$STNSD" -V
CI= "$STNS" --config "$SRCDIR/tests/stns.conf" checkconf >/dev/null 2>&1 &&
	ok "upstream accepts tests/stns.conf" || fail "upstream accepts tests/stns.conf"
start_servers "$SRCDIR/tests/stns.conf"

echo
echo "== users =="
for name in alice bob carol dave eve nobody; do
	same "GET /v1/users?name=$name" "/v1/users?name=$name"
done
for id in 1001 1002 1003 1004 1005 9999; do
	same "GET /v1/users?id=$id" "/v1/users?id=$id"
done
same_set "GET /v1/users lists the same users" "/v1/users"

echo
echo "== groups =="
for name in staff ops empty emptylist nosuchgroup; do
	same "GET /v1/groups?name=$name" "/v1/groups?name=$name"
done
for id in 1001 1002 1003 1004 9999; do
	same "GET /v1/groups?id=$id" "/v1/groups?id=$id"
done
same_set "GET /v1/groups lists the same groups" "/v1/groups"

echo
echo "== the rest of the surface =="
same "GET /v1/status" "/v1/status"
same "GET /" "/"
same "GET an unknown path" "/v1/nope"
same "PUT /v1/users is refused" "/v1/users" -X PUT
# A percent encoded name has to survive the round trip identically.
same "GET /v1/users?name=al%69ce" "/v1/users?name=al%69ce"

echo
echo "== token auth =="
cp "$SRCDIR/tests/stns.conf" "$WORK/token.conf"
printf '\n[token_auth]\ntokens = ["s3cr3t", "another"]\n' >> "$WORK/token.conf"
start_servers "$WORK/token.conf"
same "no token is refused" "/v1/users?name=alice"
same "a wrong token is refused" "/v1/users?name=alice" -H 'Authorization: token wrong'
same "the right token is accepted" "/v1/users?name=alice" -H 'Authorization: token s3cr3t'
same "the second token works too" "/v1/users?name=alice" -H 'Authorization: token another'
same "status needs no token" "/v1/status"

echo
echo "== basic auth =="
cp "$SRCDIR/tests/stns.conf" "$WORK/basic.conf"
printf '\n[basic_auth]\nuser = "stns"\npassword = "hunter2"\n' >> "$WORK/basic.conf"
start_servers "$WORK/basic.conf"
same "no credentials are refused" "/v1/users?name=alice"
same "wrong credentials are refused" "/v1/users?name=alice" -u stns:wrong
same "the right credentials are accepted" "/v1/users?name=alice" -u stns:hunter2

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
