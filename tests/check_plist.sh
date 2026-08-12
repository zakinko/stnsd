#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Check the packaging lists against what "make install" actually installs.
#
# A packing list that has drifted from reality is not caught by building the
# port: pkgsrc and pkg(8) only notice at the very end, on a machine that has
# the ports tree and a released tarball.  Staging into a scratch directory
# reproduces the same comparison here, from the working tree.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/tmp/stnsd_stage}
# Scratch files live outside the staging tree, which has to contain nothing
# but what was installed into it.
SCRATCH=${SCRATCH:-/tmp/stnsd_plist}

OS=$(uname -s)
case "$OS" in
NetBSD)
	PREFIX=/usr/pkg
	PLIST=$SRCDIR/pkg/pkgsrc/security/stnsd/PLIST
	;;
FreeBSD|DragonFly|MidnightBSD)
	PREFIX=/usr/local
	PLIST=$SRCDIR/pkg/ports/net/nss_stns/pkg-plist
	;;
*)
	echo "unsupported OS: $OS" >&2
	exit 1
	;;
esac

rm -rf "$STAGE" "$SCRATCH"
mkdir -p "$STAGE" "$SCRATCH"

cd "$SRCDIR"
make DESTDIR="$STAGE" PREFIX="$PREFIX" install >/dev/null

installed=$(cd "$STAGE$PREFIX" && find . -type f | sed 's|^\./||' | sort)

# From the packing list, keep the plain file entries, plus the source side of
# a pkg(8) "@sample src dest" line.  Directory and hook entries are the
# package manager's business, not ours.
expected=$(awk '
		/^@sample/  { print $2; next }   # pkg(8): "@sample src dest"
		/^@/        { next }             # @dir, @comment, @postexec, ...
		/^[ \t]*$/  { next }
		{ print }
	' "$PLIST" | sort)

echo "installed under $PREFIX:"
echo "$installed" | sed 's/^/  /'
echo "listed in $(basename "$PLIST"):"
echo "$expected" | sed 's/^/  /'

rc=0
printf '%s\n' "$installed" > "$SCRATCH/installed"
printf '%s\n' "$expected" > "$SCRATCH/expected"

missing=$(comm -23 "$SCRATCH/installed" "$SCRATCH/expected")
extra=$(comm -13 "$SCRATCH/installed" "$SCRATCH/expected")

if [ -n "$missing" ]; then
	echo "FAIL - installed but not in the packing list:" >&2
	echo "$missing" | sed 's/^/  /' >&2
	rc=1
fi
if [ -n "$extra" ]; then
	echo "FAIL - in the packing list but not installed:" >&2
	echo "$extra" | sed 's/^/  /' >&2
	rc=1
fi

# The staged tree must stay inside PREFIX; anything else would be a file the
# package manager cannot own.
outside=$(cd "$STAGE" && find . -type f -o -type l | sed 's|^\./||' |
	grep -v "^${PREFIX#/}/" || true)
if [ -n "$outside" ]; then
	echo "FAIL - staged outside $PREFIX:" >&2
	echo "$outside" | sed 's/^/  /' >&2
	rc=1
fi

rm -rf "$STAGE" "$SCRATCH"

if [ "$rc" -eq 0 ]; then
	echo "ok   - the packing list matches what is installed"
fi
exit "$rc"
