#!/bin/sh
# decode_license.sh - print the contents of an ionCube license file.
#
# Usage:
#   decode_license.sh <license-file> <passphrase> [key32]
#
# make_license's --decode-license is normally enough when the license was
# produced by the bundled make_license.  Some licenses bind the decryption key
# to an additional 32-bit value that the encoded application carries in its
# license probe (the ionCube Loader reads it and passes it to the same
# decryption routine).  The make_license CLI has no option for that value and
# supplies 0, so decoding fails even with the correct passphrase.  Pass the
# value as [key32] (decimal or 0x-hex); it defaults to 0.
#
# See decode_license.md in this directory for how to recover the passphrase and
# the 32-bit value from an encoded application.
#
# Environment:
#   MAKE_LICENSE   path to the make_license_64 binary
#                  (default: ../../../ioncube_encoder_evaluation/make_license_64
#                  relative to this script, i.e. the repository's evaluation
#                  directory)
#
# Requires gdb.  The bundled make_license has an integrity check that rejects
# a patched binary, so the value is applied at runtime instead.

set -u

usage() {
    echo "usage: $0 <license-file> <passphrase> [key32]" >&2
    exit 2
}

[ $# -ge 2 ] || usage

LIC=$1
PASS=$2
KEY=${3:-0}

# Accept only decimal or 0x-hex, so the value can be interpolated into gdb.
case "$KEY" in
    0x*|0X*)
        case "${KEY#*x}" in
            ''|*[!0-9a-fA-F]*) usage ;;
        esac
        ;;
    *)
        case "$KEY" in
            ''|*[!0-9]*) usage ;;
        esac
        ;;
esac

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MAKE_LICENSE=${MAKE_LICENSE:-"$here/../ioncube_encoder_evaluation/make_license_64"}

[ -x "$MAKE_LICENSE" ] || {
    echo "make_license not found or not executable: $MAKE_LICENSE" >&2
    echo "set MAKE_LICENSE to the correct path or download it" >&2
    exit 2
}
[ -f "$LIC" ] || {
    echo "license file not found: $LIC" >&2
    exit 2
}
command -v gdb >/dev/null 2>&1 || {
    echo "gdb is required" >&2
    exit 2
}

tmp=$(mktemp) || exit 2
trap 'rm -f "$tmp"' EXIT INT TERM

# 0x412c80 is the entry of the license decode routine in the bundled
# make_license 15.0 build.  The program's own exit status is reported through
# $_exitcode so a failed decode can be propagated.
gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'set confirm off' \
    -ex 'set print thread-events off' \
    -ex 'break *0x412c80' \
    -ex 'run' \
    -ex "set \$esi=$KEY" \
    -ex 'continue' \
    -ex 'printf "__EXIT__=%d\n", $_exitcode' \
    --args "$MAKE_LICENSE" --decode-license "$LIC" --passphrase "$PASS" \
    >"$tmp" 2>&1

code=$(sed -n 's/^__EXIT__=//p' "$tmp" | tail -n 1)

grep -v -E '^(Breakpoint [0-9]|\[Thread debugging|\[Inferior [0-9]|Using host libthread_db|warning:|__EXIT__=)' "$tmp"

exit "${code:-1}"
