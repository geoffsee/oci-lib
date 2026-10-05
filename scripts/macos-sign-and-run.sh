#!/bin/sh
# Ad-hoc sign a Darwin binary with the Virtualization entitlement, then exec it.
# Cargo invokes this as the apple-darwin test and run runner.
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: macos-sign-and-run.sh <binary> [args...]" >&2
    exit 2
fi

bin=$1
shift

# Doctest binaries live under a temp dir, so also search from this script and
# from the working directory. Cargo runs the script with the workspace as cwd.
entitlements=""
find_entitlements() {
    dir=$1
    [ -n "$dir" ] || return 0
    dir=$(CDPATH= cd -- "$dir" 2>/dev/null && pwd) || return 0
    while [ "$dir" != "/" ]; do
        if [ -f "$dir/scripts/entitlements.plist" ]; then
            entitlements="$dir/scripts/entitlements.plist"
            return 0
        fi
        if [ -f "$dir/entitlements.plist" ]; then
            entitlements="$dir/entitlements.plist"
            return 0
        fi
        dir=$(dirname "$dir")
    done
}

find_entitlements "$(dirname "$0")"
if [ -z "$entitlements" ]; then
    find_entitlements "$(dirname "$bin")"
fi
if [ -z "$entitlements" ]; then
    find_entitlements "$(pwd)"
fi

if [ -z "$entitlements" ]; then
    echo "scripts/entitlements.plist was not found above $bin" >&2
    exit 1
fi

codesign --force --sign - --entitlements "$entitlements" "$bin"
exec "$bin" "$@"
