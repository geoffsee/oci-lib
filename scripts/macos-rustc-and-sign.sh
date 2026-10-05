#!/bin/sh
# Ad-hoc sign Darwin executables after rustc links and strips them.
# Cargo invokes this as rustc-wrapper. A build.rs cannot do this: it runs
# before the binary exists, and profile.release strip rewrites the Mach-O
# after the linker returns.
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: macos-rustc-and-sign.sh <rustc> [args...]" >&2
    exit 2
fi

rustc=$1
shift

"$rustc" "$@"

if [ "$(uname -s)" != "Darwin" ]; then
    exit 0
fi

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
entitlements=$script_dir/entitlements.plist
if [ ! -f "$entitlements" ]; then
    echo "macos-rustc-and-sign.sh: missing $entitlements" >&2
    exit 1
fi

crate_name=
out_dir=
extra_filename=
explicit_o=
emit=
is_bin=0
want=

consider() {
    arg=$1
    case $want in
        o)
            explicit_o=$arg
            want=
            return
            ;;
        crate-type)
            if [ "$arg" = "bin" ]; then
                is_bin=1
            fi
            want=
            return
            ;;
        crate-name)
            crate_name=$arg
            want=
            return
            ;;
        out-dir)
            out_dir=$arg
            want=
            return
            ;;
        emit)
            emit=$arg
            want=
            return
            ;;
        C)
            case $arg in
                extra-filename=*)
                    extra_filename=${arg#extra-filename=}
                    ;;
            esac
            want=
            return
            ;;
    esac

    case $arg in
        --crate-type=*)
            if [ "${arg#--crate-type=}" = "bin" ]; then
                is_bin=1
            fi
            ;;
        --crate-name=*)
            crate_name=${arg#--crate-name=}
            ;;
        --out-dir=*)
            out_dir=${arg#--out-dir=}
            ;;
        --emit=*)
            emit=${arg#--emit=}
            ;;
        -Cextra-filename=*)
            extra_filename=${arg#-Cextra-filename=}
            ;;
        -C)
            want=C
            ;;
        -o)
            want=o
            ;;
        --crate-type)
            want=crate-type
            ;;
        --crate-name)
            want=crate-name
            ;;
        --out-dir)
            want=out-dir
            ;;
        --emit)
            want=emit
            ;;
        @*)
            resp=${arg#@}
            if [ -f "$resp" ]; then
                while IFS= read -r line <&3 || [ -n "$line" ]; do
                    consider "$line"
                done 3< "$resp"
            fi
            ;;
    esac
}

for arg in "$@"; do
    consider "$arg"
done

if [ "$is_bin" -ne 1 ]; then
    exit 0
fi

# Build scripts do not need the Virtualization entitlement.
if [ "$crate_name" = "build_script_build" ]; then
    exit 0
fi

case $emit in
    *link*) ;;
    "") ;;
    *) exit 0 ;;
esac

if [ -n "$explicit_o" ]; then
    bin=$explicit_o
elif [ -n "$out_dir" ] && [ -n "$crate_name" ]; then
    bin=$out_dir/$crate_name$extra_filename
else
    exit 0
fi

if [ ! -f "$bin" ]; then
    echo "macos-rustc-and-sign.sh: expected linked binary $bin" >&2
    exit 1
fi

kind=$(file -b "$bin" || true)
case $kind in
    *executable*) ;;
    *) exit 0 ;;
esac

codesign --force --sign - --entitlements "$entitlements" "$bin"
