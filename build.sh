#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'build.sh: %s\n' "$*" >&2
    exit 1
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    cat <<'EOF'
Usage: ./build.sh

Build the WebUI and statically linked Linux client and server for the host
architecture (x86_64 or aarch64 with the GNU toolchain).
Output: rvpn/target/<rust-target>/release/{rvpn,rvpn-server}

Requires Node.js 24, npm, Rust via rustup, GCC/G++, CMake, Clang/libclang,
and GNU binutils.
EOF
    exit 0
fi
[[ $# == 0 ]] || die 'run ./build.sh --help for usage'

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace="$root/rvpn"
cd "$workspace"

[[ $(uname -s) == Linux ]] || die 'this script builds on Linux'
for tool in node npm rustc cargo gcc g++ cmake readelf; do
    command -v "$tool" >/dev/null || die "missing required command: $tool"
done

rust_version="$(rustc -vV)"
target="$(awk '/^host: / {print $2}' <<< "$rust_version")"
case "$target" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
    *) die "unsupported Rust host target: $target" ;;
esac

cpp_archive="$(g++ -print-file-name=libstdc++.a)"
[[ -f $cpp_archive ]] || die 'G++ static library libstdc++.a is missing'
cpp_dir="$(dirname -- "$cpp_archive")"

printf '\nBuilding embedded WebUI\n'
(
    cd webui
    npm ci --no-audit --no-fund
    npm run build
)
[[ -s crates/rvpn-client/ui-dist/index.html ]] || die 'WebUI build did not produce index.html'

printf '\nBuilding static client and server for %s\n' "$target"
# Match the Linux release workflow, including BoringSSL's static C++ runtime.
export BORING_BSSL_RUST_CPPLIB=static=stdc++
export RUSTFLAGS="-C target-feature=+crt-static -L native=$cpp_dir"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-thin}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-8}"
unset CARGO_ENCODED_RUSTFLAGS

cargo build --release --locked --target "$target" --target-dir "$workspace/target" \
    --package rvpn-client --package rvpn-server --bins

output="$workspace/target/$target/release"
for binary in "$output/rvpn" "$output/rvpn-server"; do
    segments="$(LC_ALL=C readelf --wide --program-headers "$binary")"
    dynamic="$(LC_ALL=C readelf --wide --dynamic "$binary")"
    if grep -Eq '^[[:space:]]*INTERP[[:space:]]' <<< "$segments" ||
        grep -Fq '(NEEDED)' <<< "$dynamic"; then
        die "$binary has an ELF interpreter or shared-library dependencies"
    fi
done

printf '\nStatic binaries:\n  %s\n  %s\n' "$output/rvpn" "$output/rvpn-server"
