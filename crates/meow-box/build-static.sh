#!/usr/bin/env bash
# Static single-file builds of `meow` with the `box` feature, for any Linux
# (glibc or musl: OpenWrt, Alpine, Debian, Arch ...). Writes
#   dist/box/meow-<target>   and   dist/box/SHA256SUMS
#
#   crates/meow-box/build-static.sh                             # both targets
#   crates/meow-box/build-static.sh x86_64-unknown-linux-musl   # just one
#
# Needs: the musl Rust targets (`rustup target add x86_64-unknown-linux-musl
# aarch64-unknown-linux-musl`), cargo-zigbuild (`cargo install cargo-zigbuild
# --locked`) and zig 0.13.0 — the version release CI (build.yml) pins; taken
# from PATH, else through mise (`mise use -g zig@0.13.0`). zig is the C/C++
# compiler and linker for BoringSSL/quiche and links its own libc++ and musl
# statically, so no system musl or cross toolchain is needed.
#
# Targets are built one after another. On a busy machine, cap it, e.g.
#   CARGO_BUILD_JOBS=4 systemd-run --user --scope -q -p MemoryMax=6G crates/meow-box/build-static.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
zig_version=0.13.0
targets=("$@")
[[ ${#targets[@]} -gt 0 ]] || targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

# zig from PATH, or the pinned one through mise.
run=()
if ! command -v zig >/dev/null; then
  command -v mise >/dev/null || { echo "zig $zig_version not found (install: mise use -g zig@$zig_version)" >&2; exit 1; }
  run=(mise exec "zig@$zig_version" --)
fi
command -v cargo-zigbuild >/dev/null || { echo "cargo-zigbuild not found (install: cargo install cargo-zigbuild --locked)" >&2; exit 1; }

out="$root/dist/box"
mkdir -p "$out"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
for t in "${targets[@]}"; do
  echo "== $t"
  "${run[@]}" cargo zigbuild --release --locked --target "$t" -p meow-app --bin meow --features box
  bin="$target_dir/$t/release/meow"
  # A static binary has no program interpreter and no shared-library deps.
  if readelf -lW "$bin" | grep -q 'INTERP' || readelf -dW "$bin" | grep -q 'NEEDED'; then
    echo "FAIL $bin is not statically linked" >&2
    exit 1
  fi
  cp "$bin" "$out/meow-$t"
done
(cd "$out" && sha256sum meow-*-linux-musl > SHA256SUMS)
ls -l "$out"
cat "$out/SHA256SUMS"
