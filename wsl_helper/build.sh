#!/bin/sh
set -eu

output="${1:-dist/wsl-helper-x86_64}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=x86_64-unknown-linux-musl

cd "$root/wsl_helper"
cargo test --locked --target "$target"
cargo build --locked --release --target "$target"
mkdir -p "$(dirname -- "$root/$output")"
cp "target/$target/release/wsl-helper" "$root/$output"
chmod 0755 "$root/$output"
hash=$(sha256sum "$root/$output" | awk '{print $1}')
printf '%s  %s\n' "$hash" "$(basename -- "$output")" > "$root/$output.sha256"
