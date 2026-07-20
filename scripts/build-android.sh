#!/usr/bin/env bash
set -euo pipefail

# Build the zk-ai UniFFI shared library for Android.
# Outputs to crates/uniffi/target/android/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Building zk-ai UniFFI for Android..."

# Android NDK targets
TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "x86_64-linux-android"
    "i686-linux-android"
)

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    rustup target add "$target" 2>/dev/null || true
    cargo build --release --target "$target" -p zk-ai-uniffi
done

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
cargo run --bin uniffi-bindgen -- generate --library \
    "$ROOT/crates/uniffi/target/aarch64-linux-android/release/libzk_ai_uniffi.so" \
    --language kotlin \
    --out-dir "$ROOT/crates/uniffi/target/android/bindings"

echo "Android build complete."
echo "Next steps: copy .so files to jniLibs/ and integrate Kotlin bindings."
