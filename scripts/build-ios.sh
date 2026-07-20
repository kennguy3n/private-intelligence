#!/usr/bin/env bash
set -euo pipefail

# Build the zk-ai UniFFI static library + XCFramework for iOS.
# Outputs to crates/uniffi/target/ios/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Building zk-ai UniFFI for iOS..."

# Build for iOS targets
TARGETS=("aarch64-apple-ios" "aarch64-apple-ios-sim" "x86_64-apple-ios")

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    rustup target add "$target" 2>/dev/null || true
    cargo build --release --target "$target" -p zk-ai-uniffi
done

# Generate Swift bindings
echo "Generating Swift bindings..."
cargo run --bin uniffi-bindgen -- generate --library \
    "$ROOT/crates/uniffi/target/aarch64-apple-ios/release/libzk_ai_uniffi.a" \
    --language swift \
    --out-dir "$ROOT/crates/uniffi/target/ios/bindings"

echo "iOS build complete."
echo "Next steps: create XCFramework and integrate into Xcode project."
