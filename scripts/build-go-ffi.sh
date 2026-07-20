#!/usr/bin/env bash
set -euo pipefail

# Build the zk-ai C static library for Go cgo linking.
# Outputs to crates/go-ffi/target/release/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Building zk-ai Go FFI static library..."

cd "$ROOT"
cargo build --release -p zk-ai-go-ffi

echo "Go FFI build complete."
echo "Static library: crates/go-ffi/target/release/libzk_ai_go_ffi.a"
echo ""
echo "To build the Go server:"
echo "  cd server && CGO_ENABLED=1 go build -o zk-ai-server ./cmd/zk-ai-server"
