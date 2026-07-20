#!/usr/bin/env bash
set -euo pipefail

# Build the zk-ai WASM module for browser use.
# Outputs to crates/wasm/pkg/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Building zk-ai WASM (WebGPU + CPU fallback)..."

# Install wasm-pack if not present
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    cargo install wasm-pack
fi

cd "$ROOT/crates/wasm"
wasm-pack build --target web --release --out-dir pkg

echo "WASM build complete: crates/wasm/pkg/"
ls -la pkg/
