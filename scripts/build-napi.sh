#!/usr/bin/env bash
set -euo pipefail

# Build the zk-ai N-API addon for Electron desktop.
# Outputs to crates/napi/target/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Building zk-ai N-API addon for desktop..."

# Install napi-rs CLI if not present
if ! command -v napi &> /dev/null; then
    echo "Installing @napi-rs/cli..."
    npm install -g @napi-rs/cli
fi

cd "$ROOT/crates/napi"

# Build for the current platform
napi build --release --platform

echo "N-API build complete."
ls -la *.node 2>/dev/null || echo "No .node files found (check build output)"
