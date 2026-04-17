#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Running host test to verify sha2 chip usage ==="
cargo run --release --bin verify-sha2-chips
echo "=== Host test passed: SHA-2 chips verified ==="
