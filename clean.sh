#!/bin/bash
# Clean all setup files and build artifacts for simple test
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Cleaning build artifacts..."

# Simple test build directory
rm -rf "$ROOT_DIR/pil2-components/test/simple/build"

# Rust build artifacts
rm -rf "$ROOT_DIR/target"

# pil2-stark compiled library
rm -rf "$ROOT_DIR/pil2-stark/lib"

echo "Clean complete!"
