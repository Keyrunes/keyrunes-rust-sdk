#!/bin/bash
set -e

# Install required components if not present (optional, usually done in CI or manual setup)
# rustup component add llvm-tools-preview
# cargo install grcov

# Export flags for coverage
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="keyrunes-%p-%m.profraw"

echo "Building and running tests..."
cargo test

echo "Generating coverage report..."
mkdir -p target/debug/coverage/

grcov . \
  --binary-path ./target/debug/ \
  -s . \
  -t html \
  --branch \
  --ignore-not-existing \
  --ignore "/*" \
  --ignore "tests/*" \
  --ignore "examples/*" \
  -o ./target/debug/coverage/

echo "Coverage report generated at target/debug/coverage/index.html"
