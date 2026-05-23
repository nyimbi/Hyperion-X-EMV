#!/usr/bin/env sh
set -eu

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    cat >&2 <<'EOF'
missing required coverage tool: cargo-llvm-cov

Install it with:
  cargo install cargo-llvm-cov --locked

Then rerun:
  scripts/coverage_100.sh
EOF
    exit 2
fi

mkdir -p target/coverage

cargo llvm-cov clean --workspace
cargo llvm-cov \
    --workspace \
    --all-targets \
    --all-features \
    --fail-under-lines 100 \
    --html \
    --output-dir target/coverage/html

cat > target/coverage/README.txt <<'EOF'
Hyperion-X-EMV 100% coverage report staging directory.

The HTML report in target/coverage/html is repository-local evidence only until
it is attached to the lab submission package with the submitted binary, profile
set, annex hashes, coverage tool version, Rust toolchain, target triple, and
reviewer acceptance.
EOF
