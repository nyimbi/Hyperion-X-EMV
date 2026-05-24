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

coverage_tool_version=$(cargo llvm-cov --version)
cargo_version=$(cargo --version)
rustc_version=$(rustc --version)
target_triple=$(rustc -vV | sed -n 's/^host: //p')
source_commit=$(git rev-parse HEAD 2>/dev/null || printf 'unknown')

cargo llvm-cov clean --workspace

case "${KRN_COVERAGE_ENFORCE:-1}" in
    1)
        coverage_enforced=true
        cargo llvm-cov \
            --workspace \
            --all-targets \
            --all-features \
            --fail-under-lines 100 \
            --html \
            --output-dir target/coverage/html
        enforcement_note="100% line coverage was enforced for this run."
        ;;
    0)
        coverage_enforced=false
        cargo llvm-cov \
            --workspace \
            --all-targets \
            --all-features \
            --html \
            --output-dir target/coverage/html
        enforcement_note="100% line coverage was measured but not enforced for this run."
        ;;
    *)
        echo "KRN_COVERAGE_ENFORCE must be 0 or 1" >&2
        exit 2
        ;;
esac

cat > target/coverage/README.txt <<EOF
Hyperion-X-EMV 100% coverage report staging directory.

The HTML report in target/coverage/html is repository-local evidence only until
it is attached to the lab submission package with the submitted binary, profile
set, annex hashes, coverage tool version, Rust toolchain, target triple, and
reviewer acceptance.

$enforcement_note
EOF

cat > target/coverage/metadata.json <<EOF
{"type":"hyperion-coverage-report-metadata","source_commit":"$source_commit","cargo_version":"$cargo_version","rustc_version":"$rustc_version","target_triple":"$target_triple","coverage_tool_version":"$coverage_tool_version","workspace":true,"all_targets":true,"all_features":true,"line_coverage_threshold":100,"coverage_enforced":$coverage_enforced,"html_report":"target/coverage/html","readme":"target/coverage/README.txt","open_issue":"CERT-OPEN-009","does_not_close":"CERT-OPEN-009"}
EOF
