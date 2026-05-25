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
# cargo-llvm-cov writes HTML into an `html/` child of --output-dir, so this
# script uses target/coverage as the report root and stages target/coverage/html.
# FFI coverage runs are single-threaded because the callback harness deliberately
# shares C ABI fixture counters to verify stateful transaction sequencing.
#
# The enforced line gate is the LCOV line ledger produced by the same coverage
# run. The merged `llvm-cov report --fail-under-lines 100` summary can report
# false missed lines when Rust builds the same source for lib, integration, and
# example targets with different cfg(test) shapes, emitting "mismatched data"
# diagnostics. We still generate the HTML report for review, but we fail the
# gate only from explicit DA records so a line is either executed or reported.

coverage_tool_version=$(cargo llvm-cov --version)
cargo_version=$(cargo --version)
rustc_version=$(rustc --version)
target_triple=$(rustc -vV | sed -n 's/^host: //p')
source_commit=$(git rev-parse HEAD 2>/dev/null || printf 'unknown')

cargo llvm-cov clean --workspace

run_lcov() {
    cargo llvm-cov --workspace --all-targets --all-features --lcov --output-path target/coverage/lcov.info -- --test-threads=1
}

generate_html() {
    cargo llvm-cov report --html --output-dir target/coverage
}

validate_lcov_100() {
    awk '
        BEGIN { total = 0; missed = 0; }
        /^DA:/ {
            total += 1;
            split(substr($0, 4), fields, ",");
            if (fields[2] + 0 == 0) {
                missed += 1;
            }
        }
        END {
            if (total == 0) {
                print "coverage LCOV contained no DA records" > "/dev/stderr";
                exit 2;
            }
            if (missed != 0) {
                printf "coverage below 100%%: %d missed source lines out of %d\n", missed, total > "/dev/stderr";
                exit 1;
            }
            printf "LCOV source line coverage: %d/%d = 100%%\n", total, total;
        }
    ' target/coverage/lcov.info
}

case "${KRN_COVERAGE_ENFORCE:-1}" in
    1)
        coverage_enforced=true
        run_lcov
        validate_lcov_100
        generate_html
        enforcement_note="100% line coverage was enforced for this run from target/coverage/lcov.info."
        ;;
    0)
        coverage_enforced=false
        run_lcov
        generate_html
        enforcement_note="100% line coverage was measured but not enforced for this run."
        ;;
    *)
        echo "KRN_COVERAGE_ENFORCE must be 0 or 1" >&2
        exit 2
        ;;
esac

cat > target/coverage/README.txt <<EOF
Hyperion-X-EMV 100% coverage report staging directory.

The HTML report in target/coverage/html and the LCOV ledger in
target/coverage/lcov.info are repository-local evidence only until they are
attached to the lab submission package with the submitted binary, profile set,
annex hashes, coverage tool version, Rust toolchain, target triple, and
reviewer acceptance.

$enforcement_note
EOF

cat > target/coverage/metadata.json <<EOF
{"type":"hyperion-coverage-report-metadata","source_commit":"$source_commit","cargo_version":"$cargo_version","rustc_version":"$rustc_version","target_triple":"$target_triple","coverage_tool_version":"$coverage_tool_version","workspace":true,"all_targets":true,"all_features":true,"line_coverage_threshold":100,"coverage_enforced":$coverage_enforced,"html_report":"target/coverage/html","lcov_report":"target/coverage/lcov.info","readme":"target/coverage/README.txt","open_issue":"CERT-OPEN-009","does_not_close":"CERT-OPEN-009"}
EOF
