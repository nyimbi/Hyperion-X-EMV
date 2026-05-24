# 100% Coverage Report Workflow

Hyperion targets a formal 100% unit coverage report before any final
certification submission. This document defines the repository workflow for
preparing that report. It does not close `CERT-OPEN-009`; the report must still
be attached to the lab submission package and accepted for the submitted
binary, profile set, and annex hashes.

## Tool

Use `cargo-llvm-cov` for Rust source-based coverage:

```sh
cargo install cargo-llvm-cov --locked
```

The workflow uses LLVM source-based coverage through Cargo-compatible test
execution. The report must record the installed `cargo-llvm-cov` version, Rust
toolchain, target triple, source commit, feature flags, and submitted artifact
hashes.

## Command

Run the repository script:

```sh
scripts/coverage_100.sh
```

The script:

- Verifies that `cargo llvm-cov` is installed.
- Cleans workspace coverage state.
- Runs all workspace targets and features under coverage.
- Fails unless line coverage reaches 100%.
- Writes an HTML report under `target/coverage/html`.
- Writes a local staging note under `target/coverage/README.txt`.
- Writes machine-readable run metadata under `target/coverage/metadata.json`,
  including source commit, Cargo version, Rust compiler version, target triple,
  `cargo-llvm-cov` version, target/feature scope, threshold, enforcement mode,
  and the `CERT-OPEN-009` non-closure marker.

After a run, audit the staged package:

```sh
cargo run --quiet --example krn_coverage_package_audit -- --root target/coverage
```

The audit checks `metadata.json`, `README.txt`, and `html/index.html`, hashes
present files, validates the expected metadata fields, and reports one of these
states:

- `measurement_only_unreviewed`: a structurally reviewable package generated
  without 100% enforcement, suitable for trend visibility and CI artifacts.
- `certification_candidate_unreviewed`: a structurally reviewable package whose
  metadata says 100% line coverage was enforced; submitted-build binding and
  external acceptance are still required.
- `missing_or_malformed` or `incomplete`: the package is not ready for review.

The strict 100% gate is the default. For pre-lab measurement without closing
the certification blocker, set `KRN_COVERAGE_ENFORCE=0`:

```sh
KRN_COVERAGE_ENFORCE=0 scripts/coverage_100.sh
```

That mode still runs the same targets/features and writes the same report, but
it does not fail the process when coverage is below 100%. It is suitable for
trend visibility and artifact review only. The final certification-facing run
must use the default enforcing mode.

## Acceptance Rules

A coverage report is certification-facing only when it:

- Was generated from the exact source commit submitted to the lab.
- Uses the same Rust toolchain, target, feature set, and build mode recorded in
  the submission package.
- Is tied to the submitted kernel binary hash, profile hash, CAPK bundle hash,
  test-vector hash, and traceability matrix hash.
- Shows 100% line coverage for the submitted Rust kernel scope.
- Records all exclusions and has those exclusions accepted by the reviewer or
  lab.
- Is attached alongside the full EMV integration report.

Passing `cargo test` is necessary but not sufficient. A green test suite proves
that tests pass; it does not prove measured coverage.

## Continuous Integration

The pre-lab GitHub Actions workflow at `.github/workflows/prelab.yml` runs the
normal Rust quality gates and a separate enforced coverage job. The coverage job
installs `cargo-llvm-cov`, runs `KRN_COVERAGE_ENFORCE=1 scripts/coverage_100.sh`,
and audits the staged package with `krn_coverage_package_audit --require-package`
before uploading `target/coverage`, including `coverage_audit.json`, as a
workflow artifact. This proves the repository 100% line-coverage gate for that
commit, while `CERT-OPEN-009` still requires submitted-binary/profile binding
and external acceptance before final certification closure.

The CI artifact remains repository evidence until the submitted binary, profiles,
CAPKs, vectors, traceability matrix, and reviewer acceptance are bound into the
lab submission package.

The uploaded `target/coverage` directory must contain both the HTML report and
`metadata.json`. The metadata file is intended for report production and
submission review; it is not certification closure unless the enforcing mode
was used and the report is accepted for the submitted artifact set.

## Contributor Use

Contributors can use this workflow before submitting behavior changes:

```sh
cargo fmt --check
cargo test
cargo test --examples
scripts/coverage_100.sh
```

If coverage is below 100%, add meaningful tests for the uncovered behavior
instead of excluding code by default. Exclusions should be rare, explicit, and
reviewed as certification evidence decisions.

## Relationship To Open Issues

`CERT-OPEN-009` remains open until the 100% unit coverage report and full EMV
test-plan integration report are attached and accepted for the submitted
artifact set. This repository workflow is a preparation path, not approval.
