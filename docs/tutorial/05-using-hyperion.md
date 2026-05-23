# Using Hyperion-X-EMV

This tutorial shows how to work with the repository as a developer or
integrator. It focuses on local build, test, evidence generation, and the
integration model.

## Build The Kernel

From the repository root:

```sh
cargo build
```

Release builds use deterministic-friendly settings in `Cargo.toml`, including
LTO and `panic = "abort"`.

## Run The Test Suite

Run all repository tests:

```sh
cargo test
```

Run example evidence generators as tests:

```sh
cargo test --examples
```

Run formatting and lint gates:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

These are repository quality gates. They do not replace the formal 100%
coverage report, full EMV integration report, lab APDU trace pack, static
analysis report, or fuzzing report required before final certification.

## Regenerate Controlled Evidence

Hyperion has deterministic evidence generators. The expected workflow is to
regenerate an artifact and compare it to the checked-in version.

```sh
cargo run --quiet --example krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json -
cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -
cargo run --quiet --example krn_scheme_profile_dictionary | diff -u docs/scheme_profile_dictionary.md -
cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -
cargo run --quiet --example krn_prelab_no_crash_smoke | diff -u docs/prelab_no_crash_smoke.json -
```

If a generator output changes, the code or annex that caused the change should
be reviewed and committed with the regenerated artifact.

## Build Provenance

The build manifest generator emits canonical hashes for source modules,
controlled annexes, and evidence generators:

```sh
cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml .github/workflows/prelab.yml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/scheme_profile_dictionary.md docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json docs/prelab_no_crash_smoke.json docs/prelab_static_fuzz_plan.json docs/certification_open_issues.md docs/standards_watch.md docs/open_source.md docs/coverage.md scripts/coverage_100.sh examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_cabi_script_adapter.rs examples/krn_scheme_profile_dictionary.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs examples/krn_prelab_no_crash_smoke.rs examples/krn_prelab_static_fuzz_plan.rs examples/krn_emv_decode.rs
```

Use this when preparing a submission package or checking that source and annex
hashes match an intended build.

## Decode EMV Data For Review

The decoder utility helps inspect TLV, DOL, APDU, and EMV data shapes without
turning the decoder into certification evidence:

```sh
cargo run --quiet --example krn_emv_decode -- tlv 6F108407A0000000031010A5055003564953
cargo run --quiet --example krn_emv_decode -- sw 9000
cargo run --quiet --example krn_emv_decode -- termcap E0B8C8
```

Default decoder behavior suppresses payloads where raw data could be sensitive.

## Understand The Integration Boundary

A terminal integration should treat Hyperion as a kernel library, not a full
payment application. The integrator remains responsible for:

- Device drivers and Level 1 communication.
- UI and merchant workflow.
- Online host message formatting.
- Receipt and settlement behavior.
- PED and PCI PTS integration.
- Signed profile loading and operational key management.
- Certification package assembly.

Hyperion remains responsible for Level 2 EMV transaction behavior within its
declared scope.

## C ABI Integration Shape

The C ABI exists so terminal software can integrate the Rust kernel without
rewriting the Level 2 logic. The integration should:

1. Initialize the ABI with the expected version and callbacks.
2. Load or select an accepted profile.
3. Start a transaction with terminal parameters.
4. Let the kernel build APDUs or drive runtime callbacks.
5. Return card responses to the kernel.
6. Provide host response data when the kernel goes online.
7. Read the final outcome, TVR, TSI, CVM result, script results, and masked
   trace evidence.

The ABI is defensive about buffer ownership. Callers should probe output sizes,
allocate caller-owned buffers, and retry with sufficient capacity.

## Profile Usage

Do not treat bundled example or fixture profiles as production authority.

Certification and production profile loading should use:

- Signed profile source metadata.
- Monotonic profile versioning.
- Scheme/acquirer-approved AIDs.
- Accepted TAC/IAC and limits.
- CAPK checksums and provenance.
- Explicit contact/contactless interface mapping.
- Review of contactless C-8 and bulletin scope.

Hyperion rejects example-only profiles in certification and production modes.

## Trace Usage

Masked traces support debugging and lab review, but they are not a license to
log sensitive data. Production trace policy suppresses:

- PAN except masked form.
- Track 2 equivalent data.
- Transaction cryptograms.
- Issuer authentication data.
- Issuer script command bytes.
- Signed dynamic authentication data.
- Profile-defined issuer application data.

Contributors adding trace fields should preserve that policy.

## A Minimal Developer Workflow

For a documentation or test-only change:

```sh
git diff --check
cargo test
```

For behavior changes:

```sh
cargo fmt --check
cargo test
cargo test --examples
cargo clippy --all-targets --all-features -- -D warnings
```

For evidence-affecting changes, also regenerate and diff the relevant evidence
artifacts.
