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
cargo run --quiet --example krn_prelab_static_fuzz_plan | diff -u docs/prelab_static_fuzz_plan.json -
cargo run --quiet --example krn_prelab_fuzz_seed_corpus | diff -u docs/prelab_fuzz_seed_corpus.json -
cargo run --quiet --example krn_public_standards_watch | diff -u docs/public_standards_watch.json -
cargo run --quiet --example krn_certification_security_assessment_plan -- --json | diff -u docs/certification_security_assessment_plan.json -
cargo run --quiet --example krn_certification_security_assessment_plan -- --markdown | diff -u docs/certification_security_assessment_plan.md -
cargo run --quiet --example krn_certification_device_evidence_plan -- --json | diff -u docs/certification_device_evidence_plan.json -
cargo run --quiet --example krn_certification_device_evidence_plan -- --markdown | diff -u docs/certification_device_evidence_plan.md -
cargo run --quiet --example krn_certification_integration_report_plan -- --json | diff -u docs/certification_integration_report_plan.json -
cargo run --quiet --example krn_certification_integration_report_plan -- --markdown | diff -u docs/certification_integration_report_plan.md -
cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui
cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace
cargo run --quiet --example krn_basic_pos
```

If a generator output changes, the code or annex that caused the change should
be reviewed and committed with the regenerated artifact.

The ABI conformance statement includes capability-readiness records for
implemented engines such as CVM/PIN, TRM/TAA, ODA/CDA, issuer scripts, and
Contactless C-8 behavior. These records mean the repository has executable
implementation and tests, but the capability remains
`implemented-standard-validation-pending` until licensed standards review,
scheme/acquirer profile reconciliation, device/L1 evidence, trace packages, and
lab approval are attached.

## Build Provenance

The build manifest generator emits canonical hashes for source modules,
controlled annexes, and evidence generators:

```sh
cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml .github/workflows/prelab.yml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/scheme_profile_dictionary.md docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json docs/prelab_no_crash_smoke.json docs/prelab_static_fuzz_plan.json docs/prelab_fuzz_seed_corpus.json docs/public_standards_watch.json docs/certification_evidence_checklist.json docs/certification_evidence_checklist.md docs/certification_evidence_intake.json docs/certification_evidence_intake.md docs/certification_freeze_manifest.json docs/certification_freeze_manifest.md docs/certification_security_assessment_plan.json docs/certification_security_assessment_plan.md docs/certification_device_evidence_plan.json docs/certification_device_evidence_plan.md docs/certification_integration_report_plan.json docs/certification_integration_report_plan.md docs/certification_report_pack.json docs/certification_report_pack.md docs/certification_report_ui.html docs/certification_open_issues.md docs/standards_watch.md docs/open_source.md docs/coverage.md scripts/coverage_100.sh examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_cabi_script_adapter.rs examples/krn_certification_evidence_checklist.rs examples/krn_certification_evidence_intake.rs examples/krn_certification_freeze_manifest.rs examples/krn_certification_security_assessment_plan.rs examples/krn_certification_device_evidence_plan.rs examples/krn_certification_integration_report_plan.rs examples/krn_certification_report_ui.rs examples/krn_certification_workspace.rs examples/krn_basic_pos.rs examples/krn_scheme_profile_dictionary.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs examples/krn_prelab_no_crash_smoke.rs examples/krn_prelab_static_fuzz_plan.rs examples/krn_prelab_fuzz_seed_corpus.rs examples/krn_public_standards_watch.rs examples/krn_emv_decode.rs
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
Callers should also query `krn_get_callback_timeout_policy` during adapter
startup and apply those bounded budgets to APDU transport, host authorization,
PIN entry, and contactless UI callbacks. The values are part of the ABI
contract so timeout handling can be traced consistently during certification
report production.

The `krn_basic_pos` example is the smallest end-to-end integration shape in the
repository. It creates a C ABI context, loads the certification profile fixture,
sets sale parameters, routes APDUs through a scripted reader, sends ARQC data
to a stub host, applies the host response, performs issuer authentication, and
finishes with second GENERATE AC.

If the active profile enables TRM random transaction selection, Level 3 must
call `krn_set_trm_random_selection_sample` after
`krn_set_transaction_params` for that transaction. The basic PoS example uses
an explicit out-of-selection sample so the scripted sale demonstrates the
integration contract without relying on hidden kernel randomness.

## Profile Usage

Do not treat bundled example or fixture profiles as production authority.

Certification and production profile loading should use:

- Signed profile source metadata.
- Monotonic profile versioning.
- Loaded profile SHA-256 captured through the ABI and trace identity for
  certification-freeze reconciliation.
- Scheme/acquirer-approved AIDs.
- Accepted TAC/IAC and limits.
- CAPK checksums and provenance.
- Explicit contact/contactless interface mapping.
- Review of contactless C-8 and bulletin scope.

Hyperion rejects example-only profiles in certification and production modes.
Integrations should store the reported profile version and SHA-256 alongside
build hashes, trace packs, and test-tool outputs.

Before report production, run the variable-data boundary audit:

```sh
cargo run --quiet --example krn_variable_data_boundary_audit -- src
```

This audit checks production Rust source for scheme/profile/CAPK/TAC/IAC
fixture literals. A passing audit supports the signed-profile boundary, but it
does not replace signed scheme/acquirer profile bundles, accepted CAPKs,
lab-supplied vectors, or submitted-build review.

For report production, `krn_certification_evidence_checklist` emits the
external attachment checklist, `krn_certification_evidence_intake` emits
pending attachment slots for hash capture and review disposition,
`krn_certification_freeze_manifest` emits submitted-build hash slots, and
`krn_certification_security_assessment_plan` emits external-assessor controls
for `CERT-OPEN-008`. `krn_certification_device_evidence_plan` emits device,
Level 1, and PCI/PED controls for `CERT-OPEN-005`, `CERT-OPEN-006`, and
`CERT-OPEN-007`. `krn_certification_integration_report_plan` emits full
integration-report, Level 3/acquirer reconciliation, and masked trace-pack
controls for `CERT-OPEN-009` and `CERT-OPEN-012`.
`krn_certification_report_ui` emits a static workbench and JSON/Markdown
exports that index repository artifacts, pending external reports, evidence
attachments, open certification gates, checked-in artifact file size and
SHA-256 inventory, and the commands needed to regenerate evidence.
`krn_certification_workspace` emits a complete local workspace with
`index.html`, `workspace_manifest.json`, `workspace_inventory.json`,
`workspace_inventory.md`, report-pack exports, evidence checklists,
intake/freeze ledgers, security/device/integration plans, quality artifacts,
the ABI statement, empty `attachments/CERT-OPEN-*` staging directories, an
attachment-slot guide, `attachment_audit.html`, and attachment audit
JSON/Markdown. Treat it as a review bundle; attach only accepted, hash-bound
artifacts to a certification submission.

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
