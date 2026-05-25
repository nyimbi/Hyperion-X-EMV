# Hyperion EMV Kernel

Hyperion is an open-source, data-driven EMV Level 2 kernel foundation. The
kernel code is written in Rust; the certification target, scheme profile,
device profile, runtime policy, test plan, evidence bindings, and external
authority references are supplied as signed or hash-pinned data bundles.

That split is the core design choice. EMV protocol behavior should be small,
deterministic, auditable code. Certification variability should be reviewable
data that can be changed, linted, compiled, signed, frozen, and submitted
without rebuilding a different kernel for every scheme, acquirer, terminal, or
test campaign.

Hyperion is being built toward certification readiness for contact EMV and
contactless Book C-8 flows, with a C ABI for terminal integration and a
repository-owned evidence pack for pre-lab review.

This repository is not a final certification claim. It is a controlled
engineering baseline pending licensed EMVCo, scheme, acquirer, PCI PTS, device,
and lab review. Licensed standards, signed profiles, accepted CAPKs, lab
vectors, test-tool results, and approval artifacts prevail over this repository
on conflict.

## Why Hyperion Exists

Payment infrastructure should be inspectable. New fintechs, terminal builders,
acquirers, processors, and researchers should not have to start from an opaque
kernel, a private test harness, and a set of assumptions that only become
visible during lab failure.

Hyperion exists to make the certification path legible before a formal
submission. The repository provides source, tooling, evidence generators,
traceability, masked trace fixtures, report-production tools, and explicit
open-issue registers. The external authorities still decide certification; the
project makes the work needed for that decision concrete and reproducible.

## Why DataCraft Is Building This

DataCraft is building Hyperion because robust payment systems need a shared
technical foundation that is open to inspection, hard to misuse, and practical
for teams without large incumbent payment-kernel budgets.

The goal is not to bypass EMVCo, schemes, acquirers, PCI, device vendors, or
recognized labs. The goal is to reduce avoidable ambiguity before those parties
review a product. By making kernel behavior, configuration boundaries,
evidence production, and remaining blockers visible in one open repository,
DataCraft can help the community converge on better tests, clearer reports,
safer integration patterns, and fewer private reinventions of the same
security-sensitive machinery.

## The Data-Driven Contract

Hyperion treats payment behavior as two different kinds of material:

- **Invariant kernel logic** lives in Rust: TLV, DOL, APDU, selection, GPO,
  AFL, READ RECORD, CVM, TRM, TAA, GENERATE AC handling, issuer
  authentication/script sequencing, ODA structure, contactless C-8 support,
  masking, provenance, and ABI boundaries.
- **Variable certification data** lives in bundles: scheme profiles, AIDs,
  CAPK metadata, TAC/IAC values, limits, CVM extension choices, runtime
  timeout policy, device/L1/PCI references, certification test scope, vector
  bindings, report hashes, trace bindings, and external evidence references.

A different certification campaign should therefore mean a different reviewed
bundle, not a forked kernel. The Rust loader remains authoritative: browser and
terminal tools help authors, but final acceptance is gated by bundle parsing,
signature or trust-anchor checks, rollback policy, embedded profile validation,
timeout bounds, vector status, artifact hashes, and production/test/certification
mode separation.

## Current Status

- Kernel specification baseline: `docs/spec.md`, version 6.0.
- Engineering notes and certification boundaries: `docs/eng_notes.md`.
- Lab submission manifest: `docs/lab_submission_manifest.md`.
- Open external blockers: `docs/certification_open_issues.md`.
- Requirement traceability: `docs/requirements_traceability.csv` and
  `docs/requirements-traceability-matrix.csv`.
- Public standards drift watch: `docs/standards_watch.md` and
  `docs/public_standards_watch.json`.
- Tooling completeness audit: `docs/tooling_completeness_audit.json` and
  `docs/tooling_completeness_audit.md`.
- Data-driven certification bundle: `docs/certification_data_bundle.json`,
  `docs/certification_data_bundle_trust_anchors.json`,
  `docs/certification_data_bundle.md`,
  `docs/certification_data_bundle_workbench.html`,
  `docs/certification_data_bundle_lint.json`, and
  `docs/certification_data_bundle_lint.md`.
- Certification evidence checklist: `docs/certification_evidence_checklist.json`
  and `docs/certification_evidence_checklist.md`.
- Clean-room open-source reference review: `docs/open_source.md`.
- Tutorial learning path: `docs/tutorial/README.md`.
- 100% coverage workflow: `docs/coverage.md` and `scripts/coverage_100.sh`.
- Static/fuzz evidence plan: `docs/prelab_static_fuzz_plan.json`.
- Fuzz seed corpus manifest: `docs/prelab_fuzz_seed_corpus.json`.
- Certification report workbench: `docs/certification_report_ui.html`,
  `docs/certification_report_pack.json`, and
  `docs/certification_report_pack.md`.
- One-command local certification workspace:
  `cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace`
  with a workspace manifest and generated file hash inventory.
- Pre-lab CI workflow: `.github/workflows/prelab.yml`.
- Session progress log: `docs/progress_log.md`.

Repository-controlled evidence is intentionally separated from external
certification evidence. Passing local tests does not close open items that
require recognized laboratory reports, signed profiles, scheme or acquirer
authority, device evidence, PCI/PED evidence, or lab-supplied cryptographic
vectors.

## Why This Is Open Source

Hyperion is MIT-licensed so fintech teams, terminal builders, acquirers,
researchers, test labs, and independent reviewers can inspect the source,
reproduce evidence, contribute test cases, and harden the kernel together. The
goal is a robust shared foundation for new payment products rather than a
closed implementation that each company must rediscover from scratch.

Open source also changes the testing model. A private kernel can only be
tested by the people who can see it. Hyperion invites community review of
parsers, trace replay, no-crash corpora, profile validation, documentation,
integration harnesses, report production, and pre-lab evidence. That is how the
project intends to crowdsource certification preparation and testing: by making
the evidence surface explicit enough for many teams to improve it.

Crowdsourcing does not replace formal approval. EMVCo, schemes, acquirers, PCI
PTS, device authorities, recognized labs, CAPK owners, and test-tool providers
retain their own authority, licensing terms, and acceptance criteria.

## Language Choices

Rust is the kernel implementation language because the Level 2 core needs
memory safety without garbage collection, deterministic resource use, explicit
error handling, strong typing for EMV data objects, and stable `staticlib` /
`cdylib` outputs for terminal integration. Those properties fit a payment
kernel that must keep PAN, cryptograms, PIN handles, issuer scripts, and
profile data inside narrow ownership boundaries while still running on
resource-constrained or vendor-controlled terminal platforms.

Python is the development automation language, not the certification runtime
kernel. It is reserved for scripts and tooling where fast iteration matters:
lab-artifact preparation, report shaping, trace analysis, corpus triage,
fixture conversion, CI glue, and reviewer utilities. Python-generated outputs
must be reproducible, checked, and treated as tooling evidence around the Rust
kernel rather than as a substitute for reviewed kernel behavior.

## Data-Driven Certification Bundles

For the detailed authoring workflow, field-by-field bundle anatomy, secure
signing and trust-anchor guidance, validation/lint commands, TUI/workbench
usage, and report-tool sequence, read
`docs/tutorial/08-data-bundles-and-tools.md`.

A Hyperion data bundle is the unit of certification variability. It carries the
scheme profile JSON, vector-bundle reference, terminal/device profile, runtime
timeout policy, kernel registry, CVM extension rules, test-plan cases, artifact
hashes, and a trust-anchor-bound signature envelope. The same binary can be
exercised against different certification or testing targets by changing the
bundle and trust-anchor data, not the Rust source.

The checked-in fixture uses schema version `hyperion-certification-bundle-1.0`
and illustrates the fields every author must understand:

- `submission_scope`: product, version, interfaces, target, authorities, and
  standards scope being claimed.
- `standards_target`: public standards-watch and bulletin reconciliation data.
- `terminal_profile`: device, L1, PCI/PED, reader, and deployment references.
- `runtime_policy`: callback timeouts and trace masking policy enforced by the
  runtime.
- `kernel_registry`: the mapping from interface and scheme profile to kernel
  behavior.
- `cvm_extensions`: CVM and CDCVM policy data that belongs outside source code.
- `test_plan`: named pre-lab or certification cases the bundle expects to
  exercise.
- `artifact_hashes`: hashes for profiles, vectors, reports, traces, and other
  evidence attachments.
- `scheme_profile_set_json`: the embedded signed profile set consumed by the
  kernel.
- `vector_bundle_json`: the embedded or referenced vector bundle and its
  certification/test/fixture status.
- `signature`: the payload signature that binds the bundle to configured trust
  anchors.

### Create A Data Bundle

1. Generate the local workbench and fixture files:

   ```sh
   cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle
   ```

2. Open `target/hyperion-cert-bundle/certification_bundle_workbench.html` in a
   local browser, or use the checked-in
   `docs/certification_data_bundle_workbench.html` as a reference. The
   workbench explains each field's role, impact, utilization, and security
   consequences while producing a compiled JSON preview.

3. Fill in the claimed scope first: product name, product version,
   certification target, interfaces, authorities, L1/device references, PCI/PED
   references, and standards/bulletin scope. Pending external evidence can be
   represented honestly, but it must not be described as accepted.

4. Attach the operational data: scheme profile set, CAPK metadata, TAC/IAC
   values, limits, CVM extensions, runtime callback timeout policy, kernel
   registry entries, test cases, vector bundle, and artifact hashes.

5. Sign the bundle payload and configure trust anchors. The checked-in trust
   anchor fixture is for local reproducibility; certification and production
   submissions must protect signer material and expose only verification data
   appropriate for the review environment.

6. Run the authoritative Rust validator:

   ```sh
   cargo run --quiet --example krn_certification_bundle -- --validate --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json
   ```

7. Run lint and compile checks before review:

   ```sh
   cargo run --quiet --example krn_certification_bundle -- --lint --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json
   ```

8. For terminal-only provisioning, use the TUI:

   ```sh
   cargo run --quiet --example krn_certification_bundle_tui -- --out target/hyperion-cert-bundle-tui
   ```

9. Freeze the resulting hashes into the report package and attach matching
   binary, profile, CAPK, vector, trace, coverage, integration, security,
   device, L1, PCI/PED, scheme, acquirer, and lab evidence. The bundle is only
   useful for certification when it is bound to the exact submitted artifact
   set.

## Certification Process

Hyperion separates certification preparation into four layers:

1. **Build and local proof.** Run the Rust tests, example tests, formatting,
   clippy, traceability checks, deterministic artifact drift checks, bundle
   validation, bundle linting, variable-data boundary audit, and 100% coverage
   workflow. This proves repository-controlled behavior is coherent.

2. **Evidence binding.** Freeze the exact submitted binary hash, ABI version,
   profile hash, CAPK hash, vector hash, traceability matrix hash, report-pack
   hash, coverage package, and data-bundle hash. Claims that are not tied to a
   concrete artifact set are not certification-ready.

3. **External review.** Submit the product, device, profile set, vectors,
   reports, masked traces, security assessment, and supporting evidence to the
   relevant lab, scheme, acquirer, PCI/PED, device, and L1 authorities. Their
   accepted artifacts control the final result.

4. **Closure and maintenance.** Close `CERT-OPEN-*` items only when the required
   authority, artifact, hash, metadata, and acceptance gate are present. New
   schemes, devices, or certification campaigns should be represented by new
   data bundles and evidence bindings, not by unexplained source forks.

The repository can help generate, audit, and organize the package. It cannot
self-certify licensed standards, scheme interpretation, accepted CAPKs,
lab-supplied ODA vectors, device/L1 approval, PCI/PED approval, test-tool
results, or signed approval artifacts.

## Scope

In scope for this kernel:

- BER-TLV parsing and admission policy.
- DOL parsing and deterministic DOL construction.
- PSE, PPSE, and direct AID selection.
- GPO response parsing and AFL record planning.
- READ RECORD ingestion with card-originated tag admission controls.
- TVR and TSI symbolic bit mutation with RFU protection.
- Processing restrictions.
- CVM list parsing and evaluation with PED-owned PIN handles.
- Terminal risk management.
- Terminal action analysis with signed-profile TAC/IAC inputs and
  deterministic fallback keys.
- GENERATE AC request/response handling.
- Online authorization package construction without issuer cryptogram custody.
- Issuer authentication and issuer script sequencing.
- ODA scaffolding and structural SDA, DDA, and CDA evidence paths.
- Contactless C-8 outcome, limit, CDCVM, TTQ, and relay-resistance scaffolding.
- Masked trace generation, APDU replay fixtures, and decoder tooling.
- Stable C ABI surfaces for terminal and test-harness integration.

Out of scope for repository-only closure:

- EMVCo Level 2 approval.
- Scheme approval.
- Real CAPK authority.
- Lab-supplied SDA, DDA, and CDA certification vectors.
- Full lab APDU trace pack.
- PCI PTS/PED certification.
- Device and L1 approval evidence.
- Third-party security assessment acceptance.

Those items are tracked in `docs/certification_open_issues.md`.

## Architecture

The crate is organized as small protocol modules rather than a terminal
application. The kernel owns invariant EMV behavior. Scheme, acquirer, CAPK,
limit, and device-specific inputs must arrive through signed configuration or
explicit ABI calls.

Core modules:

- `src/ffi.rs`: C ABI, runtime callbacks, transaction lifecycle, and output
  buffers.
- `src/tlv.rs`: BER-TLV parser and traversal helpers.
- `src/dol.rs`: DOL parser, `DataStore`, padding policy, and DOL construction.
- `src/apdu.rs`: APDU command construction.
- `src/sw.rs`: context-specific status word policy.
- `src/selection.rs`: candidate AID parsing and signed-profile matching.
- `src/gpo.rs`: GPO response and PDOL extraction.
- `src/afl.rs`: AFL parsing and READ RECORD planning.
- `src/record.rs`: record parsing, card-originated tag admission, and
  cardholder-data consistency.
- `src/state.rs`: TVR and TSI types.
- `src/restrictions.rs`: processing restriction checks.
- `src/cvm.rs`: CVM list evaluation and PED handle model.
- `src/trm.rs`: terminal risk management.
- `src/taa.rs`: terminal action analysis.
- `src/gac.rs`: GENERATE AC response parsing and online handoff package.
- `src/oda.rs`: ODA selection, certificate recovery helpers, and structural
  vector validation.
- `src/issuer.rs`: issuer authentication and issuer script parsing/results.
- `src/c8.rs`: contactless outcome and C-8 oriented helpers.
- `src/config.rs`: signed profile loading and certification/profile gates.
- `src/trace.rs`: masked APDU/TLV traces and deterministic replay fixtures.
- `src/quality.rs`: repository-controlled quality gate and no-crash evidence.
- `src/provenance.rs`: canonical build provenance and hashing.
- `src/perf.rs`: performance profile parsing and counters.

The library is built as:

- `rlib` for Rust integration.
- `staticlib` for static C ABI integration.
- `cdylib` for dynamic C ABI integration.

## Security And Data Custody

Hyperion deliberately avoids broad data custody:

- The kernel does not own issuer master keys.
- The kernel does not generate ARQC, ARPC, TC, or AAC cryptograms.
- The kernel does not accept clear PIN values.
- Offline PIN uses opaque PED-owned handles.
- Production trace policy suppresses PAN, Track 2, cryptograms, issuer
  authentication data, issuer script command bytes, signed dynamic
  authentication data, and profile-defined issuer application data.
- Debug implementations for sensitive structures report lengths and policy
  text rather than raw values.
- Card-originated records cannot overwrite terminal-owned, host-owned,
  generated, or dynamic authentication data objects.

These constraints are part of the certification boundary, not incidental
implementation details.

## Prerequisites

- Rust toolchain compatible with `rust-version = "1.70"` in `Cargo.toml`.
- Standard Cargo tooling: `cargo build`, `cargo test`, `cargo clippy`, and
  `cargo fmt`.
- No runtime network dependency is required for normal local builds and tests.

## Quick Start

Build the library:

```sh
cargo build
```

Run the full test suite:

```sh
cargo test
```

Run example/test binaries:

```sh
cargo test --examples
```

Run the strict lint gate:

```sh
cargo clippy --all-targets --all-features -- -D warnings
```

Check formatting and whitespace:

```sh
cargo fmt --check
git diff --check
```

## Pre-Lab Quality Gate

The local engineering gate is intentionally stronger than a single test run:

```sh
cargo fmt --check
git diff --check
cargo test
cargo test --examples
cargo clippy --all-targets --all-features -- -D warnings
cargo run --quiet --example krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json -
cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -
cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl --require-prelab-fixture | diff -u docs/prelab_trace_pack_audit.json -
cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl --markdown | diff -u docs/prelab_trace_pack_audit.md -
cargo run --quiet --example krn_scheme_profile_dictionary | diff -u docs/scheme_profile_dictionary.md -
cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -
cargo run --quiet --example krn_prelab_no_crash_smoke | diff -u docs/prelab_no_crash_smoke.json -
cargo run --quiet --example krn_prelab_static_fuzz_plan | diff -u docs/prelab_static_fuzz_plan.json -
cargo run --quiet --example krn_prelab_fuzz_seed_corpus | diff -u docs/prelab_fuzz_seed_corpus.json -
cargo run --quiet --example krn_public_standards_watch | diff -u docs/public_standards_watch.json -
cargo run --quiet --example krn_tooling_completeness_audit -- --json | diff -u docs/tooling_completeness_audit.json -
cargo run --quiet --example krn_tooling_completeness_audit -- --markdown | diff -u docs/tooling_completeness_audit.md -
```

The generated quality manifest is `docs/prelab_quality_gates.json`. It records
local repository gates only. It does not replace formal unit coverage,
integration, static analysis, fuzzing, lab trace, or approval reports.

The repository coverage workflow is documented in `docs/coverage.md` and
implemented by `scripts/coverage_100.sh`. By default it uses `cargo-llvm-cov`
to fail unless line coverage reaches 100%, then stages an HTML report under
`target/coverage/html` plus run metadata under `target/coverage/metadata.json`.
Use `krn_coverage_package_audit` to inspect the staged package and distinguish
measurement-only evidence from an enforced 100% candidate that still awaits
submitted-build and external reviewer acceptance.
The CI workflow runs the same script with `KRN_COVERAGE_ENFORCE=1`, so protected
pre-lab gates fail below 100% line coverage. `CERT-OPEN-009` remains open until
the enforced report is tied to the submitted binary/profile set and accepted as
certification evidence.

## Evidence Generators

The repository includes deterministic examples that generate or inspect
controlled evidence:

- `krn_abi_conformance_statement`: emits ABI conformance JSON with
  capability-readiness records for implemented behavior that remains
  standard-validation pending.
- `krn_prelab_trace_pack`: emits masked pre-lab APDU trace JSONL fixtures.
- `krn_trace_pack_audit`: audits masked APDU trace JSONL for case metadata,
  production trace identity, command/response counts, TLV-stream counts,
  sensitive tag suppression, and `CERT-OPEN-012` non-closure boundaries.
- `krn_scheme_profile_dictionary`: emits a review-focused profile dictionary
  without raw CAPK modulus disclosure.
- `krn_prelab_quality_gates`: emits the local quality gate manifest.
- `krn_prelab_no_crash_smoke`: emits parser/APDU no-crash smoke evidence.
- `krn_prelab_static_fuzz_plan`: emits the static/fuzz evidence plan.
- `krn_prelab_fuzz_seed_corpus`: emits the hash-only fuzz seed corpus
  manifest.
- `krn_public_standards_watch`: emits the public standards-watch signal
  manifest.
- `krn_tooling_completeness_audit`: emits JSON and Markdown audits showing
  which repository-controlled tooling and verification mechanisms are present,
  and which `CERT-OPEN-*` gates still require external evidence.
- `krn_certification_evidence_checklist`: emits JSON and Markdown attachment
  checklists that map every `CERT-OPEN-*` blocker to the required external
  authority, artifact, metadata, acceptance gate, and repository support.
- `krn_certification_evidence_intake`: emits JSON and Markdown attachment
  slots for crowdsourced testing, lab package assembly, hash capture,
  supersession history, and submission-scope review.
- `krn_certification_attachment_audit`: scans a local evidence attachment
  directory, hashes files under `CERT-OPEN-*` slots, reports missing or
  unmapped attachments, and flags unsupported entries such as symlinks as
  rejected without closing external evidence gates.
- `krn_coverage_package_audit`: inspects `target/coverage` for coverage
  metadata, the staging README, and the HTML report entry point, separating
  pre-lab measurement packages from enforced 100% candidates without closing
  `CERT-OPEN-009`.
- `krn_certification_freeze_manifest`: emits JSON and Markdown submitted-build
  hash slots for the kernel binary, signed configuration, CAPKs, profiles,
  vectors, RTM, reports, and approval package.
- `krn_certification_security_assessment_plan`: emits JSON and Markdown
  assessment controls for the external `CERT-OPEN-008` penetration test and
  architecture review.
- `krn_certification_device_evidence_plan`: emits JSON and Markdown device,
  Level 1, and PCI/PED evidence controls for `CERT-OPEN-005`,
  `CERT-OPEN-006`, and `CERT-OPEN-007`.
- `krn_certification_integration_report_plan`: emits JSON and Markdown full
  EMV integration-report and masked trace-pack controls for `CERT-OPEN-009`
  and `CERT-OPEN-012`.
- `krn_certification_report_ui`: emits deterministic JSON, Markdown, and a
  static HTML workbench for report production, open certification gate review,
  checked-in artifact file size and SHA-256 inventory, and certification
  artifact review.
- `krn_certification_workspace`: emits a complete local report-production
  workspace with the static UI, report pack, evidence checklists, freeze
  manifest, security/device/integration plans, quality artifacts, ABI statement,
  masked pre-lab trace fixture and trace-pack audit, empty `CERT-OPEN-*`
  attachment directories, attachment-slot guide, attachment audit dashboard,
  audit exports, workspace file hash inventory, and workspace manifest.
- `krn_build_manifest`: emits canonical source and annex provenance hashes.
- `krn_cabi_script_adapter`: exercises the C ABI APDU callback path.
- `krn_basic_pos`: shows a basic scripted PoS integration from reader callbacks
  through TRM random-selection sample registration, host approval, issuer
  authentication, and final GENERATE AC.
- `krn_basic_softpos`: shows a basic mobile NFC SoftPoS integration using the
  data-driven certification bundle, contactless transaction parameters, TTQ,
  CDCVM capability signaling, APDU callbacks, host approval, issuer
  authentication, final GENERATE AC, and redacted JSON output.
- `krn_callback_timeout_policy`: emits the C ABI callback timeout policy as
  JSON for terminal adapter startup checks and certification evidence.
- `krn_variable_data_boundary_audit`: scans production Rust source for
  compiled scheme/profile/CAPK/TAC/IAC fixture literals so variable payment
  data stays in signed profile/vector artifacts or isolated tests.
- `krn_emv_decode`: decodes lab-triage inputs while suppressing sensitive
  payload values by default.

Example decoder usage:

```sh
cargo run --quiet --example krn_emv_decode -- tlv 6F108407A0000000031010A5055003564953
cargo run --quiet --example krn_emv_decode -- dol 9F02069F3704
cargo run --quiet --example krn_emv_decode -- termcap E0B0C8
cargo run --quiet --example krn_emv_decode -- add-termcap 7080F0F0FF
cargo run --quiet --example krn_emv_decode -- ttq 36004000
cargo run --quiet --example krn_emv_decode -- sw generate-ac 9000
cargo run --quiet --example krn_certification_evidence_checklist -- --out docs
cargo run --quiet --example krn_certification_evidence_intake -- --out docs
cargo run --quiet --example krn_certification_attachment_audit -- --root target/hyperion-cert-attachments
cargo run --quiet --example krn_coverage_package_audit -- --root target/coverage
cargo run --quiet --example krn_certification_freeze_manifest -- --out docs
cargo run --quiet --example krn_certification_security_assessment_plan -- --out docs
cargo run --quiet --example krn_certification_device_evidence_plan -- --out docs
cargo run --quiet --example krn_certification_integration_report_plan -- --out docs
cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui
cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace
cargo run --quiet --example krn_basic_pos
cargo run --quiet --example krn_basic_softpos
cargo run --quiet --example krn_variable_data_boundary_audit -- src
```

## Controlled Annexes

The `docs/` directory is part of the executable baseline:

- `tlv_catalogue.csv`: canonical TLV catalogue and sensitive-data
  classification.
- `bitmap_catalogue.csv`: TVR/TSI symbolic bit catalogue.
- `state_machine.csv`: machine-readable state transition table.
- `scheme_profiles.cert.json`: structured certification-profile scaffold.
- `scheme_profile_dictionary.md`: generated profile review view.
- `oda_test_vectors.json`: structural ODA fixture annex unless replaced with
  `vector_class = "CERTIFICATION"` and complete lab-supplied vectors.
- `prelab_apdu_trace_pack.jsonl`: masked local trace fixture.
- `prelab_trace_pack_audit.json` / `.md`: generated trace fixture audit.
- `prelab_quality_gates.json`: local gate manifest.
- `prelab_no_crash_smoke.json`: no-crash parser/APDU smoke artifact.
- `prelab_static_fuzz_plan.json`: static-analysis and fuzzing evidence plan.
- `prelab_fuzz_seed_corpus.json`: hash-only deterministic fuzz seed corpus
  manifest.
- `public_standards_watch.json`: generated public standards-watch signal
  manifest.
- `tooling_completeness_audit.json`: generated repository-controlled tooling
  completeness audit.
- `tooling_completeness_audit.md`: generated Markdown tooling completeness
  audit for pre-lab review.
- `krn_variable_data_boundary_audit`: source audit utility that keeps
  scheme/profile/CAPK/TAC/IAC fixture literals out of production Rust code.
- `certification_evidence_checklist.json`: generated external evidence
  attachment checklist.
- `certification_evidence_checklist.md`: generated Markdown attachment
  checklist for certification package review.
- `certification_evidence_intake.json`: generated external evidence intake
  ledger with pending attachment slots, hash requirements, review fields, and
  supersession controls.
- `certification_evidence_intake.md`: generated Markdown intake ledger for
  crowdsourced testing and lab submission assembly.
- `certification_artifact_import_plan.json`: generated adapter registry for
  real lab, scheme, CAPK, vector, device, and report artifacts.
- `certification_artifact_import_plan.md`: reviewable guide for the artifact
  import lanes and their required metadata/security policies.
- `krn_certification_artifact_import`: CLI that hashes, classifies, and rejects
  unsafe external artifacts before they enter the report/freeze workflow. It also
  emits normalized integration reports and release-freeze bindings from staged
  authority artifacts plus optional `hyperion-integration-manifest.json` files.
- `certification_freeze_manifest.json`: generated submitted-build freeze
  manifest with pending SHA-256 slots bound to open certification issues.
- `certification_freeze_manifest.md`: generated Markdown freeze manifest for
  lab package assembly and review.
- `certification_security_assessment_plan.json`: generated third-party
  security assessment control plan for `CERT-OPEN-008`.
- `certification_security_assessment_plan.md`: generated Markdown security
  assessment plan for external assessor review.
- `certification_device_evidence_plan.json`: generated device, Level 1, and
  PCI/PED evidence control plan.
- `certification_device_evidence_plan.md`: generated Markdown device evidence
  plan for certification package review.
- `certification_integration_report_plan.json`: generated full integration
  report and APDU trace-pack evidence control plan.
- `certification_integration_report_plan.md`: generated Markdown integration
  report plan for certification package review.
- `certification_report_pack.json`: generated report-pack index for artifact
  tracking, checked-in artifact file size and SHA-256 inventory,
  external-report tracking, and open certification gates.
- `certification_report_pack.md`: generated Markdown report-pack export.
- `certification_report_ui.html`: generated static report workbench UI with
  requirement, artifact, report, gate, evidence, and tool-command views.
- `abi_conformance_statement.json`: generated ABI conformance statement.
- `performance_profile.csv`: product timing buckets and targets.
- `requirements_traceability.csv`: current RTM.
- `requirements-traceability-matrix.csv`: compatibility RTM copy.

When code changes affect generated evidence, regenerate the relevant artifact
and keep the traceability tests aligned.

## C ABI Integration Model

The C ABI is centered on `KrnContext`, `KrnRuntime`, and explicit transaction
parameters. The terminal application owns UI, host networking, device drivers,
reader transport, persistent counters, and PED integration. The kernel calls
out through callbacks for APDU transmission and unpredictable number supply.

Important ABI principles:

- `KRN_ABI_VERSION` identifies the ABI contract.
- `krn_get_profile_version` and `krn_get_profile_sha256` let integrations bind
  logs and certification-freeze evidence to the loaded signed profile artifact.
- `krn_get_callback_timeout_policy` exposes the bounded APDU transport, host
  authorization, PIN entry, and contactless UI timeout budgets that terminal
  adapters must honor.
- Callers provide explicit interface preference for contact or contactless.
- Terminal-owned DOL values such as `9F33`, `9F40`, and `9F66` enter through
  typed setter functions after transaction parameters are set.
- Output buffers are caller-owned and probeable.
- Issuer script result APIs report phase, phase-local script index,
  phase-local command index, optional `9F18` script identifier, and SW1/SW2
  status while keeping issuer script command bytes suppressed.
- Callback errors fail closed and preserve stable kernel error codes.
- Reentrant mutating calls are rejected.

See `src/ffi.rs` and the integration tests in `tests/traceability_foundation.rs`
for the authoritative behavior.

## Configuration And Profiles

Runtime variability belongs in signed profiles and explicit terminal inputs,
not in hardcoded scheme behavior. The certification profile scaffold covers:

- Scheme and AID identity.
- Interface-to-kernel mapping.
- TAC/IAC data.
- Floor and CVM limits.
- Contactless limits.
- CDCVM policy flags.
- CDA controls.
- Issuer script criticality policy.
- CAPK metadata and checksum/provenance gates.
- Deterministic TAA fallback keys.

Production and certification loading reject example-only profiles,
placeholder material, invalid schema, expired CAPKs, rollback/replay attempts,
bad checksums, and inconsistent interface mappings.
The variable-data boundary audit also checks production Rust source so
scheme-specific RIDs/AIDs, CAPKs, limits, TAC/IAC values, CDA encodings, and
certification vectors remain signed profile/vector data rather than compiled
kernel behavior.
The loaded profile version and SHA-256 are also carried into trace identity
records so masked logs can be reconciled against the exact submitted profile
bundle without exposing profile contents.

## Testing Strategy

Tests are organized around certification-sensitive behavior:

- Unit tests for parsers, builders, state mutation, profiles, and policies.
- Integration tests in `tests/traceability_foundation.rs` that tie code,
  annexes, RTM rows, generated artifacts, and lab-boundary statements
  together.
- Example tests for operator tooling and evidence generators.
- Deterministic artifact drift checks for generated annexes.
- No-crash smoke coverage for malformed parser and APDU boundaries.
- A 100% unit coverage target for the Rust kernel before any final
  certification submission.

The project prefers evidence that proves a concrete requirement over broad
"looks green" claims.

## Development Rules

Follow these rules when changing the kernel:

- Keep diffs small and reversible.
- Do not add dependencies without an explicit need and review.
- Keep terminal, card, issuer, host, PED, and lab responsibilities separate.
- Do not import public CAPKs, private test keys, or open-source project
  implementation code into certification artifacts.
- Do not infer scheme behavior from public references.
- Preserve redaction and crash-safety policies.
- Update RTM rows and generated artifacts when behavior or evidence changes.
- Keep `docs/progress_log.md` current for certification-hardening increments.
- Commit verified slices regularly.

## Certification Boundary

The repository can demonstrate engineering readiness and pre-lab evidence, but
it cannot certify itself. The following must be attached and accepted outside
the repository before final certification claims:

- Signed EMVCo, scheme, acquirer, and lab approval artifacts.
- Lab-supplied certification ODA vectors.
- Scheme/acquirer-approved CAPK bundle.
- Scheme/acquirer-approved AID, TAC/IAC, limit, CDA-control, and kernel
  profile bundle.
- Full masked lab APDU trace pack.
- Runtime trace identity tying ABI version, profile version, and profile
  SHA-256 to the submitted artifact set.
- 100% unit coverage report and full EMV integration report for the submitted
  binary/profile set.
- Static analysis and fuzzing reports with accepted findings.
- PCI PTS/PED integration statement.
- Device and L1 approval evidence.
- Third-party security assessment acceptance.

Until those artifacts exist and pass independent review, Hyperion remains an
engineering baseline pending licensed review and laboratory evidence.

## License

Repository source code and documentation are distributed under the MIT License.
See `LICENSE`.

This license does not relicense third-party standards, scheme materials,
accepted CAPKs, lab vectors, test-tool outputs, signed profiles, device
evidence, PCI/PED evidence, or approval artifacts. Those inputs remain governed
by their own owners, labs, schemes, contracts, and regulatory obligations.
