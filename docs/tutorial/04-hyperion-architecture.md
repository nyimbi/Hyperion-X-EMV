# Hyperion Architecture

Hyperion-X-EMV is organized as a Rust Level 2 kernel library with C ABI outputs,
controlled annexes, evidence generators, and repository tests that lock
certification-sensitive behavior.

## Design Goals

Hyperion is designed around these goals:

- Deterministic EMV behavior.
- Narrow data custody.
- Explicit terminal, card, issuer, host, PED, profile, and lab boundaries.
- Stable integration through Rust and C ABI surfaces.
- Reproducible local evidence.
- Clean-room use of public references.
- A path toward formal certification without pretending the repository can
  certify itself.

## Why Rust

Rust is the kernel implementation language because Level 2 code needs memory
safety without garbage collection, deterministic resource behavior, strong
types for protocol data, explicit error handling, and stable library artifacts
for terminal integration.

The kernel manipulates sensitive data and complex state:

- PAN and Track 2 equivalent data.
- Application cryptograms.
- Issuer authentication data.
- Issuer scripts.
- Offline authentication material.
- Terminal and card risk state.
- Profile-controlled policy.

Rust helps keep these paths bounded and reviewable.

## Why Python

Python is reserved for development automation and support tooling. It is useful
for:

- Generating or checking reports.
- Transforming lab artifacts into reviewable forms.
- Triage of APDU traces.
- Corpus management for parser and replay testing.
- CI glue and contributor tooling.

Python should not become the certification runtime kernel. Python-generated
outputs must be reproducible, reviewed, and treated as tooling evidence around
the Rust core.

## Main Source Modules

The Rust crate is split by protocol responsibility:

- `src/tlv.rs`: BER-TLV parsing and traversal.
- `src/dol.rs`: DOL parsing, data store, padding policy, and DOL output.
- `src/apdu.rs`: APDU command construction.
- `src/sw.rs`: context-specific status word handling.
- `src/selection.rs`: PSE, PPSE, direct AID, and signed-profile matching.
- `src/gpo.rs`: GPO response parsing and PDOL extraction.
- `src/afl.rs`: AFL parsing and READ RECORD planning.
- `src/record.rs`: card record parsing and overwrite policy.
- `src/state.rs`: TVR and TSI symbolic bit mutation.
- `src/restrictions.rs`: processing restrictions.
- `src/cvm.rs`: CVM parsing and PED-owned PIN handle model.
- `src/trm.rs`: terminal risk management.
- `src/taa.rs`: terminal action analysis.
- `src/gac.rs`: GENERATE AC parsing and online handoff package.
- `src/oda.rs`: ODA selection, certificate recovery helpers, and vector checks.
- `src/issuer.rs`: issuer authentication and issuer script parsing/results.
- `src/c8.rs`: contactless C-8 helpers and outcome scaffolding.
- `src/config.rs`: signed profile loading and certification/profile gates.
- `src/ffi.rs`: C ABI, transaction lifecycle, callbacks, and buffers.
- `src/trace.rs`: masked APDU/TLV traces and replay fixtures.
- `src/quality.rs`: pre-lab quality manifest and no-crash evidence.
- `src/provenance.rs`: canonical build provenance and hashing.

## Library Outputs

The crate builds as:

- `rlib` for Rust integration.
- `staticlib` for static C ABI integration.
- `cdylib` for dynamic C ABI integration.

This lets terminal vendors choose an integration shape without changing kernel
logic.

## Runtime Integration Model

The terminal or payment application owns runtime services. Hyperion receives
them through explicit calls or callbacks:

- Card APDU transmit.
- Transaction parameters.
- Terminal capabilities.
- Supported interface.
- Random/unpredictable number source.
- Online authorization handoff.
- PED-owned PIN handles.
- Profile loading.
- Output buffer ownership.

The C ABI is intentionally defensive: it checks versioning, buffer lengths,
callback shapes, and reentrant mutation.

## Data Custody Model

Hyperion avoids owning data that should belong elsewhere:

- No issuer master keys.
- No clear PIN custody.
- No card cryptogram generation.
- No profile authority.
- No CAPK authority.
- No lab-vector authority.

Sensitive data that must pass through the kernel is masked in production traces
and redacted in debug output where practical.

## Evidence Model

Hyperion keeps machine-readable evidence under version control:

- Requirement traceability CSVs.
- TLV catalogue.
- Bitmap catalogue.
- State machine table.
- Performance profile.
- Scheme profile dictionary.
- ODA vector fixture.
- ABI conformance statement.
- Masked pre-lab APDU trace pack.
- Pre-lab quality gates.
- No-crash smoke artifact.
- Certification open-issues register.

Tests and generators protect these artifacts from silent drift.

## What Still Comes From Outside

The repository does not provide final certification inputs:

- Licensed EMVCo specifications.
- Scheme and acquirer acceptance.
- Accepted CAPK bundles.
- Lab-supplied ODA and APDU vectors.
- Device and L1 approval evidence.
- PCI PTS/PED evidence.
- Static-analysis and fuzzing reports accepted for the submission.
- 100% coverage report for the submitted binary/profile set.
- Signed approval artifacts.

The architecture is built to receive and preserve those inputs when they become
available.

