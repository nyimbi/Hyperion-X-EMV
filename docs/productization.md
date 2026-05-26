# Hyperion Tooling Guide

Hyperion ships repository-controlled tooling for building data-driven EMV kernel
candidates, provisioning signed data bundles, importing certification evidence,
checking local readiness, and assembling submission packs. This guide documents
what the tools do, how they fit together, what they emit, and where the local
boundary stops before external certification authorities take over.

The tools are intentionally conservative. They prefer deterministic output,
explicit hashes, signed configuration, and fail-closed behavior over convenience
that could hide a certification gap.

## Tooling Map

| Surface | Primary users | Purpose | Main outputs |
| --- | --- | --- | --- |
| `hyperion` CLI | integrators, release owners, CI | First-class command surface for bundles, artifact import, reports, schemas, headers, and freeze packs. | JSON, Markdown, HTML, signed bundle workspaces, submission packs. |
| `Makefile` | contributors, CI | One command per common job. | Verification, coverage, bundle, workspace, freeze, schema, and header outputs. |
| Certification examples | engineers, auditors | Executable references for lower-level tooling and deterministic report generation. | Checked-in docs, report packs, trace packs, workspaces. |
| Static workbenches | bundle authors, reviewers | Browser-readable local UIs for bundle and report review. | `index.html` files with embedded JSON data. |
| JSON Schemas | tool builders, CI | Reference contracts for bundle, integration, report, and freeze data. | Files under `docs/schemas/`. |
| C ABI header | C, C++, Swift, Kotlin/JNI, embedded wrappers | Stable packaged ABI declaration for kernel integration. | `include/hyperion_emv.h`. |
| Python helper package | automation authors | Small standard-library helper commands for submission indexing and report automation. | `hyperion-tools` command and JSON hash indexes. |
| Docker/devcontainer | new contributors, CI | Repeatable development environment. | Container image and VS Code devcontainer config. |
| Starter kits | application teams | Minimal integration patterns for common adoption paths. | `starter-kits/*/README.md`. |

## Recommended Workflow

Start from a clean checkout and use the highest-level commands first.

```sh
make verify
make coverage
make bundle
make workspace
make freeze
```

For a product or lab-facing run, use this sequence:

1. Create a candidate bundle workspace.
2. Replace generated placeholder data with authority-provided scheme, AID, TAC,
   IAC, limit, CAPK, ODA vector, device, and report data.
3. Lint and compile the signed bundle.
4. Stage external evidence under an artifact intake directory.
5. Import and normalize staged artifacts.
6. Build a report workspace for human review.
7. Run the freeze command without `--allow-incomplete` for submission readiness.
8. Keep the generated submission pack intact and hash-indexed.

A freeze produced with `--allow-incomplete` is a review workspace only. It is not
a certification submission candidate.

## First-Class CLI

Run all CLI commands through Cargo during development:

```sh
cargo run --quiet --bin hyperion -- <command>
```

Packaged releases may expose the same command as `hyperion` directly. The CLI is
implemented in `src/cli.rs` and delegates to library functions so behavior is
unit-testable.

### Command Catalogue

```sh
cargo run --quiet --bin hyperion -- commands
cargo run --quiet --bin hyperion -- commands --markdown
```

The JSON form is intended for scripts. The Markdown form is intended for humans
and release notes. Both are generated from the same command catalogue in
`src/productization.rs`.

### Bundle Init

```sh
cargo run --quiet --bin hyperion -- bundle init --out target/hyperion-certification-wizard
```

Creates a guided certification workspace with a signed data-bundle scaffold,
trust-anchor material, static workbench assets, artifact intake directories,
commands, and next-step notes. The generated data is for local preparation. A
certification bundle must be replaced with accepted authority data before it can
support a certification claim.

Primary output:

```text
target/hyperion-certification-wizard/bundle/certification_bundle.json
```

Use this when onboarding a new team, preparing a demonstration bundle, or
creating a structured place to add real scheme/lab/acquirer/device evidence.

### Bundle Sign

```sh
cargo run --quiet --bin hyperion -- bundle sign --out target/hyperion-signed-bundle
```

Writes the same local signed bundle scaffold used by `bundle init`. Treat this
as a provisioning scaffold, not as a certification authority signature. Private
signing keys must never be committed, embedded in reports, or copied into
submission packs.

### Bundle Lint

```sh
cargo run --quiet --bin hyperion -- bundle lint \
  --bundle docs/certification_data_bundle.json \
  --trust-anchors docs/certification_data_bundle_trust_anchors.json
```

Authenticates and compiles a signed data bundle under certification-mode policy.
It emits a JSON compile report and fails if the bundle is unsigned, stale,
rolled back, placeholder-backed, missing required material, or inconsistent with
trust-anchor policy.

The lint command is the right gate before loading a bundle into an integration
or before allowing a bundle hash into a freeze pack.

### Artifact Import

```sh
cargo run --quiet --bin hyperion -- artifacts import \
  --root target/hyperion-cert-artifact-import \
  --out target/hyperion-artifact-report
```

Hashes, classifies, and normalizes staged lab, scheme, CAPK, vector, device,
and report artifacts. It writes:

```text
target/hyperion-artifact-report/certification_artifact_import_report.json
```

Without `--out`, the command writes the JSON report to stdout.

The importer rejects unsafe paths, private key material, unsupported containers,
bad hash declarations, and malformed integration manifests. It can read a
`hyperion-integration-manifest.json` supplied by an authority, lab, acquirer, or
internal integration team to bind staged files to bundle fields, open issues, and
release-freeze slots.

Common semantic adapters already covered by the productization layer include:

| Format | Typical file | Use |
| --- | --- | --- |
| CAPK CSV | `capk/*.csv` | CAPK authority exports and public-key provenance staging. |
| Lab APDU JSONL | `lab/*.jsonl` | Trace rows from lab tools or replay harnesses. |
| C-8 outcome CSV | `reports/*c8*.csv` | Contactless C-8 outcome exports. |
| Level 3 reconciliation CSV | `reports/*l3*.csv` | Acquirer or Level 3 comparison files. |
| Signed conformance JSON | `lab/*conformance*.json` | Signed templates or approval package metadata. |
| Static/fuzz JSON | `reports/*fuzz*.json` | Static-analysis and fuzzing summaries. |

Unknown proprietary formats should be adapted by adding a parser that emits the
same normalized manifest shape. Do not bypass the bundle/report/freeze hashes.

### Release Freeze

```sh
cargo run --quiet --bin hyperion -- release freeze \
  --artifacts target/hyperion-cert-artifact-import \
  --out target/hyperion-submission-pack
```

Assembles a submission pack from staged artifacts and repository-controlled
reports. It fails closed unless every required freeze slot is bound and the
integration import report is not failed or missing.

For review-only workspaces, use:

```sh
cargo run --quiet --bin hyperion -- release freeze \
  --artifacts target/hyperion-cert-artifact-import \
  --out target/hyperion-submission-pack \
  --allow-incomplete
```

The pack includes:

| File or directory | Purpose |
| --- | --- |
| `submission_manifest.json` | Hash inventory for the generated pack and overall status. |
| `certification_integration_import_report.json` | Normalized artifact import result. |
| `certification_integration_import_report.md` | Human-readable import report. |
| `certification_release_freeze.json` | Freeze-slot bindings from staged evidence. |
| `certification_release_freeze.md` | Human-readable freeze report. |
| `certification_freeze_manifest_template.json` | Repository freeze-slot template. |
| `certification_freeze_manifest_template.md` | Human-readable freeze-slot template. |
| `report-workspace/` | Static report UI, report pack, conformance JSON, and quality gates. |
| `schemas/` | JSON Schemas copied into the pack. |
| `include/hyperion_emv.h` | C ABI header copied into the pack. |
| `README.md` | Pack status and missing-slot summary. |

Submission packs are still `*_unreviewed`. External authorities decide whether
the evidence is accepted.

### Report Workspace

```sh
cargo run --quiet --bin hyperion -- report workspace --out target/hyperion-report-workspace
```

Writes a static local report workspace containing:

| File | Purpose |
| --- | --- |
| `index.html` | Browser-readable report UI with embedded data. |
| `report_pack.json` | Machine-readable requirements, artifacts, evidence, gates, and tool commands. |
| `report_pack.md` | Human-readable report pack. |
| `abi_conformance_statement.json` | ABI baseline statement. |
| `prelab_quality_gates.json` | Repository-controlled pre-lab quality gates. |

No server is required. Open `index.html` locally when reviewing the generated
workspace.

### Certification Check

```sh
cargo run --quiet --bin hyperion -- certify check
```

Emits `prelab_quality_gates.json` to stdout. This command is useful in CI and
release reviews because it shows what repository-controlled checks exist and
which external gates remain open. It is not an approval command.

### Schema Generation

```sh
cargo run --quiet --bin hyperion -- schemas write --out docs/schemas
```

Writes reference schemas for:

| Schema | File |
| --- | --- |
| Certification data bundle | `docs/schemas/certification-data-bundle.schema.json` |
| Integration manifest | `docs/schemas/integration-manifest.schema.json` |
| Report pack | `docs/schemas/report-pack.schema.json` |
| Freeze manifest | `docs/schemas/freeze-manifest.schema.json` |

The Rust parsers and validators remain the source of truth. Use the schemas for
editor assistance, CI preflight checks, and external tool builders.

### C Header Generation

```sh
cargo run --quiet --bin hyperion -- c-header write --out include/hyperion_emv.h
```

Writes the packaged C ABI header. Regenerate it when exported ABI functions,
error codes, constants, or callback contracts change. Downstream SDK wrappers
should treat the header and ABI conformance statement as a matched pair.

## Make Targets

The Makefile wraps common jobs without hiding the underlying commands.

| Target | Runs | Use |
| --- | --- | --- |
| `make verify` | `cargo fmt --check`, `cargo test`, `cargo test --examples`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check` | Default local quality gate. |
| `make coverage` | `scripts/coverage_100.sh` | Enforced repository-controlled Rust source coverage gate. |
| `make bundle` | `hyperion bundle init` | Generate a bundle workspace. |
| `make workspace` | `hyperion report workspace` | Generate report UI and report artifacts. |
| `make freeze` | `hyperion release freeze --allow-incomplete` | Generate a review-only submission pack. |
| `make schemas` | `hyperion schemas write` | Regenerate checked-in schemas. |
| `make header` | `hyperion c-header write` | Regenerate checked-in C ABI header. |
| `make cli-smoke` | `hyperion commands --markdown` and `hyperion certify check` | Fast CLI smoke check. |

Use `make freeze` for review loops only. For submission readiness, run the
release freeze command manually without `--allow-incomplete`.

## Certification Examples

The examples remain valuable because they expose lower-level tooling and are
covered by `cargo test --examples`.

| Example | Purpose |
| --- | --- |
| `krn_certification_bundle` | Generate, template, validate, and lint certification bundles. |
| `krn_certification_bundle_tui` | Conservative terminal provisioning workflow. |
| `krn_certification_wizard` | Guided candidate workspace generator. |
| `krn_certification_workspace` | Full local certification workspace generator. |
| `krn_certification_report_ui` | Static report UI and report-pack generator. |
| `krn_certification_artifact_import` | Lower-level artifact import, integration import, and release-freeze reports. |
| `krn_certification_freeze_manifest` | Freeze-slot template generator. |
| `krn_certification_attachment_audit` | Attachment hash inventory and unsafe-file rejection. |
| `krn_certification_evidence_checklist` | External evidence checklist generator. |
| `krn_certification_evidence_intake` | Intake ledger generator. |
| `krn_certification_device_evidence_plan` | Device, L1, and PCI/PED evidence plan. |
| `krn_certification_integration_report_plan` | Lab trace, C-8, and L3 integration report plan. |
| `krn_certification_security_assessment_plan` | Security assessment plan. |
| `krn_tooling_completeness_audit` | Repository-controlled tooling completeness audit. |
| `krn_coverage_package_audit` | Coverage evidence package audit. |
| `krn_trace_pack_audit` | Masked APDU trace-pack audit. |
| `krn_emv_decode` | Redacted EMV support decoder for TLV/APDU/status data. |
| `krn_basic_pos` | Basic contact PoS integration example. |
| `krn_basic_softpos` | Basic SoftPoS-style contactless integration example. |

Prefer the first-class `hyperion` CLI for product workflows. Use examples when
you need a narrower artifact, a drift check, or executable documentation of a
specific boundary.

## Artifact Intake Layout

A typical staged artifact root looks like this:

```text
target/hyperion-cert-artifact-import/
  hyperion-integration-manifest.json
  lab/
  scheme/
  capk/
  vectors/
  device/
  reports/
```

The manifest is optional for early review, but required for complete freeze
binding. It should declare which file maps to which artifact ID, open issue,
bundle field, and freeze slot. The schema is in
`docs/schemas/integration-manifest.schema.json`.

Minimum manifest shape:

```json
{
  "schema_version": "hyperion-certification-integration-manifest-1.0",
  "manifest_id": "example-lab-drop-001",
  "authority": "example-lab",
  "artifacts": [
    {
      "path": "reports/trace-pack.jsonl",
      "adapter_id": "REPORT",
      "artifact_id": "trace.pack",
      "artifact_kind": "trace pack",
      "binds_open_issues": ["CERT-OPEN-012"],
      "freeze_artifact_id": "trace_pack_hash",
      "expected_sha256_hex": "0000000000000000000000000000000000000000000000000000000000000000",
      "metadata": ["tool", "version", "scope"]
    }
  ]
}
```

Replace the example hash with the actual SHA-256. If the expected hash does not
match the file, import and freeze must fail.

## SDK And Distribution Assets

### Rust Crate Metadata And Features

`Cargo.toml` declares package metadata and feature flags for the productized
crate. Current features are:

| Feature | Purpose |
| --- | --- |
| `std` | Default host build support. |
| `c-abi` | Marker for C ABI packaging and downstream wrappers. |
| `productization` | Marker for product tooling builds. |

Keep product workflow code in library APIs where possible so CLI behavior can be
unit-tested without invoking a subprocess.

### C ABI Header

`include/hyperion_emv.h` is generated from the productization layer. It should be
checked in so C, C++, Swift, Kotlin/JNI, and embedded wrapper authors can inspect
the ABI without building Rust first. Regenerate it with `make header`.

### Python Helper Package

The Python package is intentionally small and standard-library only:

```sh
PYTHONPATH=python python3 -m hyperion_tools.cli index \
  --root target/hyperion-submission-pack \
  --out target/hyperion-submission-pack/python_index.json
```

It writes a sorted SHA-256 inventory for all files in a submission directory.
This is useful for external automation, handoff checks, and verifying that a
pack was not modified after freeze assembly. The output is hash inventory only,
not certification acceptance.

### Docker And Devcontainer

Use the Dockerfile when a repeatable Rust environment matters more than local
machine speed. Use `.devcontainer/devcontainer.json` when onboarding contributors
through a devcontainer-aware editor. Keep containers deterministic and avoid
putting private signing keys, lab credentials, or proprietary scheme data into
images.

### Starter Kits

Starter kits are lightweight adoption guides:

| Starter kit | Audience |
| --- | --- |
| `starter-kits/rust-pos` | Rust PoS application teams. |
| `starter-kits/c-abi-pos` | C/C++ or platform-wrapper teams. |
| `starter-kits/python-automation` | Bundle/report automation teams. |
| `starter-kits/android-softpos` | Android SoftPoS adapter teams. |
| `starter-kits/pcsc-desktop` | Desktop PC/SC terminal teams. |

They define boundaries and next steps. They are not production hardware drivers
or certified payment applications by themselves.

## Deterministic Generated Artifacts

When generator code changes, regenerate and drift-check checked-in artifacts in
the same commit:

```sh
cargo run --quiet --example krn_tooling_completeness_audit -- --json | diff -u docs/tooling_completeness_audit.json -
cargo run --quiet --example krn_tooling_completeness_audit -- --markdown | diff -u docs/tooling_completeness_audit.md -
cargo run --quiet --example krn_certification_report_ui -- --json | diff -u docs/certification_report_pack.json -
cargo run --quiet --example krn_certification_report_ui -- --markdown | diff -u docs/certification_report_pack.md -
cargo run --quiet --example krn_certification_report_ui -- --html | diff -u docs/certification_report_ui.html -
```

If a diff is expected, commit the generator and regenerated artifact together.
If a diff is unexpected, fix the generator or stale artifact before release.

## Security Rules

- Never commit private signing keys, lab credentials, device secrets, PED keys,
  PAN data, Track 2 data, PIN material, issuer scripts, issuer authentication
  data, or raw cryptograms.
- Treat trust anchors as public verification material only.
- Keep rollback counters monotonic; never lower them to make an old bundle load.
- Require explicit SHA-256 bindings for submitted binaries, bundles, vectors,
  trace packs, reports, and approval packages.
- Keep certification and testing data in signed bundles or staged external
  artifact directories, not hardcoded in kernel logic.
- Mask sensitive APDU/TLV data in traces and reports.
- Use `--allow-incomplete` only for local review workspaces.
- Keep generated submission packs immutable after freeze. If any file changes,
  create a new pack and record the new hash inventory.

## Certification Boundary

Hyperion tooling can produce reproducible evidence packages, but it cannot grant
certification. The following remain external gates:

- EMVCo, scheme, and acquirer approval.
- Recognized lab execution and signed reports.
- Device/L1 evidence and firmware identity.
- PCI/PED evidence where applicable.
- CAPK authority provenance and accepted checksums.
- Official SDA/DDA/CDA and contactless vectors.
- Accepted APDU trace packs, C-8 outcomes, and Level 3 reconciliation results.
- Signed conformance templates and approval artifacts.

A complete local tool run means the repository-controlled evidence is
reproducible and internally consistent. It does not mean a lab or scheme has
accepted the evidence.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `bundle lint` fails with a certification policy error | Placeholder, expired, rolled-back, unsigned, or untrusted bundle data. | Replace fixture material with accepted authority data and verify trust anchors. |
| `artifacts import` rejects files | Unsafe path, unsupported container, bad hash, private key material, or malformed manifest. | Move files into an allowed intake lane and fix the manifest. |
| `release freeze` fails without `--allow-incomplete` | Missing freeze slots or failed integration import. | Attach the required external artifacts and rerun import. |
| `make coverage` fails below 100% | New Rust source lines are not covered by tests. | Add focused tests or remove unreachable/dead code. |
| Drift check fails | Checked-in generated artifact is stale or generator changed unexpectedly. | Regenerate intentionally or fix the generator. |
| Python helper cannot be imported | `PYTHONPATH` does not include `python/`. | Run with `PYTHONPATH=python` or install the package in an environment. |
| Static report UI looks stale | Workspace was generated before the latest report changes. | Rerun `hyperion report workspace` or `make workspace`. |

## Quick Reference

```sh
# Full local verification
make verify

# Enforced 100% source-line coverage gate
make coverage

# CLI catalogue
cargo run --quiet --bin hyperion -- commands --markdown

# Candidate bundle workspace
cargo run --quiet --bin hyperion -- bundle init --out target/hyperion-certification-wizard

# Bundle lint
cargo run --quiet --bin hyperion -- bundle lint --bundle <bundle.json> --trust-anchors <trust_anchors.json>

# Artifact import
cargo run --quiet --bin hyperion -- artifacts import --root <artifact-root> --out <report-dir>

# Submission readiness freeze, fail closed
cargo run --quiet --bin hyperion -- release freeze --artifacts <artifact-root> --out <submission-pack>

# Review-only incomplete freeze
cargo run --quiet --bin hyperion -- release freeze --artifacts <artifact-root> --out <submission-pack> --allow-incomplete

# Report workspace
cargo run --quiet --bin hyperion -- report workspace --out target/hyperion-report-workspace

# Schema and C header regeneration
make schemas
make header
```
