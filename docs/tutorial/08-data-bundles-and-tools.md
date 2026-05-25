# Data Bundles And Tooling Guide

This guide explains how to assemble a Hyperion data bundle, validate it, use it
from the kernel, and package the surrounding evidence with the repository
controlled tools. It is intentionally operational: follow it when you are
preparing a pre-lab bundle, a testing bundle, or a certification submission
candidate.

The short rule is simple: if a value changes by scheme, acquirer, device,
terminal profile, CAPK set, test plan, lab vector set, or approval scope, it
belongs in a signed and hash-bound data bundle or in an external evidence
attachment. It should not become a hard-coded Rust source change.

## What A Bundle Does

A Hyperion bundle is the configuration and evidence identity layer around the
kernel binary. It lets the same compiled Rust kernel run against different
certification or testing scopes by changing input data, not implementation code.

A bundle carries:

- The claimed product and certification scope.
- The contact/contactless standards target and bulletin reconciliation markers.
- The terminal, device, firmware, L1, and PCI/PED references.
- Runtime callback timeout and trace-masking policy.
- Interface-to-kernel registry entries.
- CVM and CDCVM extension policy.
- Test-plan identifiers and expected evidence obligations.
- Hash bindings for profiles, CAPKs, vectors, traces, reports, and freeze data.
- Embedded or referenced scheme profile JSON.
- Embedded or referenced vector-bundle JSON.
- A signature envelope bound to trust-anchor data.

The kernel loader verifies the bundle, extracts the profile and runtime policy,
records hashes for trace identity, and rejects unsafe or inconsistent inputs.
The browser workbench and TUI are authoring aids. The Rust loader, validator,
linter, and integration tests remain authoritative.

## Files Involved

The checked-in fixture lives in `docs/` and is useful as a reference shape:

| File | Purpose |
| --- | --- |
| `docs/certification_data_bundle.json` | The signed bundle fixture consumed by validation and examples. |
| `docs/certification_data_bundle_trust_anchors.json` | Verification-only trust-anchor data for the fixture. It must not contain private signing material. |
| `docs/certification_data_bundle.md` | Generated human summary of the current fixture. |
| `docs/certification_data_bundle_workbench.html` | Static local workbench for bundle inspection and authoring. |
| `docs/certification_data_bundle_fingerprints.json` | Generated bundle, payload, profile, and vector hashes. |
| `docs/certification_data_bundle_lint.json` | Machine-readable lint/compile report. |
| `docs/certification_data_bundle_lint.md` | Human-readable lint/compile report. |

Do not edit generated summaries or lint outputs directly. Change bundle inputs,
run the generators, review the diff, then commit the regenerated artifacts.

## Bundle Classes And Modes

Hyperion separates bundle intent from loader policy.

| Concept | Values | Meaning |
| --- | --- | --- |
| `bundle_class` | `TESTING`, `CERTIFICATION`, `PRODUCTION` | The declared purpose of the bundle itself. |
| Loader `--mode` | `test`, `certification`, `production` | The policy applied by validation and loading. |
| `rollback_counter` | Monotonic integer | Prevents stale bundles from replacing newer accepted data. |
| `created` and trust `not_after` | EMV date fields | Bound the review and trust window. |

Use `test` mode for local experimentation. Use `certification` mode for
pre-lab and submission candidates. Use `production` only when the profile,
CAPKs, vectors, device evidence, and approval package are authority accepted.

Certification and production modes should reject fixture-only or self-attested
data that is acceptable only for local testing.

## Bundle Anatomy

The top-level bundle has these fields:

| Field | Role | Impact If Wrong |
| --- | --- | --- |
| `schema_version` | Identifies the bundle schema, currently `hyperion-certification-bundle-1.0`. | Unknown schemas fail validation. |
| `bundle_id` | Stable identifier for this bundle lineage. | Ambiguous IDs make evidence and rollback tracking unreliable. |
| `bundle_version` | Human review version. | Reviewers cannot tell which data set they accepted. |
| `rollback_counter` | Machine-enforced monotonic counter. | Stale or replayed bundles may be accepted if this is mishandled. |
| `bundle_class` | Declares testing, certification, or production purpose. | A fixture can be mistaken for authority data. |
| `created` | Bundle creation date in EMV-style date form. | Date-sensitive trust and expiry checks become unclear. |
| `payload` | All variable certification and runtime data. | Incorrect payload data changes kernel behavior and evidence identity. |
| `signature` | Signature and hash envelope for the payload. | Tampering or signer mismatch must fail closed. |

### `payload.submission_scope`

Use this section to say what the bundle claims.

| Field | Role | Required Discipline |
| --- | --- | --- |
| `product_name` | Product under review. | Must match the report pack and submitted binary identity. |
| `product_version` | Product version. | Must match build provenance and release tags. |
| `certification_target` | Target package or test scope. | Use exact lab or internal target names. |
| `interfaces` | Claimed interfaces, such as `contact` and `contactless`. | Do not claim interfaces without matching profile, device, and trace evidence. |
| `authorities` | Lab, scheme, acquirer, or owner references. | Mark pending authorities honestly; do not imply approval. |

### `payload.standards_target`

Use this section to bind the bundle to the standards and bulletin scope.

- `emv_contact_version`: contact specification target.
- `emv_contactless_kernel`: contactless kernel family, for example C-8.
- `bulletins_included`: bulletins accepted into this target.
- `bulletins_excluded`: bulletins explicitly excluded or deferred.

This section does not replace licensed standards review. It records the scope
that the submitted evidence must reconcile.

### `payload.terminal_profile`

This section connects kernel behavior to the real terminal or SoftPoS target.

- `terminal_type`: EMV terminal category used by processing restrictions and
  terminal action analysis.
- `device_model`: submitted device or mobile acceptance profile reference.
- `firmware_version`: firmware, app, or secure component version.
- `l1_approval_reference`: contact/contactless Level 1 evidence reference.
- `pci_pts_reference`: PED, PIN, or mobile acceptance security evidence.
- `supported_interfaces`: interfaces the target device actually supports.

Placeholders are acceptable for pre-lab fixtures, but they keep external gates
open. Final submissions need accepted evidence references and matching hashes.

### `payload.runtime_policy`

This section controls runtime policy that must be consistent across adapters,
traces, and reports.

- `callback_timeouts.apdu_transport_timeout_ms`: timeout for card or NFC APDU
  transport callbacks.
- `callback_timeouts.host_authorization_timeout_ms`: timeout for online host
  authorization callbacks.
- `callback_timeouts.pin_entry_timeout_ms`: timeout for PED-owned PIN entry.
- `callback_timeouts.contactless_ui_timeout_ms`: timeout for contactless UI and
  outcome presentation callbacks.
- `offline_counter_persistence`: whether terminal nonvolatile counters are
  required for velocity checks.
- `trace_masking_policy`: sensitive-data suppression policy for APDU traces.

Adapters should query the loaded timeout policy and enforce it. Do not keep
separate timeout constants in UI, NFC, host, or PED glue code.

### `payload.kernel_registry`

The registry maps claimed interface and scheme scope to kernel behavior.

Each entry should name:

- `kernel_profile_id`: stable profile identifier used in reports.
- `interface`: `contact` or `contactless`.
- `algorithm`: implementation module or algorithm reference.
- `c8_package`: C-8 approval or pre-lab package reference where applicable.
- `scheme_scope`: schemes covered by this registry entry.

A contactless claim needs matching C-8 package evidence, terminal profile,
profile data, and masked traces.

### `payload.cvm_extensions`

CVM behavior that differs by scheme or profile belongs here or in the scheme
profile set, not in Rust constants.

Each entry records:

- `rule_id`: stable review identifier.
- `scheme_scope`: schemes affected.
- `cvm_code_hex`: certified or profile-defined CVM code.
- `meaning`: human explanation.
- `tvr_on_failure_hex`: TVR effect if the CVM fails.
- `continue_on_failure`: whether CVM processing may continue.

CDCVM support should be profile-driven and backed by terminal and wallet
capability evidence. Do not assume CDCVM from one hard-coded CVM code.

### `payload.test_plan`

This section lists cases the bundle expects to exercise.

- `case_id`: lab, test-tool, or pre-lab case identifier.
- `vector_class`: whether vectors are fixtures, testing data, or certification
  vectors.
- `expected_outcome`: expected high-level result.
- `trace_requirement`: trace evidence expected for submission.

The test plan is not proof by itself. It becomes useful when the integration
report, APDU trace pack, and coverage/static/fuzz reports bind to the same
bundle hashes.

### `payload.artifact_hashes`

Every externally meaningful input or report should be hash-bound.

Common entries include:

- Scheme profile set hash.
- CAPK bundle hash.
- ODA/vector bundle hash.
- APDU trace pack hash.
- Coverage report package hash.
- Integration report hash.
- Static analysis and fuzz report hash.
- Submitted binary hash.
- Final approval package hash.

Use `binds_open_issues` to show which `CERT-OPEN-*` item the artifact supports.
A hash does not close an issue; accepted authority evidence does.

### `payload.scheme_profile_set_json`

This is the signed profile material consumed by the kernel. It owns scheme and
acquirer configuration such as:

- Scheme name and RID.
- AID list, priorities, and partial-selection policy.
- Contact and contactless interface support.
- TAC and IAC values.
- Floor limits, CVM limits, and contactless transaction limits.
- Random selection percentages and TRM settings.
- CDCVM and CDA support.
- CDA request encoding.
- Default CDOL data.
- Critical issuer script INS policy.
- CAPK metadata: RID, key index, modulus, exponent, expiry, checksum, and
  source provenance.

Final certification needs scheme/acquirer/lab accepted profile and CAPK
material. The checked-in data is a deterministic fixture shape, not authority
material.

### `payload.vector_bundle_json`

This section binds ODA and APDU vector evidence.

Certification-ready vector bundles should contain non-empty, authority-supplied
SDA, DDA, and CDA cases with expected TVR, TSI, cryptographic verification
state, and outcome data. Fixture or empty vector bundles can support local
flow testing, but they cannot close ODA certification coverage.

### `signature`

The signature binds the payload to a signer and hash.

- `algorithm`: signature scheme identifier.
- `signer_id`: signer matched against trust anchors.
- `signing_key_fingerprint`: public fingerprint of the signing key.
- `payload_sha256`: exact hash of the signed payload.
- `signature_hex`: signature over the payload.
- `signature_artifact_sha256`: hash of the signature artifact.

Keep private signing keys out of the repository, browser storage, shell
history, logs, trace files, and support tickets. The checked-in fixture exists
only so local tests and examples are deterministic.

## Trust Anchors

Trust anchors are stored separately from the bundle. They contain verification
data, not signer secrets.

A trust-anchor entry includes:

- `signer_id`: signer allowed for this bundle family.
- `signing_key_fingerprint`: expected key fingerprint.
- `verification_public_key_hex`: public verification key.
- `allowed_payload_sha256`: optional pin to one exact payload.
- `not_after`: expiry date for the trust entry.

For production-like work:

1. Generate and custody private signing material outside the repository.
2. Publish only public verification material into trust-anchor data.
3. Pin payload hashes for submitted candidates when possible.
4. Rotate trust anchors deliberately and record why.
5. Increase rollback counters when replacing accepted bundles.
6. Remove or supersede expired trust anchors.

## Authoring Workflow

Use this workflow for a new testing or certification candidate.

### 1. Start from a Generated Workspace

```sh
cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle
```

This writes:

- `target/hyperion-cert-bundle/certification_bundle.json`
- `target/hyperion-cert-bundle/trust_anchors.json`
- `target/hyperion-cert-bundle/certification_bundle_report.md`
- `target/hyperion-cert-bundle/certification_bundle_lint.json`
- `target/hyperion-cert-bundle/certification_bundle_lint.md`
- `target/hyperion-cert-bundle/bundle_fingerprints.json`
- `target/hyperion-cert-bundle/index.html`

The generated files are local working artifacts. Review them before promoting
anything into `docs/`.

### 2. Use The Static Workbench

Open `target/hyperion-cert-bundle/index.html` locally, or inspect the checked-in
`docs/certification_data_bundle_workbench.html` reference.

Use the workbench to review field descriptions, impact, utilization, security
notes, compiled JSON, and lint suggestions. Treat the workbench as a local GUI.
Do not paste private signing keys, real PANs, issuer secrets, or proprietary lab
vectors into a hosted page or shared browser session.

### 3. Use The Wizard For Guided Candidate Preparation

```sh
cargo run --quiet --example krn_certification_wizard -- --out target/hyperion-certification-wizard
```

The wizard asks for the candidate scope, interfaces, schemes, authorities,
device identity, firmware identity, external evidence references, and local
signing identity. It then writes a bundle, trust anchors, browser workbench,
artifact intake lanes, integration manifest template, validation commands, and
next-step runbook. Use `--non-interactive` for CI smoke tests or scripted
onboarding.

### 4. Use The TUI For Terminal-Only Provisioning

```sh
cargo run --quiet --example krn_certification_bundle_tui -- --out target/hyperion-cert-bundle-tui
```

The TUI prompts for the core identity fields and writes:

- `certification_bundle.json`
- `trust_anchors.json`
- `index.html`

Use the TUI when working over SSH, in CI sandboxes, or on machines where a
browser workflow is inconvenient. The current TUI is intentionally conservative:
it helps provision the bundle shell and common identity fields, then the Rust
validator/linter remains the source of truth.

### 4. Replace Fixture Values With Authority Data

Work through the bundle in this order:

1. `submission_scope`: product, version, interfaces, authorities.
2. `standards_target`: accepted standards and bulletin scope.
3. `terminal_profile`: device, firmware, L1, PCI/PED, and supported interfaces.
4. `scheme_profile_set_json`: signed scheme/acquirer AIDs, TAC/IAC, limits,
   CVM, CDA, CAPKs, and provenance.
5. `vector_bundle_json`: lab or scheme vector data.
6. `kernel_registry`: interface and kernel package mapping.
7. `runtime_policy`: callback timeouts and masking policy.
8. `test_plan`: lab and integration cases.
9. `artifact_hashes`: profile, CAPK, vector, trace, report, binary, and approval
   hashes.
10. `signature` and trust anchors.

Use placeholder wording only when evidence is genuinely pending. Placeholders
must produce warnings and must keep the relevant `CERT-OPEN-*` gates open.

### 5. Validate The Bundle

```sh
cargo run --quiet --example krn_certification_bundle --   --validate   --bundle docs/certification_data_bundle.json   --trust-anchors docs/certification_data_bundle_trust_anchors.json   --mode certification
```

Validation authenticates the bundle, verifies trust-anchor policy, enforces
rollback and date rules, parses embedded profile and vector data, and prints
bundle/profile/vector hashes.

Run validation in every intended mode before claiming the bundle is usable:

```sh
cargo run --quiet --example krn_certification_bundle -- --validate --bundle <bundle.json> --trust-anchors <trust_anchors.json> --mode test
cargo run --quiet --example krn_certification_bundle -- --validate --bundle <bundle.json> --trust-anchors <trust_anchors.json> --mode certification
cargo run --quiet --example krn_certification_bundle -- --validate --bundle <bundle.json> --trust-anchors <trust_anchors.json> --mode production
```

### 6. Lint And Compile The Bundle

```sh
cargo run --quiet --example krn_certification_bundle --   --lint   --bundle docs/certification_data_bundle.json   --trust-anchors docs/certification_data_bundle_trust_anchors.json   --mode certification
```

The lint report classifies findings as errors, warnings, or info. Errors block
loading. Warnings usually mean the bundle can support local or pre-lab work but
cannot close a final certification gate.

Common warnings and fixes:

| Finding | Meaning | Fix |
| --- | --- | --- |
| External evidence placeholder remains | A field still says pending or required. | Attach accepted evidence and replace the placeholder with the accepted reference. |
| Certification vector bundle is still fixture or empty data | ODA vectors are structural or pending. | Replace with non-empty authority-supplied certification vectors. |
| Fixture verification key is still present | The deterministic local public key is still used. | Provision submission-specific trust anchors and keep private keys out of repo storage. |
| Relay resistance warning | Contactless profile claims may not include full RRP data. | Add accepted relay resistance parameters or remove the claim from scope. |

### 7. Fingerprint And Freeze The Candidate

Generate or refresh bundle fingerprints:

```sh
cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle
```

Then freeze the full submission identity:

```sh
cargo run --quiet --example krn_certification_freeze_manifest -- --out docs
```

The freeze manifest should bind at least:

- Submitted binary hash.
- Configuration/data-bundle hash.
- CAPK bundle hash.
- Scheme profile hash.
- Test-vector bundle hash.
- RTM hash.
- Coverage report hash.
- Integration report hash.
- Static/fuzz report hash.
- Approval package hash.

## Using A Bundle From The Kernel

The C ABI loader is the integration boundary for terminal software and examples.
A typical adapter does this:

1. Initialize `KrnRuntime` with APDU, RNG, host/PIN/contactless callbacks as
   required by the interface.
2. Call `krn_init` with the ABI version and runtime callbacks.
3. Load the verified bundle with `krn_load_certification_bundle_verified`.
4. Query `krn_get_certification_bundle_sha256`, `krn_get_profile_version`, and
   `krn_get_profile_sha256` and store those values in trace identity.
5. Query `krn_get_callback_timeout_policy` and apply those timeout budgets to
   APDU transport, host authorization, PIN entry, and contactless UI callbacks.
6. Set transaction parameters and terminal capabilities.
7. Run the transaction and process host/issuer/final-GAC phases.
8. Emit only masked traces and redacted summaries.

Minimal shape:

```rust
let bundle = include_bytes!("../docs/certification_data_bundle.json");
let trust_anchors = include_bytes!("../docs/certification_data_bundle_trust_anchors.json");

let status = krn_load_certification_bundle_verified(
    ctx,
    bundle.as_ptr(),
    bundle.len(),
    trust_anchors.as_ptr(),
    trust_anchors.len(),
    installed_rollback_counter,
    evaluation_year,
    evaluation_month,
    evaluation_day,
);
```

Use the examples as executable references:

```sh
cargo run --quiet --example krn_basic_pos
cargo run --quiet --example krn_basic_softpos
cargo run --quiet --example krn_callback_timeout_policy
```

`krn_basic_pos` shows a contact-style scripted sale. `krn_basic_softpos` shows a
mobile NFC contactless path with TTQ, CDCVM capability signaling, NFC APDU
callbacks, host authorization, issuer authentication, final GENERATE AC, and
redacted JSON output.

## Tool Reference

Use these tools from the repository root.

| Task | Command | Output |
| --- | --- | --- |
| Generate bundle workspace | `cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle` | Bundle JSON, trust anchors, lint reports, fingerprints, and workbench HTML. |
| Emit bundle template | `cargo run --quiet --example krn_certification_bundle -- --json-template` | Bundle JSON template on stdout. |
| Emit trust template | `cargo run --quiet --example krn_certification_bundle -- --trust-template` | Trust-anchor JSON template on stdout. |
| Validate bundle | `cargo run --quiet --example krn_certification_bundle -- --validate --bundle <bundle.json> --trust-anchors <trust_anchors.json> --mode certification` | Authenticated hashes and verification status. |
| Lint bundle | `cargo run --quiet --example krn_certification_bundle -- --lint --bundle <bundle.json> --trust-anchors <trust_anchors.json> --mode certification` | Compile report JSON on stdout. |
| Run TUI provisioner | `cargo run --quiet --example krn_certification_bundle_tui -- --out target/hyperion-cert-bundle-tui` | Prompted bundle, trust anchors, and workbench HTML. |
| Audit source data boundary | `cargo run --quiet --example krn_variable_data_boundary_audit -- src` | JSON source-hygiene audit. |
| Generate profile dictionary | `cargo run --quiet --example krn_scheme_profile_dictionary` | Masked scheme-profile dictionary Markdown. |
| Generate report UI | `cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui` | Static report UI and report-pack exports. |
| Generate full workspace | `cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace` | Complete local certification workspace. |
| Generate evidence checklist | `cargo run --quiet --example krn_certification_evidence_checklist -- --out docs` | External evidence checklist JSON and Markdown. |
| Generate intake ledger | `cargo run --quiet --example krn_certification_evidence_intake -- --out docs` | Evidence intake JSON and Markdown. |
| Generate artifact import plan | `cargo run --quiet --example krn_certification_artifact_import -- --out docs` | Adapter plan for real lab, scheme, CAPK, vector, device, and report artifacts. |
| Import real artifacts | `cargo run --quiet --example krn_certification_artifact_import -- --root target/hyperion-cert-artifact-import` | Classified SHA-256 inventory and fail-closed rejection report. |
| Normalize real artifacts | `cargo run --quiet --example krn_certification_artifact_import -- --integration-root target/hyperion-cert-artifact-import` | Bundle artifact hash bindings, evidence mappings, and release-freeze candidates from staged authority artifacts and optional `hyperion-integration-manifest.json` files. |
| Build release freeze bindings | `cargo run --quiet --example krn_certification_artifact_import -- --release-freeze-root target/hyperion-cert-artifact-import` | Repeatable submitted-release hash bindings for binary, profiles, CAPKs, vectors, trace packs, coverage, static/fuzz reports, and approval packages. |
| Audit attachments | `cargo run --quiet --example krn_certification_attachment_audit -- --root target/hyperion-cert-attachments` | Attachment hash inventory. |
| Generate freeze manifest | `cargo run --quiet --example krn_certification_freeze_manifest -- --out docs` | Submitted-build hash slots. |
| Generate security plan | `cargo run --quiet --example krn_certification_security_assessment_plan -- --out docs` | Security assessment plan JSON and Markdown. |
| Generate device plan | `cargo run --quiet --example krn_certification_device_evidence_plan -- --out docs` | Device, L1, and PCI/PED evidence plan. |
| Generate integration plan | `cargo run --quiet --example krn_certification_integration_report_plan -- --out docs` | Integration report and trace-pack plan. |
| Run coverage gate | `scripts/coverage_100.sh` | `target/coverage` LCOV, HTML, and metadata. |
| Audit coverage package | `cargo run --quiet --example krn_coverage_package_audit -- --root target/coverage` | Coverage package status. |
| Generate trace fixture | `cargo run --quiet --example krn_prelab_trace_pack` | Masked JSONL trace fixture. |
| Audit trace pack | `cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl --require-prelab-fixture` | Trace-pack audit JSON. |
| Decode support data | `cargo run --quiet --example krn_emv_decode -- <mode> <hex>` | Redacted EMV data interpretation. |
| Check tooling completeness | `cargo run --quiet --example krn_tooling_completeness_audit -- --markdown` | Human-readable tooling audit. |

## Deterministic Drift Checks

For checked-in generated artifacts, prefer drift checks:

```sh
cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -
cargo run --quiet --example krn_tooling_completeness_audit -- --json | diff -u docs/tooling_completeness_audit.json -
cargo run --quiet --example krn_tooling_completeness_audit -- --markdown | diff -u docs/tooling_completeness_audit.md -
cargo run --quiet --example krn_certification_report_ui -- --json | diff -u docs/certification_report_pack.json -
cargo run --quiet --example krn_certification_report_ui -- --markdown | diff -u docs/certification_report_pack.md -
cargo run --quiet --example krn_certification_report_ui -- --html | diff -u docs/certification_report_ui.html -
```

When a drift check fails, determine whether the generator changed correctly. If
so, regenerate the checked-in artifact and commit the generator and artifact
together.

## Security Checklist

Before sharing or submitting a bundle:

- Confirm private signing keys are not present in the bundle, trust anchors,
  workbench state, logs, shell history, reports, or screenshots.
- Confirm trust anchors contain public verification material only.
- Confirm rollback counters only move forward.
- Confirm fixture keys and placeholders are removed or clearly marked as
  non-closing for pre-lab use.
- Confirm PAN, Track 2, cryptograms, issuer authentication data, issuer scripts,
  PIN material, and signed dynamic authentication data are masked in traces.
- Confirm CAPK material has accepted provenance and checksums.
- Confirm profile and vector hashes match the submitted evidence package.
- Confirm every external claim maps to a `CERT-OPEN-*` item or an accepted
  closure artifact.

## Submission Checklist

A bundle is certification-ready only when this package is coherent:

- Bundle validation passes in the intended mode.
- Bundle lint has no blocking errors and all warnings are accepted or resolved.
- The loaded profile SHA-256 matches the profile hash in traces and reports.
- The bundle SHA-256 matches the freeze manifest and report pack.
- The submitted binary hash is captured.
- The coverage package is generated for the submitted source and binary scope.
- The integration report references the same test plan, device, profile, CAPKs,
  vectors, and trace pack.
- Static analysis and fuzzing reports are attached.
- Device, L1, PCI/PED, C-8, scheme, acquirer, and lab evidence are attached.
- The signed conformance template agrees with the ABI conformance statement.
- The full masked APDU trace pack is complete and accepted.

## Troubleshooting

### Validation Fails With A Signature Or Payload Hash Error

The payload changed after signing, the trust anchor pins a different payload,
or the signer metadata does not match. Regenerate the signature, update the
trust-anchor data deliberately, and rerun validation.

### Validation Fails With Rollback Or Date Errors

The `rollback_counter` is not higher than the installed counter, or the trust
anchor expired before the evaluation date. Use a newer accepted bundle counter
and a valid trust-anchor window.

### Lint Reports External Evidence Placeholders

The bundle is still pre-lab shaped. Attach accepted evidence or keep the warning
visible. Do not silence it with vague wording.

### Lint Reports Fixture Vector Data

Replace `vector_bundle_json` with authority-supplied certification vectors and
update artifact hashes. Empty or fixture vectors cannot close ODA coverage.

### The Workbench Preview Differs From CLI Validation

Trust the CLI. The workbench is an authoring aid; the Rust validator/linter is
the authority used by CI and examples.

### A Runtime Example Uses The Wrong Timeout

Ensure the adapter queries `krn_get_callback_timeout_policy` after loading the
bundle and applies those values to APDU, host, PIN, and contactless UI callbacks.
Do not duplicate timeout values in integration code.

## What Not To Do

- Do not fork Rust source to change scheme profiles, CAPKs, limits, or TAC/IAC.
- Do not treat checked-in fixture CAPKs as final authority data.
- Do not commit private signing keys.
- Do not claim certification closure from local tests alone.
- Do not attach unmasked APDU traces or real cardholder data.
- Do not change a checked-in generated report without also changing or rerunning
  its generator.
- Do not use the SoftPoS example as a PCI mobile acceptance approval claim.

## Where To Go Next

- Use `docs/certification_open_issues.md` to see which external gates remain.
- Use `docs/lab_submission_manifest.md` to assemble submission attachments.
- Use `docs/certification_report_ui.html` to review generated evidence.
- Use `docs/tooling_completeness_audit.md` to confirm which local tools exist.
- Use `docs/coverage.md` for the coverage package workflow.
- Use `examples/krn_basic_pos.rs` and `examples/krn_basic_softpos.rs` as
  integration references.
