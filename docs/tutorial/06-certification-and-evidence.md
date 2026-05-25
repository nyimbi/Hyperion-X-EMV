# Certification And Evidence

This tutorial explains what must be true before Hyperion can support a final
certification claim. It is intentionally conservative: certification is proven
by accepted evidence, not by repository statements.

## What Certification Means

Certification means the claimed product, binary, profile set, device, interface,
and payment application scope have been tested and accepted by the relevant
authorities. For EMV products, that can involve:

- EMVCo Level 2 testing.
- Scheme-specific approval.
- Acquirer acceptance.
- Device and Level 1 evidence.
- PCI PTS POI evidence for PIN and device security boundaries.
- Recognized lab reports.
- Signed profile, CAPK, trace, and conformance artifacts.

The exact path depends on product scope.

## What Hyperion Can Provide

The repository can provide:

- Source code and documentation under MIT license.
- Rust tests and traceability guards.
- Controlled annexes.
- Generated ABI conformance JSON, including capability-readiness records for
  implemented engines that remain standard-validation pending.
- Masked pre-lab APDU trace fixtures.
- Quality-gate manifest.
- No-crash smoke artifact.
- Build provenance hashes.
- Runtime trace identity for ABI version, profile version, and loaded profile
  SHA-256.
- A generated certification evidence checklist that maps each open external
  blocker to required authorities, attachments, metadata, acceptance gates, and
  repository support.
- A generated security assessment plan that maps `CERT-OPEN-008` review
  surfaces to repository evidence and external assessor report requirements.
- A static certification report workbench and JSON/Markdown report-pack exports
  with checked-in artifact file size and SHA-256 inventory.
- Open issue tracking for missing external evidence.
- A shared place for community review and test contributions.

This can reduce the cost and ambiguity of certification preparation.

## What Hyperion Cannot Self-Certify

The repository cannot provide final approval by itself. These remain external:

- Licensed EMVCo standards and lab interpretation.
- Scheme and acquirer rule acceptance.
- Accepted CAPK bundle and provenance.
- Lab-supplied SDA, DDA, CDA, APDU, and contactless test vectors.
- Full lab/test-tool APDU trace pack.
- Device and L1 approval evidence.
- PCI PTS/PED statement.
- 100% unit coverage report for the submitted build.
- Full EMV integration report for the submitted profile set.
- Static-analysis and fuzzing reports accepted for the submission context.
- Third-party security assessment.
- Signed approval artifacts.

## The Certification Package Mindset

Every final claim should identify:

- Product name and version.
- Submitted kernel binary hash.
- Submitted configuration bundle hash.
- CAPK bundle hash.
- Scheme profile hash.
- Test vector bundle hash.
- Traceability matrix hash.
- Device and L1 evidence references.
- PCI/PED evidence references.
- Test-tool version and lab environment.
- Open findings and accepted residual risks.

If a claim cannot be tied to a specific artifact set, it is not ready.

## Hyperion Open Issues

The controlling external blocker list is `docs/certification_open_issues.md`.
The generated checklist in `docs/certification_evidence_checklist.json` and
`docs/certification_evidence_checklist.md` turns that register into an
attachment plan for report production. It does not close any item by itself; it
names what must be attached and accepted before an item can close.

At the time this tutorial was written, final certification still depends on:

- Signed profile authority.
- Scheme and acquirer accepted AID/TAC/IAC/limit configuration.
- Accepted CAPKs.
- Lab-supplied ODA vectors.
- Contactless C-8 package and bulletin reconciliation.
- Device and L1 evidence.
- PCI/PED evidence.
- Third-party security assessment.
- 100% coverage and full integration reports.
- Static-analysis and fuzzing reports.
- Signed conformance template.
- Full masked lab APDU trace pack.

Do not close those issues with local repository tests alone.

## Coverage Requirement

Hyperion now targets a formal 100% unit coverage report before final
certification submission. The report must match the submitted binary, profiles,
and annex hashes. A passing `cargo test` run is necessary but not sufficient:
it proves tests pass, not that every unit coverage obligation has been measured
and accepted.

The repository workflow is documented in `docs/coverage.md` and implemented by
`scripts/coverage_100.sh`. By default it uses `cargo-llvm-cov` to run all
workspace targets, exports `target/coverage/lcov.info`, fails unless every LCOV
source line has a non-zero hit count, and stages an HTML report under
`target/coverage/html`. The pre-lab CI workflow runs the same script with
`KRN_COVERAGE_ENFORCE=0` so contributors can review measurement artifacts
before the 100% requirement is actually closed.

Coverage should be treated as a certification artifact:

- Record tool name and version.
- Record compiler and target.
- Record exact source commit.
- Record profile and feature flags.
- Attach HTML/XML or lab-accepted report format.
- Explain exclusions, if any, and get them accepted.

## Integration Report Requirement

The full EMV integration report should prove that the kernel, terminal
application, device, profile set, and host path work together across the
claimed EMV test plan. This is different from unit coverage.

It should include:

- Test plan version.
- Test-tool version.
- Profile set and hashes.
- Device model and firmware.
- APDU trace references.
- Expected and actual outcomes.
- Deviations and dispositions.
- Lab or reviewer acceptance.

## Static Analysis And Fuzzing

Static analysis and fuzzing reports should include:

- Tool names and versions.
- Commands and configuration.
- Corpus description.
- Iteration counts and duration.
- Coverage or path metrics if available.
- Findings, remediations, and accepted residual issues.

Hyperion's no-crash smoke artifact is useful, but it does not replace the
formal fuzzing report.

The repository also includes `docs/prelab_static_fuzz_plan.json`, generated by
`cargo run --example krn_prelab_static_fuzz_plan`. It records the static gates,
candidate fuzz surfaces, corpus hygiene constraints, and report metadata that a
formal `CERT-OPEN-010` package must carry. It is a planning and drift-control
artifact, not an accepted report.

`docs/prelab_fuzz_seed_corpus.json`, generated by
`cargo run --example krn_prelab_fuzz_seed_corpus`, makes the plan more concrete
by replaying synthetic TLV, DOL, APDU, GENERATE AC, issuer host-response, and
Track 2-shaped seeds through the real parser boundaries. The manifest records
seed length, SHA-256, and expected/actual outcomes, but not the seed bytes.

## Lab Trace Pack

The repository includes a deterministic masked pre-lab trace fixture. Final
certification still needs the full lab/test-tool trace pack for the accepted
scope.

The final trace pack should:

- Cover every applicable test case.
- Preserve ordering and status words.
- Include profile and ABI identity metadata.
- Mask sensitive cardholder and cryptographic material.
- Tie traces to the submitted build and profile hashes.
- Reconcile Hyperion trace identity with the loaded profile SHA-256 reported by
  the ABI.
- Be accepted by the lab or scheme reviewer.

Before using the pre-lab fixture in report production, audit it:

```sh
cargo run --example krn_trace_pack_audit -- \
  --path docs/prelab_apdu_trace_pack.jsonl \
  --require-prelab-fixture
```

The audit verifies case metadata, scenario rows, production trace identity,
expected command/response counts, expected TLV-stream counts, sensitive tag
suppression, and the `CERT-OPEN-012` non-closure marker. It does not replace
the full accepted lab/test-tool trace pack.

## Public Standards Watch

Public EMVCo and PCI pages can signal standards drift before the licensed
submission package is finalized. Hyperion records those signals in
`docs/standards_watch.md` and the generated
`docs/public_standards_watch.json` artifact. Regenerate the JSON artifact with
`cargo run --example krn_public_standards_watch`.

The watch artifact maps public signals to open issues such as C-8 reconciliation,
device evidence, PCI/PED evidence, and signed conformance templates. It is a
drift-control artifact, not implementation authority. Licensed standards,
scheme profiles, lab instructions, and approval artifacts still prevail.

## Evidence Attachment Checklist

Run the checklist generator whenever certification package contents change:

```sh
cargo run --quiet --example krn_certification_evidence_checklist -- --out docs
cargo run --quiet --example krn_certification_evidence_intake -- --out docs
cargo run --quiet --example krn_certification_attachment_audit -- --root target/hyperion-cert-attachments
cargo run --quiet --example krn_coverage_package_audit -- --root target/coverage
cargo run --quiet --example krn_certification_freeze_manifest -- --out docs
cargo run --quiet --example krn_certification_security_assessment_plan -- --out docs
cargo run --quiet --example krn_certification_device_evidence_plan -- --out docs
cargo run --quiet --example krn_certification_integration_report_plan -- --out docs
```

The checklist JSON output is intended for tooling and the Markdown output is
intended for human review. Each row records:

- The controlling `CERT-OPEN-*` issue.
- The external authority or signer.
- The required attachment.
- Metadata required to bind that attachment to the submitted binary, profile
  set, device, and test-tool scope.
- The acceptance gate that must be satisfied before the open issue can close.
- Repository-controlled support artifacts that help reviewers inspect the
  claim.

Treat the checklist as the requirement map and the intake ledger as the
attachment-control surface for crowdsourced testing and certification
preparation. The intake ledger starts every `CERT-OPEN-*` attachment slot as
pending and records the fields needed before review: authority, signer or
reviewer, artifact path, artifact SHA-256, artifact date, submitted-build
scope, disposition, and supersession history. Community contributors can add
better fixtures, trace replays, validation tests, and reports, but closure
still requires the external authority named in the row.

Use `krn_certification_attachment_audit` to scan a local attachment directory
before review. Files placed under directories named after `CERT-OPEN-*` issues
are hashed and listed against those slots; files outside known slots are
reported as unmapped. Unsupported entries such as symlinks are reported as
rejected instead of being silently skipped. This makes crowdsourced evidence
packages auditable without treating a local file as accepted certification
evidence.

Use `krn_coverage_package_audit` after `scripts/coverage_100.sh` to inspect the
staged coverage package. The audit checks for `metadata.json`, `README.txt`,
and `html/index.html`, validates the expected 100% threshold and non-closure
metadata, and reports whether the package is measurement-only or an enforced
candidate still awaiting submitted-build binding and external review.

Use `krn_certification_workspace` to create the local report-production
workspace. It creates empty `attachments/CERT-OPEN-*` directories, writes an
attachment-slot guide, emits `attachment_audit.html`, and emits
`certification_attachment_audit.json` and `certification_attachment_audit.md`
against that staging area. It also emits `workspace_inventory.json` and
`workspace_inventory.md` so reviewers can check file size and SHA-256 values
for generated workspace artifacts before packaging. Empty slots remain
`missing`; files staged there become `present_unreviewed` until an accepted
authority or reviewer closes the matching external gate.

Treat the freeze manifest as the submitted-build binding surface. It records
pending SHA-256 slots for the kernel binary, signed configuration, CAPK bundle,
scheme profile bundle, lab vector bundle, RTM/lab crosswalk, accepted quality
reports, and signed approval package so a reviewer can tell exactly which
artifact set was submitted.

Treat the security assessment plan as the external-assessor control surface for
`CERT-OPEN-008`. It groups APDU injection, state-machine bypass, trace leakage,
profile tampering, PIN custody, ODA material handling, issuer-script handling,
and report-integrity review with repository evidence and the outside report
attachments still required before closure.

## Data-Driven Certification Bundles

Hyperion certification data is provisioned as data, not Rust edits. A
certification bundle contains the selected scheme profile JSON, vector bundle,
terminal/device identity, runtime callback timeouts, kernel-profile registry,
CVM extension rules, test-plan cases, and artifact hash bindings. Trust-anchor
data verifies that the payload hash and signature envelope are expected for the
submission.

Generate the default local bundle and static GUI workbench:

```sh
cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle
```

The workbench is intended for bundle authors, not only kernel engineers. Each
major field explains its role, impact, runtime utilization, and security
consequence. Authors can edit guided fields, embedded scheme profile JSON,
vector bundle JSON, and trust-anchor JSON; the browser view then produces
suggestions, fingerprints, a normalized bundle preview, and an EMV capability
coverage map. Browser checks are advisory and local. The Rust compile/lint
command is the authoritative gate.

Validate the checked-in fixture bundle:

```sh
cargo run --quiet --example krn_certification_bundle -- --validate --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json
```

Lint and compile-check the checked-in fixture bundle:

```sh
cargo run --quiet --example krn_certification_bundle -- --lint --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json
```

Provision a new local bundle with terminal prompts:

```sh
cargo run --quiet --example krn_certification_bundle_tui -- --out target/hyperion-cert-bundle-tui
```

A different certification target should change bundle input data: profile JSON,
CAPK/profile authority metadata, vector package, terminal/device profile,
standards/bulletin target, runtime policy, and evidence bindings. The compiled
kernel should only change when the protocol algorithm itself changes.

## Crowdsourced Certification Preparation

Crowdsourcing can help before formal submission:

- More parser edge cases.
- More APDU replay fixtures.
- More trace redaction tests.
- More profile validation tests.
- Better tutorial and integration documentation.
- Independent security review.
- Portability reports for terminal platforms.

Crowdsourcing cannot replace final authority. It can make the submitted package
stronger, easier to inspect, and less likely to fail late.

## Practical Readiness Checklist

Before a certification-facing submission, confirm:

- `cargo test` passes.
- `cargo test --examples` passes.
- `cargo run --quiet --example krn_certification_evidence_checklist -- --out docs` reproduces the current evidence checklist.
- `cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui` produces the current report workbench.
- `cargo run --quiet --example krn_tooling_completeness_audit -- --out docs` produces the repository-controlled tooling completeness audit.
- `cargo run --quiet --example krn_certification_bundle -- --validate --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json` validates the active data-driven bundle fixture.
- `cargo run --quiet --example krn_certification_bundle -- --lint --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json` emits the compile/lint report with suggestions and EMV capability coverage.
- `cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace` produces the complete local report-production workspace.
- `target/hyperion-cert-workspace/attachments/CERT-OPEN-*` is the generated staging layout for external evidence attachments.
- `target/hyperion-cert-workspace/attachment_audit.html` is the generated local dashboard for slot status and attachment hashes.
- `target/hyperion-cert-workspace/workspace_inventory.json` and `.md` are the generated size/SHA-256 inventory for local workspace files.
- `cargo run --quiet --example krn_basic_pos` completes the basic scripted PoS integration.
- `cargo fmt --check` passes.
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
- Controlled evidence generators reproduce checked-in artifacts.
- The 100% coverage report is attached.
- Full EMV integration report is attached.
- Static-analysis and fuzzing reports are attached.
- CAPKs and profiles are accepted and signed.
- Device, L1, and PCI/PED evidence are attached.
- Full masked lab APDU trace pack is attached.
- `docs/certification_open_issues.md` has no open item for the claimed scope.
