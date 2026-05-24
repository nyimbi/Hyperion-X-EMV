# Testing And Contribution Playbook

Hyperion is MIT-licensed so the payment community can improve the kernel in
the open. This tutorial explains how to contribute useful tests and review
evidence without weakening certification boundaries.

## Good Contributions

High-value contributions include:

- Parser edge cases.
- DOL construction tests.
- APDU command and status-word fixtures.
- AFL and READ RECORD ordering tests.
- TVR and TSI bit tests.
- CVM result tests.
- Terminal risk management tests.
- Terminal action analysis tests.
- GENERATE AC response parsing tests.
- Issuer authentication and issuer script sequencing tests.
- Contactless C-8 outcome tests.
- Trace redaction tests.
- No-crash corpus additions.
- Documentation that clarifies boundaries.

The best contribution names the requirement or boundary it protects.

## Clean-Room Rule

Do not copy implementation code from other EMV projects into Hyperion. Public
open-source projects can be reviewed for architecture ideas, testing strategy,
tooling patterns, and conceptual gaps, but Hyperion code and certification
artifacts should remain clean-room.

Do not import:

- Unlicensed EMVCo text.
- Scheme confidential material.
- Private CAPKs or test keys.
- Lab vectors that cannot be redistributed.
- Proprietary terminal traces.
- Payment card data from real cardholders.

When in doubt, describe the behavior and create your own minimal fixture.

## Test Naming

Good tests explain the risk:

- `rejects_duplicate_record_data_without_partial_store`
- `production_suppresses_transaction_cryptograms`
- `runtime_selection_uses_status_policy_for_get_response_and_invalidated_aids`
- `runtime_rejects_final_select_fci_with_mismatched_adf_name`
- `krn_ttq_001_supplies_9f66_to_contactless_pdol_and_online_handoff`

Avoid names that only describe mechanics:

- `test1`
- `works`
- `parse_ok`
- `card_test`

## What To Test

For every behavior change, ask:

- What data source owns this value?
- What happens with malformed input?
- What happens at the maximum supported length?
- What happens with duplicate tags?
- What happens if a card tries to overwrite terminal-owned data?
- What TVR or TSI bit should be set?
- What should be masked in traces?
- Which profile input controls this behavior?
- Which external artifact is still needed?

## Regression Pattern

A useful regression usually has this shape:

1. Build a minimal card, profile, or APDU fixture.
2. Exercise one kernel behavior.
3. Assert the exact output, TVR/TSI state, error code, or trace masking.
4. Add RTM or documentation evidence when the behavior maps to a requirement.
5. Run the focused test and then the wider relevant suite.

## Documentation Changes

Documentation changes should be treated as evidence changes when they affect
certification language.

Update these when relevant:

- `README.md` for project-level onboarding.
- `docs/tutorial/` for educational material.
- `docs/progress_log.md` for work increments.
- `docs/certification_open_issues.md` for external blockers.
- `docs/lab_submission_manifest.md` for submission package expectations.
- RTM CSVs when requirements or evidence mappings change.

## Local Verification

For small docs-only changes:

```sh
git diff --check
```

For tests or behavior changes:

```sh
cargo fmt --check
cargo test
```

For evidence or release-facing changes:

```sh
cargo test --examples
cargo clippy --all-targets --all-features -- -D warnings
cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -
cargo run --quiet --example krn_prelab_static_fuzz_plan | diff -u docs/prelab_static_fuzz_plan.json -
cargo run --quiet --example krn_prelab_fuzz_seed_corpus | diff -u docs/prelab_fuzz_seed_corpus.json -
cargo run --quiet --example krn_public_standards_watch | diff -u docs/public_standards_watch.json -
```

Run additional generator diffs when your change affects the relevant artifact.

## Submitting Test Artifacts

When contributing a trace or fixture:

- Use synthetic data.
- Mask PAN and Track 2 data.
- Do not include real cardholder data.
- Do not include issuer secrets.
- Do not include private CAPKs.
- State whether the fixture is structural, regression, fuzzing, or lab-derived.
- State whether redistribution is allowed.
- Keep fuzz corpora synthetic and hashable; do not commit generated crash
  corpora without a reviewed reproducer and disposition.
- Prefer manifesting corpus seeds by length, SHA-256, target, and expected
  parser outcome rather than emitting raw PAN-like, Track 2-like, cryptogram,
  or issuer-script bytes in documentation.

If redistribution is not allowed, do not commit it to the repository.

## Review Checklist

Before merging a contribution, reviewers should check:

- The change preserves terminal/card/host/PED/profile/lab boundaries.
- Sensitive data is not exposed in logs, traces, debug output, or fixtures.
- Tests cover success and failure paths where risk warrants it.
- Controlled artifacts are regenerated when needed.
- External certification blockers are not closed by repository-only evidence.
- The contribution does not copy implementation code from reviewed reference
  projects.

## Community Testing Strategy

The community can help most by creating broad, reproducible tests:

- Synthetic malformed TLV and DOL corpora.
- APDU replay scripts for known edge cases.
- Contactless outcome fixtures.
- Cross-platform C ABI smoke tests.
- Decoder samples for support tooling.
- Documentation corrections from integrators.
- Security review notes with minimal reproductions.

Every high-quality test makes the foundation stronger for new fintech teams and
reduces repeated work across the ecosystem.
