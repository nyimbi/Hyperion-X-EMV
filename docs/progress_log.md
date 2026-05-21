# Hyperion EMV Kernel Progress Log

This log records certification-hardening increments, evidence, and open risks.
It is intentionally concise: commit history remains the authoritative code
decision record, while this file tracks work toward certification readiness.

## 2026-05-21T22:15:35Z

- Baseline checked: current public EMVCo materials still frame Level 2 as
  acceptance-device software compliance testing, with contact kernel approval
  requiring ICS submission, lab validation, test reports, and EMVCo approval.
- Increment completed: bound transaction amounts to explicit terminal currency
  exponent handling at the ABI boundary.
- Code impact: `KrnTxnParams` and `StoredTxnParams` now carry
  `currency_exponent`; the transaction data store emits EMV tag `5F36`; invalid
  exponents above single BCD digit range are rejected; ABI version increased to
  account for the struct layout change.
- Evidence updated: TLV catalogue now includes `5F36`, and KRN-API-003 RTM rows
  point to executable test evidence instead of pending implementation text.
- Verification: `cargo fmt`, `cargo test`, and
  `cargo clippy --all-targets --all-features` passed.
- Remaining risk: this only closes a narrow API/currency-data gap. Final
  certification still requires licensed EMV/scheme reconciliation, lab-supplied
  vectors and profiles, recognized-lab execution, and approval artifacts.

## 2026-05-21T22:25:00Z

- Increment completed: enforce interface-specific kernel/profile mapping for
  selected AIDs.
- Code impact: signed profiles now retain `contact_kernel_type`; profile loading
  rejects `contact_kernel_type = c8_contactless`; runtime mapping validation
  rejects contactless transactions without a C-8 mapping and contact
  transactions without a distinct contact kernel mapping.
- Evidence updated: KRN-INT-001, KRN-INT-002, and KRN-INT-004 RTM rows now point
  to config, FFI, and traceability tests.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:29:45Z

- Increment completed: implement explicit profile-defined CDOL1 fallback for
  first GENERATE AC when the card omits tag `8C`.
- Code impact: signed AID profiles now validate optional `default_cdol1` DOL
  bytes; first GAC still prefers card-supplied `8C`, falls back only to the
  selected signed profile default, and fails closed when neither source exists.
- Evidence updated: KRN-GAC1-001 RTM rows now cite config, FFI, and traceability
  tests instead of pending implementation text.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:37:14Z

- Increment completed: harden the online authorization boundary between the
  kernel and Level 3 integration.
- Code impact: host response parsing now rejects malformed issuer
  authentication data length for tag `91`; online authorization handoff remains
  kernel-packaged TLV data without host/acquirer role behavior.
- Evidence updated: KRN-ONL-001 and KRN-ONL-002 RTM rows now cite GAC package,
  FFI runtime, issuer parser, and traceability evidence.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:41:48Z

- Increment completed: harden production APDU logging policy and trace identity
  evidence.
- Code impact: full APDU command data is now suppressed whenever the log policy
  is in production mode, even if a caller constructs a misconfigured public
  `LogPolicy` with support authorization and `full_apdu = true`.
- Evidence updated: KRN-LOG-002 and KRN-LOG-004 RTM rows now cite production
  suppression, deterministic replay, and trace identity tests. KRN-LOG-003
  remains pending because crash-dump exclusion still needs dedicated evidence.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:46:06Z

- Increment completed: tighten APDU command construction evidence and SELECT
  AID P2 validation.
- Code impact: `select_aid` rejects unsupported P2 values; the APDU constructor
  matrix now covers the kernel-built short APDU shapes used by SELECT AID, GPO,
  READ RECORD, INTERNAL AUTHENTICATE, EXTERNAL AUTHENTICATE, and GENERATE AC.
- Evidence updated: KRN-APDU-001 RTM rows now cite concrete constructor,
  environment SELECT, READ RECORD validation, and traceability tests.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:50:33Z

- Increment completed: promote phase-gated TSI evidence for KRN-TSI-002.
- Code impact: added a regression covering ODA-not-performed, ODA-performed,
  empty issuer-script, non-empty issuer-script, and TRM execution paths so TSI
  bits are asserted only after their corresponding processing has run.
- Evidence updated: KRN-TSI-002 RTM rows now cite the phase-gating regression,
  the RTM guard, and existing runtime coverage for CVM/TRM, issuer
  authentication, and issuer scripts.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:53:36Z

- Increment completed: promote processing-restriction order and TVR-bit
  evidence for KRN-REST-001 and KRN-REST-002.
- Code impact: processing restrictions now use an explicit internal check
  sequence for application version, expiration, effective date, AUC service
  permission, and new-card handling; tests lock the order to standard TVR byte 2
  bits only.
- Evidence updated: KRN-REST-001 and KRN-REST-002 RTM rows now cite the order
  regression, existing restriction TVR tests, and the traceability guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T22:58:20Z

- Increment completed: harden configuration schema rejection evidence for
  KRN-CFG-002.
- Code impact: signed profile loading now rejects unknown JSON fields at root,
  source, certification-scope, scheme, AID, CAPK, and relay-resistance object
  boundaries while preserving documented metadata fields. Transaction parameter
  validation now also has explicit oversized merchant-name length coverage.
- Evidence updated: KRN-CFG-002 RTM rows now cite schema/field rejection,
  expired CAPK rejection, terminal parameter validation, and a traceability
  guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:04:24Z

- Increment completed: promote VERIFY `63 Cx` offline PIN warning evidence for
  KRN-PIN-004.
- Code impact: CVM now has a deterministic offline PIN VERIFY status interpreter
  that converts `90 00` and `63 Cx` into CVM result bytes, tries-remaining
  evidence, and TVR updates without accepting PIN data into kernel memory.
- Evidence updated: KRN-PIN-004 RTM rows now cite status-word classification,
  CVM VERIFY-status mapping, traceability coverage, and the RTM guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:14:48Z

- Increment completed: enforce non-volatile offline counter provenance for
  KRN-TRM-003.
- Code impact: TRM profiles can declare consecutive-offline limits; TRM
  evaluation fails closed when those limits are active and the supplied counter
  is missing or marked volatile; the FFI exposes
  `krn_set_nonvolatile_offline_counter` for Level 3 counter input without adding
  kernel-owned volatile counter state.
- Evidence updated: KRN-TRM-003 RTM rows now cite TRM provenance checks, the
  FFI boundary, and a traceability guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:19:56Z

- Increment completed: promote executable state-machine annex validation for
  KRN-ANNEX-001 and KRN-ANNEX-002.
- Code impact: `validate_state_machine_annex` now verifies the exact CSV schema,
  parses each documented event/action/error, and rejects annex rows whose
  next-state, action, or error semantics drift from the executable FSM
  transition table.
- Evidence updated: KRN-ANNEX-001 and KRN-ANNEX-002 RTM rows now cite FSM
  schema validation, semantic-drift rejection, and a traceability guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:25:14Z

- Increment completed: add canonical TVR/TSI bitmap catalogue evidence for
  KRN-BIT-001.
- Code impact: `docs/bitmap_catalogue.csv` now records every TVR and TSI bit,
  symbolic name, RFU row, mask, owner, and test ID; the lab manifest and build
  provenance include the catalogue; traceability tests verify the catalogue
  masks match the implementation masks and implementation modules avoid raw
  bitmap setter patterns.
- Evidence updated: KRN-BIT-001 RTM rows now cite bitmap catalogue validation,
  implementation source scanning, and the RTM guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:29:23Z

- Increment completed: harden crash/debug redaction evidence for KRN-LOG-003.
- Code impact: `DataStore`, `ReplayExchange`, and `ReplayScript` no longer
  expose stored card data or raw APDU bytes through `Debug`; replay fixtures
  still reject VERIFY APDUs carrying PIN data, preserving the existing PED-owned
  PIN custody boundary.
- Evidence updated: KRN-LOG-003 RTM rows now cite data-store debug redaction,
  replay debug redaction, PIN VERIFY replay rejection, and the logging RTM
  guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.
