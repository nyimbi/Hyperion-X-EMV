# Hyperion EMV Kernel Progress Log

This log records certification-hardening increments, evidence, and open risks.
It is intentionally concise: commit history remains the authoritative code
decision record, while this file tracks work toward certification readiness.

## 2026-05-22T02:23:49Z

- Increment completed: widen reproducible-build provenance to the source tree.
- Research note: certification packaging evidence should not rely on a digest of
  one Rust entrypoint when the kernel behavior is spread across source modules;
  provenance needs stable coverage for all kernel source files and controlled
  annexes.
- Code impact: `krn_build_manifest` now accepts directory arguments and expands
  them deterministically, so `src` can be included as one provenance root.
- Evidence updated: the lab manifest now states that provenance covers every
  kernel source module, and traceability tests compare provenance source entries
  against the current `src/*.rs` set.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed; `cargo run --example
  krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md
  docs/lab_submission_manifest.md docs/requirements_traceability.csv
  docs/scheme_profiles.cert.json docs/oda_test_vectors.json
  docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv
  docs/performance_profile.csv examples/krn_build_manifest.rs` emitted canonical
  provenance covering every `src/*.rs` module.

## 2026-05-22T02:18:46Z

- Increment completed: make EMV Level 2 approval evidence boundary explicit.
- Research note: KRN-CERT-001 should cite executable conformance-statement
  evidence only for repository-controlled preparation work; actual approval
  still requires an external EMV Level 2 approval and signed LoA.
- Code impact: no runtime behavior changed; traceability guards now reject any
  remaining generic pending implementation evidence in the RTM annexes.
- Evidence updated: KRN-CERT-001 now points at deterministic conformance
  statement coverage and the explicit external approval/LoA requirement.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:16:05Z

- Increment completed: promote ODA vector-annex boundary evidence.
- Research note: KRN-ANNEX-005 should not remain a generic pending row when the
  repository already enforces complete vector syntax, method-specific coverage,
  and placeholder rejection; it still must retain the lab-supplied SDA/DDA/CDA
  vector boundary for certification use.
- Code impact: no runtime behavior changed; traceability guards now require the
  vector-annex row to cite executable ODA vector validation evidence.
- Evidence updated: KRN-ANNEX-005 now points at complete-vector syntax,
  SDA/DDA/CDA coverage, and certification-mode placeholder rejection tests while
  explicitly preserving the lab-supplied vector requirement.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:12:20Z

- Increment completed: promote penetration-boundary evidence.
- Research note: KRN-CERT-004 needs both executable APDU/state-bypass
  regression evidence and a clearly external third-party assessment boundary.
- Code impact: no runtime behavior changed; the existing certification security
  regression is now first-class RTM evidence for the penetration row.
- Evidence updated: KRN-CERT-004 now cites the internal APDU injection and state
  bypass regression while retaining the external assessment requirement.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:08:05Z

- Increment completed: promote ODA CAPK, TVR, and CDA evidence.
- Research note: ODA claims should cite executable CAPK checksum/provenance,
  certificate-recovery, SDA/DDA/CDA failure, no-fallback, and vector-syntax
  regressions rather than broad TVR, config-signature, or CDA-vector labels.
- Code impact: no runtime behavior changed; existing ODA, config, FFI, and
  traceability tests are now first-class RTM evidence for the older ODA rows.
- Evidence updated: KRN-ODA-001/002/003/004/005/006/007/008 now cite concrete
  ODA regressions and an RTM guard in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:03:50Z

- Increment completed: promote reference, profile-class, and log-policy
  evidence.
- Research note: conformance, example-profile rejection, and production log
  policy claims should cite executable ABI JSON, certification profile class,
  masking, and APDU log suppression regressions rather than broad audit labels.
- Code impact: no runtime behavior changed; existing conformance, config, trace,
  and traceability tests are now first-class RTM evidence for the older rows.
- Evidence updated: KRN-REF-001, KRN-CFG-004, and KRN-LOG-001 now cite concrete
  regressions and an RTM guard in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:00:16Z

- Increment completed: promote deployment/profile-update evidence.
- Research note: deployment claims should cite executable signed-profile load,
  anti-rollback/replay rejection, atomic failed-update preservation, and
  versioned trace-identity regressions rather than broad update labels.
- Code impact: no runtime behavior changed; existing config, FFI, trace, and
  traceability tests are now first-class RTM evidence for the DPL rows.
- Evidence updated: KRN-DPL-001/002/003/004 now cite concrete profile update
  regressions and an RTM guard in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:54:05Z

- Increment completed: promote API and error-boundary evidence.
- Research note: ABI and callback-failure claims should cite executable
  reentrancy, timeout, last-error, stable-error-table, and fail-closed
  regressions rather than broad concurrency or callback-trace labels.
- Code impact: no runtime behavior changed; existing API, FFI, FSM, and error
  table tests are now first-class RTM evidence for the older API/error rows.
- Evidence updated: KRN-API-004/006/007 and KRN-ERR-001/002 now cite concrete
  API/error regressions and an RTM guard in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:49:38Z

- Increment completed: promote CVM/PIN capability and custody evidence.
- Research note: CVM and PIN boundary claims should cite executable capability,
  9F34 result, PED-handle, redaction, and replay-custody regressions rather
  than broad ABI or method labels.
- Code impact: no runtime behavior changed; existing CVM capability, CVM
  Results, PIN method, PED handle, and PIN-custody tests are now first-class
  RTM evidence for the older CVM/PIN rows.
- Evidence updated: KRN-CVMCAP-001, KRN-CVMRES-001, KRN-PIN-001/002/003, and
  KRN-PINAPI-001/002 now cite concrete CVM/PIN regressions and RTM guards in
  both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:45:44Z

- Increment completed: promote terminal capability and TTQ evidence.
- Research note: terminal parameter claims should cite executable ABI, PDOL,
  contactless-PDOL, and online-handoff checks rather than broad handoff labels.
- Code impact: no runtime behavior changed; existing 9F33 and 9F66 transaction
  flow regressions are now first-class RTM evidence for the older terminal
  parameter rows.
- Evidence updated: KRN-TERMCAP-001 and KRN-TTQ-001 now cite concrete
  traceability and RTM guard regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:41:55Z

- Increment completed: promote GPO and READ RECORD evidence.
- Research note: early transaction-flow claims should cite executable parser,
  APDU-construction, AFL-order, record-storage, and masking regressions rather
  than generic parser or log labels.
- Code impact: no runtime behavior changed; existing GPO, READ RECORD, AFL,
  record parser, and APDU masking tests are now first-class RTM evidence for
  the older GPO/RR rows.
- Evidence updated: KRN-GPO-001/002 and KRN-RR-001/002/003 now cite concrete
  parser, APDU, AFL, record, traceability, and RTM guard regressions in both
  RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:38:17Z

- Increment completed: promote TVR clearing, RFU masking, and TSI bit evidence.
- Research note: TVR/TSI certification claims need executable bit-state
  controls rather than generic trace labels, especially where reserved bits and
  phase-specific indicators define the observable transaction state.
- Code impact: no runtime behavior changed; existing TVR clearing, RFU-mask,
  TSI allowed-bit, and phase-gating regressions are now first-class RTM
  evidence for the older TVR/TSI rows.
- Evidence updated: KRN-TVR-002/003 and KRN-TSI-001 now cite concrete state,
  traceability, and RTM guard regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:36:20Z

- Increment completed: promote legacy GAC/CDA-control evidence.
- Research note: public approval-oriented material cannot prove command-bit
  correctness by log labels alone, so the RTM should tie GENERATE AC P1 and CDA
  request behavior to executable bit-mask, profile-encoding, and first-GAC
  control regressions.
- Code impact: no runtime behavior changed; existing GENERATE AC type-bit,
  CDA profile-encoding, and first-GAC CDA-control tests are now first-class RTM
  evidence for the older GAC rows.
- Evidence updated: KRN-GAC-008/009/010 now cite concrete APDU, profile, FFI,
  traceability, and RTM guard regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:31:56Z

- Increment completed: promote C-8 contactless kernel evidence.
- Research note: current public EMVCo contact-kernel material keeps
  C-8/contactless approval tied to product scope, ICS evidence, and laboratory
  execution, so RTM rows should cite structured outcome/callback and
  interface-separation regressions rather than generic logs or interface
  labels.
- Code impact: no runtime behavior changed; existing C-8 outcome, contactless
  callback, and contact/contactless separation regressions are now first-class
  RTM evidence.
- Evidence updated: KRN-C8-001/002/003 now cite concrete structured outcome,
  FFI contactless callback, C-8-only outcome, selected-kernel mapping, and
  contact-kernel rejection regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:27:09Z

- Increment completed: promote caller-owned buffer evidence.
- Research note: current public EMVCo approval material still ties product
  claims to ICS-supported features and laboratory conformance testing, so ABI
  ownership requirements should cite repeatable caller-buffer regressions
  instead of generic memory-analysis labels.
- Code impact: no runtime behavior changed; the existing caller-owned output
  buffer probes, short-buffer no-write check, exact-write check, null-length
  rejection, and empty-output helper tests are now first-class evidence.
- Evidence updated: KRN-API-005 now cites concrete caller-owned buffer,
  buffer-size probe, no-partial-write, empty-output, and RTM guard regressions
  in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:22:34Z

- Increment completed: promote unpredictable-number callback evidence.
- Research note: public EMVCo Level 2 material describes kernel software
  testing for EMV Chip specification compliance, so unpredictable-number
  evidence should identify runtime callback and weak-output rejection
  regressions instead of generic RNG trace or injection labels.
- Code impact: RNG integration evidence now explicitly counts a successful
  platform unpredictable-number callback invocation, then still verifies
  fail-closed behavior for all-zero and repeated values.
- Evidence updated: KRN-RNG-001/002 now cite concrete callback, weak-output
  rejection, stable RNG error-code, and RTM guard regressions in both RTM
  annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:17:46Z

- Increment completed: promote APDU status-word evidence.
- Research note: current public EMVCo contact-kernel approval material frames
  approval as kernel conformance to the EMV specification, and public Level 2
  guidance describes kernel software testing for specification compliance; the
  RTM should therefore identify executable status-policy controls rather than
  generic APDU logs or error-injection labels.
- Code impact: status-word classification now explicitly regresses that the
  same non-`9000` response maps to context-specific actions across SELECT,
  GPO, READ RECORD, GENERATE AC, and EXTERNAL AUTHENTICATE states.
- Evidence updated: KRN-APDU-009/010 now cite concrete state-specific,
  transport-follow-up, read-record, VERIFY/script, same-status-different-state,
  and traceability guard regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:13:16Z

- Increment completed: promote CVM parser and outcome evidence.
- Research note: current public EMVCo contact-kernel process material still
  centers product feature declarations in the ICS and validation through an
  EMVCo-recognized laboratory, so evidence rows should identify repeatable
  parser and outcome tests for each supported CVM feature.
- Code impact: CVM evaluation now explicitly regresses the EMV continuation
  bit behavior by skipping an unsupported offline PIN rule when continuation is
  allowed and selecting the next matching online PIN rule.
- Evidence updated: KRN-CVM-001/002 now cite concrete CVM parser,
  amount-condition, continuation, CVM result, and TVR-byte-3 regressions in
  both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:08:36Z

- Increment completed: promote TVR and CVM table evidence.
- Research note: public EMVCo process material continues to tie kernel
  approval to ICS-backed specification conformance and accredited laboratory
  testing, so RTM rows for low-level tables should cite deterministic tests
  rather than generic code-review labels.
- Code impact: CVM method decoding now has explicit coverage for the
  certification table codes, continuation-bit masking, scheme-specific range,
  and unknown-code handling.
- Evidence updated: KRN-TVR-001 and KRN-CVM-003 now cite executable bitmap
  catalogue, symbolic setter, CVM table, and contactless CDCVM boundary
  regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T01:01:06Z

- Increment completed: promote security trust-boundary evidence.
- Research note: current public EMVCo materials continue to frame kernel
  approval as specification compliance proven through implementation
  conformance statements, accredited test execution, and approval evidence,
  so trust-boundary rows should cite executable controls rather than generic
  review labels.
- Code impact: RTM coverage now guards KRN-SEC-001/002/003/004 against generic
  architecture, APDU-log, or PED-statement evidence labels and binds them to
  source custody scans, card-returned cryptogram packaging, CAPK
  integrity/provenance checks, and PED-owned PIN handle regressions.
- Evidence updated: KRN-SEC-001/002/003/004 now cite concrete executable
  trust-boundary evidence in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:56:22Z

- Increment completed: promote issuer script execution evidence.
- Code impact: issuer script runtime regressions now assert exact Template 71
  and Template 72 command APDU bytes for non-critical and critical script
  outcomes, binding script execution evidence to transmitted payloads rather
  than INS/length-only checks.
- Evidence updated: KRN-SCR-001/002/003/004/005/006 now cite concrete parser,
  command execution, SW result capture, phase-specific TVR/TSI, post-final
  script, critical-failure, and ABI result-reporting regressions in both RTM
  annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:50:59Z

- Increment completed: promote DDA INTERNAL AUTHENTICATE evidence.
- Code impact: the runtime DDA regression now captures and asserts the exact
  INTERNAL AUTHENTICATE APDU bytes built from the card DDOL, proving the DDA
  path transmits kernel-assembled DDOL data rather than checking only INS and
  command length.
- Evidence updated: KRN-DDA-001, KRN-DDA-002, and KRN-ODA-006 now cite
  concrete DDOL APDU, signed-dynamic-data parsing, ICC-key verification, and
  bad-signature TVR regressions in both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:47:13Z

- Increment completed: promote issuer authentication and final GENERATE AC
  evidence.
- Code impact: final GENERATE AC regression now captures and asserts the CDOL2
  APDU payload built from host ARC, issuer authentication data, TVR, and TSI,
  proving the second GENERATE AC path uses host/state data rather than generic
  length-only evidence.
- Evidence updated: KRN-IAUTH-001/002/003 and KRN-GAC2-001/002/003/004 now cite
  concrete APDU, issuer-authentication, CDOL2, and final-outcome regressions in
  both RTM annexes.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:39:47Z

- Increment completed: tighten ODA certification vector coverage validation.
- Code impact: certification-mode ODA vector validation now requires SDA, DDA,
  and CDA vector objects to each carry their method-specific cryptographic
  inputs and expected outputs instead of accepting required field names that
  appear elsewhere in the annex.
- Evidence updated: KRN-ODATV-001 now cites method-specific vector coverage,
  placeholder rejection, and RTM enforcement tests while KRN-ANNEX-005 remains
  pending for external lab-supplied complete cryptographic vectors.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:34:19Z

- Increment completed: harden trace-layer debug output before crash capture.
- Code impact: `MaskedValue`, `MaskedField`, and `ApduTrace` now expose only
  trace metadata, value lengths, suppression reasons, and field counts in
  `Debug` output while retaining `to_json()` as the explicit controlled log
  emission path.
- Evidence updated: KRN-LOG-003 now cites APDU trace debug redaction alongside
  APDU command, C-8, TLV, profile/CAPK, CVM, data-store, GAC, issuer, ODA, and
  replay crash-safety regressions.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:29:38Z

- Increment completed: harden contactless C-8 debug output before crash
  capture.
- Code impact: `ContactlessOutcome` and `RelayResistanceProfile` now expose
  only outcome metadata, UI/status metadata, APDU lengths, record lengths, and
  relay timing/failure metadata in `Debug` output without printing raw
  contactless outcome records or relay-resistance APDU bytes.
- Evidence updated: KRN-LOG-003 now cites contactless outcome and relay-profile
  debug redaction alongside APDU, TLV, profile/CAPK, CVM, data-store, GAC,
  issuer, ODA, and replay crash-safety regressions.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:24:34Z

- Increment completed: harden parsed TLV debug output before crash capture.
- Code impact: `Tlv` and `FlatTlv` now expose tag, value length,
  constructed flag, and child count metadata in `Debug` output without
  printing raw TLV values.
- Evidence updated: KRN-LOG-003 now cites TLV parser debug redaction in
  addition to APDU, profile/CAPK, CVM, data-store, GAC, issuer, ODA, and
  replay crash-safety regressions.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:20:41Z

- Increment completed: harden signed profile and CAPK debug output.
- Code impact: `ProfileSet`, `SchemeProfile`, `AidProfile`, and `Capk` now
  expose only counts, lengths, source metadata, and non-sensitive selectors in
  `Debug` output instead of CAPK bytes, action-code details, DOL bytes, or
  full AID profile contents.
- Evidence updated: KRN-LOG-003 now cites profile/CAPK debug redaction as part
  of crash-safety coverage.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:17:08Z

- Increment completed: harden ODA authentication-material debug output.
- Code impact: recovered certificates, signed application data, public-key
  inputs, internal authentication responses, and static authentication records
  now expose only lengths and safe metadata in `Debug` output.
- Evidence updated: KRN-LOG-003 now cites ODA debug redaction alongside APDU,
  CVM, data-store, GAC, issuer, and replay crash-safety regressions.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:13:47Z

- Increment completed: harden command APDU debug output before crash capture.
- Code impact: `CommandApdu` now redacts command payload bytes in `Debug`
  output while preserving CLA/INS/P1/P2, payload length, and Le metadata for
  diagnostics.
- Evidence updated: KRN-LOG-003 now cites APDU command debug redaction alongside
  CVM, data-store, GAC, issuer, and replay crash-safety regressions.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:11:05Z

- Increment completed: harden PED offline PIN handle debug surfaces.
- Code impact: `PedPinHandle`, `CvmAction`, `CvmPinHandles`, and `CvmOutcome`
  now redact opaque secure-PIN handle values in `Debug` output while preserving
  method, presence, CVM result, and TVR metadata needed for diagnostics.
- Evidence updated: KRN-PINAPI-001 now cites concrete PED handle boundary tests,
  and KRN-LOG-003 now includes offline PIN handle debug redaction evidence.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T00:05:56Z

- Increment completed: harden crash/debug redaction for online authorization and
  issuer response structures.
- Code impact: `GenerateAcResponse`, `OnlineAuthorizationPackage`, `TagValue`,
  `HostResponse`, and `IssuerScript` now expose only non-sensitive metadata from
  their `Debug` implementations instead of raw cryptograms, issuer
  authentication data, script command bytes, PAN, or track data.
- Evidence updated: KRN-LOG-003 RTM rows now cite the new GAC and issuer debug
  redaction regressions in addition to existing data-store and replay redaction
  evidence.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:59:51Z

- Increment completed: tighten certification-mode ODA vector coverage gates.
- Code impact: `validate_oda_vector_annex` now requires certification vector
  annexes to include SDA, DDA, and CDA coverage plus the method-specific
  cryptographic fields before they can pass certification-mode validation.
- Evidence updated: ODA vector validation now rejects single-scenario
  certification annexes while keeping bundled structural fixtures
  non-certification only; KRN-ANNEX-005 remains pending until lab-supplied
  complete cryptographic vectors are attached.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

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

## 2026-05-21T23:34:31Z

- Increment completed: add product-level performance profile and measurement
  buckets for KRN-PERF-001 and KRN-PERF-002.
- Code impact: `src/perf.rs` separates ODA RSA, ODA ECC, TLV parsing, and APDU
  overhead timing buckets; `docs/performance_profile.csv` defines Hyperion MP35P
  target buckets; the lab manifest and build provenance include the performance
  profile.
- Evidence updated: KRN-PERF-001 and KRN-PERF-002 RTM rows now cite performance
  bucket accumulation, product profile validation, traceability coverage, and
  the RTM guard.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:39:48Z

- Increment completed: promote certification evidence-boundary and supported
  contactless C-8 scope evidence for KRN-CERT-002 and KRN-INT-003.
- Code impact: traceability tests now prove certification-mode profile loading
  rejects illustrative profiles, ODA structural fixtures are rejected as
  certification vectors, and bundled contactless certification profiles route
  supported contactless schemes through C-8 while keeping contact kernels
  separate.
- Evidence updated: KRN-CERT-002 and KRN-INT-003 RTM rows now cite the
  certification evidence-boundary guards, C-8 certification-scope guard,
  interface-specific kernel mapping, and RTM guards.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:43:12Z

- Increment completed: align the specification status with the controlled
  pre-certification evidence package.
- Code impact: `docs/spec.md` no longer labels v6.0 as final or a complete
  certification baseline; the header now states that licensed external
  standards and lab artifacts prevail and that final certification requires
  signed profiles, lab-supplied vectors, conformance traces, and approval
  artifacts.
- Evidence updated: traceability coverage now rejects overclaiming phrases such
  as `(Final)`, `complete artifact set`, and `complete controlled certification
  baseline` in the active specification.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:46:55Z

- Increment completed: make lab-manifest attachment state match actual evidence
  availability.
- Code impact: `docs/lab_submission_manifest.md` now leaves unattached external
  reports, PCI PTS statements, signed lab conformance templates, and full APDU
  trace packs unchecked while keeping locally generated ABI conformance JSON,
  build provenance, and trace identity metadata checked.
- Evidence updated: traceability coverage now fails if any `[to be attached]`
  manifest line is marked complete and explicitly checks the expected local
  versus external artifact states.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:50:48Z

- Increment completed: remove stale embedded lab-manifest checklist and
  declaration from `docs/spec.md`.
- Code impact: the spec now delegates attachment state to
  `docs/lab_submission_manifest.md`, requires unchecked external evidence until
  attached and independently verified, and carries the ODA structural-fixture
  gate instead of declaring bundled vectors and profiles authentic.
- Evidence updated: traceability coverage now rejects the old broad contact
  scope claim and the unsupported "all test vectors and configuration profiles
  are authentic" declaration in the active spec.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-21T23:54:20Z

- Increment completed: tighten RTM pending-evidence governance.
- Code impact: traceability coverage now allowlists pending implementation
  evidence to exactly KRN-ANNEX-005 and KRN-CERT-001 across both RTM annexes.
  The guard also verifies those rows remain tied to complete lab cryptographic
  vectors and EMV Level 2 approval artifacts rather than ordinary implementation
  backlog.
- Evidence updated: accidental new pending RTM rows or premature promotion of
  lab-only gates will now fail the traceability suite.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.
