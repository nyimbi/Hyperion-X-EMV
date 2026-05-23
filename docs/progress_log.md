# Hyperion EMV Kernel Progress Log

This log records certification-hardening increments, evidence, and open risks.
It is intentionally concise: commit history remains the authoritative code
decision record, while this file tracks work toward certification readiness.

## 2026-05-23T09:57:23Z

- Increment completed: add typed Application Usage Control (`9F07`) parsing and
  pre-lab decode output for processing-restriction triage.
- Research note: public EMV tag references and open-source decoder/tooling
  patterns consistently frame `9F07` as a two-byte issuer usage-control object
  for domestic/international cash, goods, services, ATM, other-terminal, and
  cashback permissions. Hyperion keeps final semantics under licensed
  EMV/profile review and uses the public material only to guide operator-facing
  trace readability.
- Code impact: `src/restrictions.rs` now exposes `ApplicationUsageControl::parse`,
  raw-byte access, named usage-bit predicates, and byte-2 RFU mask reporting;
  `krn_emv_decode auc <hex>` reports the same runtime mapping without changing
  processing-restriction policy.
- Evidence updated:
  `restrictions::tests::parses_auc_and_exposes_named_usage_bits`,
  `krn_emv_decode::tests::auc_output_names_usage_control_bits_without_policy_override`,
  `krn_emv_decode::tests::cli_routes_auc_mode`, and the processing-restriction
  plus TLV-catalogue RTM guards.
- Remaining external blockers: licensed EMV/scheme review still determines
  final AUC service semantics, RFU treatment, and lab-tool mapping.

## 2026-05-23T09:51:45Z

- Increment completed: make `krn_emv_decode` TLV, DOL, and primitive tag-list
  output consult the controlled TLV catalogue for tag names, type, length rule,
  and sensitive-data classification.
- Research note: refreshed the local `emvpt`, `openemv/emv-utils`, and
  `greenboxal/emv-kernel` reference clones. The useful adaptation is
  operator-facing tag dictionaries in standalone trace tools; Hyperion keeps
  the source of truth in `docs/tlv_catalogue.csv` and does not copy reference
  code or treat open-source tag tables as certification authority.
- Code impact: decoder output remains value-suppressed for TLV values and
  value-free for DOL/tag-list data, but now reports catalogue hit/missing status
  plus metadata needed for lab-trace triage.
- Evidence updated:
  `krn_emv_decode::tests::tlv_output_suppresses_values`,
  `krn_emv_decode::tests::dol_output_lists_tags_and_lengths`,
  `krn_emv_decode::tests::tag_list_output_lists_primitive_tags_without_values`,
  and `traceability_foundation::rtm_promotes_tlv_catalogue_and_dol_classification_evidence`.
- Remaining external blockers: licensed profile/lab review still determines
  accepted tag semantics, scheme-specific classifications, and formal
  tool-case mappings.

## 2026-05-23T09:42:51Z

- Increment completed: add typed CVM Results parsing and pre-lab decode output.
- Research note: tag `9F34` is a non-sensitive three-byte control object that
  carries the applied CVM method, condition code, and result status into CDOL
  construction and online handoff.
- Code impact: `src/cvm.rs` now exposes `CvmResults` and `CvmResultStatus`,
  and `krn_emv_decode cvm-results <hex>` reports the method, condition, result
  status, raw byte shape, and runtime authority without exposing PIN or PED
  handle material.
- Evidence updated: `cvm::tests::parses_cvm_results_three_byte_object`,
  `krn_emv_decode::tests::cvm_results_output_names_method_condition_and_result`,
  and `krn_emv_decode::tests::cli_routes_cvm_results_mode` bind `9F34` triage
  into CVM Results and TLV traceability.
- Remaining external blockers: licensed CVM catalogue reconciliation and
  lab-tool trace mapping remain required before treating CVM behavior as final
  certification evidence.

## 2026-05-23T09:34:40Z

- Increment completed: add masked host-response triage to `krn_emv_decode`.
- Research note: issuer authentication and issuer script handling remain a
  certification-sensitive surface because host response tags drive EXTERNAL
  AUTHENTICATE, Template 71/72 script sequencing, phase-specific TVR/TSI
  updates, and Level 3 result reporting.
- Code impact: `krn_emv_decode host-response <hex>` reuses the runtime
  `parse_host_response` path and emits only ARC, authorization-code presence,
  issuer-authentication-data length, script phases, command counts, and command
  lengths.
- Evidence updated:
  `krn_emv_decode::tests::host_response_output_suppresses_issuer_authentication_and_scripts`
  and `krn_emv_decode::tests::cli_routes_host_response_mode` cover the masked
  decoder path and are bound into issuer-authentication/script traceability.
- Remaining external blockers: lab-approved host-response traces and licensed
  scheme script-policy rules are still required before treating this as final
  certification evidence.

## 2026-05-23T09:26:19Z

- Increment completed: add controlled AIP parsing and pre-lab decode output.
- Research note: AIP is non-sensitive transaction capability evidence that
  drives GPO parsing and ODA selection; exposing the runtime-consumed ODA
  capability bits in `krn_emv_decode` improves lab-trace triage without
  treating public reference decoders as certification evidence.
- Code impact: `src/aip.rs` centralizes two-byte AIP validation and the
  runtime ODA capability predicates used by GPO parsing, ODA selection, and
  `krn_emv_decode aip <hex>`.
- Evidence updated: `aip::tests::parses_runtime_oda_capability_bits`,
  `aip::tests::rejects_non_two_byte_aip_values`, and
  `krn_emv_decode::tests::aip_output_names_runtime_oda_capabilities` are bound
  into GPO and TLV traceability rows and the lab-manifest decoder scope.
- Remaining external blockers: licensed scheme/profile rules and lab traces
  still define the accepted interpretation of any AIP bits outside the runtime
  predicates used here.

## 2026-05-23T09:17:03Z

- Increment completed: share EMV terminal-type validation between runtime
  transaction-parameter checks and the pre-lab decode utility.
- Research note: the open-source reference review favors parser-backed
  operator tooling for lab-trace triage; `9F35` Terminal Type is now decoded
  through the same allowlist the runtime uses for online-capability decisions.
- Code impact: `src/terminal.rs` centralizes accepted terminal-type values,
  operator/location labels, and online-capability classification, and
  `krn_emv_decode terminal-type <hex>` emits non-sensitive review output.
- Evidence updated: `terminal::tests::parses_valid_terminal_types_and_online_capability`,
  `krn_emv_decode::tests::terminal_type_output_names_emv_online_capability`,
  and the RTM/lab-manifest guards bind terminal-type tooling to the controlled
  TLV catalogue evidence.
- Remaining external blockers: lab trace and profile authority still determine
  which terminal types are accepted in a submitted deployment profile.

## 2026-05-23T09:09:47Z

- Increment completed: clear stale transaction artifacts whenever
  `krn_set_transaction_params` starts a new transaction.
- Research note: a certification lifecycle boundary must not allow previous
  ODA, GENERATE AC, host-response, issuer-script, offline-authentication, or
  card-data evidence to bleed into the next transaction; the unpredictable
  number repeat detector remains intentionally cross-transaction.
- Code impact: setting transaction parameters now clears selected ODA method,
  requested and completed cryptograms, final outcome, online authorization and
  host response buffers, issuer script results, card data, and offline
  authentication records before moving to `S1`.
- Evidence updated: `ffi::tests::transaction_params_clear_previous_transaction_artifacts`
  covers stale artifact clearing and RNG history preservation, and both RTM
  annexes cite it under transaction-parameter ABI evidence.
- Remaining external blockers: lab replay evidence is still required to prove
  lifecycle isolation across real terminal sessions and scheme-certified
  profiles.

## 2026-05-23T09:00:03Z

- Increment completed: require explicit ABI interface selection for every
  transaction.
- Research note: contact and contactless certification evidence must remain
  separated by selected interface and certified kernel/profile mapping; silently
  treating `interface_preference = 0` as contact weakens that boundary.
- Code impact: `KrnTxnParams.interface_preference` now accepts only
  `KRN_INTERFACE_CONTACT = 1` or `KRN_INTERFACE_CONTACTLESS = 2`, and rejects
  `0` or unknown values before transaction state is advanced.
- Evidence updated: `ffi::tests::transaction_params_require_explicit_supported_interface`
  covers accepted and rejected ABI values, and both RTM annexes cite it under
  configuration validation and explicit interface/kernel mapping evidence.
- Remaining external blockers: accepted lab/device evidence is still required
  for every claimed contact or contactless interface, scheme profile, and
  kernel approval path.

## 2026-05-23T08:54:51Z

- Increment completed: align `docs/eng_notes.md` with the current validated
  state-machine annex.
- Research note: the remaining state-machine risk is no longer a missing local
  expansion table; it is licensed/lab reconciliation of the repository annex
  against accepted tool cases and scheme constraints.
- Code impact: no runtime behavior changed; the traceability guard now rejects
  stale notes that list the expanded repository state machine as still missing.
- Evidence updated: `lab_manifest_leaves_unattached_external_reports_unchecked`
  asserts the engineering notes describe the state-machine CSV as expanded,
  machine-validated, and authoritative while preserving the licensed
  reconciliation blocker.
- Remaining external blockers: lab/tool acceptance of the complete APDU/SW and
  FSM crosswalk remains outside repository-controlled evidence.

## 2026-05-23T08:50:31Z

- Increment completed: remove the stale inline state-machine table from
  `docs/spec.md` and make `docs/state_machine.csv` the single authoritative
  transition annex.
- Research note: certification evidence should avoid duplicated normative
  transition tables because the executable annex and runtime FSM already route
  offline TC/AAC and post-final issuer-script terminal paths through `S16`.
- Code impact: no runtime behavior changed; traceability tests now assert that
  the spec delegates Annex E to the canonical CSV and does not retain stale
  inline transition rows.
- Evidence updated: `spec_delegates_state_machine_to_canonical_csv_annex`
  checks the spec delegation language and verifies the canonical CSV keeps the
  current `S16` terminal paths.
- Remaining external blockers: licensed lab reconciliation of the complete FSM
  against scheme/tool cases remains required before certification submission.

## 2026-05-23T08:43:44Z

- Increment completed: add a deterministic pre-lab parser/APDU no-crash smoke
  artifact.
- Research note: `CERT-OPEN-010` remains an external-report blocker; the local
  smoke artifact is repository-controlled evidence that selected malformed and
  valid parser inputs return typed outcomes without replacing tool-versioned
  static-analysis or fuzz/no-crash reports.
- Code impact: `prelab_no_crash_smoke_json()` exercises TLV, DOL, command APDU,
  issuer host-response, GENERATE AC response, and replay-adapter boundary cases
  and fails closed if any case returns a different typed outcome.
- Evidence updated: `docs/prelab_no_crash_smoke.json`,
  `examples/krn_prelab_no_crash_smoke.rs`, `docs/prelab_quality_gates.json`,
  `docs/abi_conformance_statement.json`, the lab manifest, and build
  provenance expectations now include the no-crash smoke artifact while
  preserving `does_not_close = CERT-OPEN-010`.
- Remaining external blockers: accepted coverage, full EMV integration,
  static-analysis, fuzz/no-crash, lab trace, signed profile/CAPK, device/PED,
  third-party security, and approval reports are still required.

## 2026-05-23T08:33:46Z

- Increment completed: harden CDCVM recognition at the CTQ/profile boundary.
- Research note: `docs/spec.md` treats CDCVM as contactless-profile specific
  and CTQ/card-capability driven, not as a universal Book 3 CVM code or a
  single unvalidated card byte.
- Code impact: CDCVM recognition now requires a contactless transaction,
  signed-profile `cdcvm_supported = true`, and well-formed two-byte `9F6C`.
  Malformed `9F6C` now returns `ParseError` instead of being silently ignored,
  and contact transactions cannot satisfy CDCVM through contactless CTQ data.
- Evidence updated:
  `ffi::tests::contactless_cdcvm_requires_profile_ctq_and_contactless_interface`
  covers the profile/interface/CTQ-shape boundary, and both RTM CSVs cite it
  under `KRN-CLESS-004` and `KRN-CVM-004`.
- Remaining external blockers: scheme-specific CTQ semantics remain subject to
  licensed profile and lab reconciliation; certification still needs accepted
  coverage, full EMV integration, static-analysis, fuzzing/no-crash, lab
  traces, signed profile/CAPK authority, device/PED evidence, and approval
  reports.

## 2026-05-23T08:27:07Z

- Increment completed: add an explicit certification-freeze hash checklist to
  the pre-lab quality manifest.
- Research note: current public EMVCo and PCI SSC checks confirm that C-8,
  contactless-suite bulletins, and PCI PTS/PED evidence remain external
  reconciliation inputs, so repository evidence should bind local artifacts
  without claiming final lab/device approval.
- Code impact: `prelab_quality_gates_json` now emits required freeze hash
  slots for `kernel_binary_hash`, `config_bundle_hash`, `capk_bundle_hash`,
  `scheme_profile_hash`, `test_vector_hash`, and
  `traceability_matrix_hash`, all marked pending external certification
  freeze.
- Evidence updated: `docs/prelab_quality_gates.json`,
  `docs/lab_submission_manifest.md`, and
  `traceability_foundation::lab_manifest_and_provenance_cover_reproducible_build_artifacts`
  now prove the freeze checklist is present while final lab/tool crosswalk and
  hash attachments remain external.
- Remaining external blockers: certification still needs the release binary
  digest, signed configuration/profile/CAPK bundle digests, lab vector and
  trace-pack digests, final RTM/lab-tool crosswalk digest, accepted coverage,
  full EMV integration, static-analysis, fuzzing/no-crash, device/PED
  evidence, and approval reports.

## 2026-05-23T08:21:14Z

- Increment completed: make CDA authentication data profile-defined.
- Research note: the open-source reference review reinforces that CDA-specific
  dynamic-authentication behavior should be driven by signed profile and
  lab-authoritative evidence, not inferred from public implementations.
- Code impact: signed AID profiles now carry `cda_authentication_data`, default
  to `application_cryptogram`, and can require
  `application_cryptogram_9f4c`. First-GAC CDA verification now builds its
  authentication input from that policy and fails closed with
  `TVR_B1_CDA_FAILED` when a required `9F4C` is absent.
- Evidence updated:
  `config::tests::cda_authentication_data_is_profile_defined_and_consistent`,
  `ffi::tests::cda_authentication_data_follows_profile_policy`, and
  `ffi::tests::runtime_cda_profile_required_9f4c_sets_tvr_when_absent` cover
  the profile parser, input builder, and runtime TVR branch. Both RTM CSVs and
  the scheme profile dictionary cite the new policy evidence.
- Remaining external blockers: certification still needs licensed EMV/scheme
  reconciliation for any additional CDA concatenation rules, accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-23T08:04:04Z

- Increment completed: reroute failed CDA offline cryptograms through TAA.
- Code impact: when first GENERATE AC returns an offline TC/AAC while CDA
  verification fails, the runtime no longer accepts the card-returned offline
  outcome directly. It records `TVR_B1_CDA_FAILED`, re-enters Terminal Action
  Analysis with the updated TVR, and fails closed if that reroute would require
  unsupported online evidence from a non-ARQC response.
- Evidence updated:
  `ffi::tests::runtime_cda_failed_offline_cryptogram_reroutes_through_taa`
  covers the offline-TC failure branch, and both RTM CSVs now cite it under
  `KRN-ODA-007` and `KRN-GAC1-005`.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-23T07:43:14Z

- Increment completed: reject ambiguous profile ISO date prefixes.
- Code impact: signed certification profile dates now require a `20YY-MM-DD`
  shape before conversion into the EMV two-digit date model. Non-numeric or
  unsupported century prefixes can no longer alias to an accepted CAPK expiry or
  provenance retrieval date.
- Evidence updated:
  `config::tests::preserves_and_validates_profile_source_retrieval_dates` covers
  ambiguous retrieval-date prefixes, and
  `config::tests::rejects_invalid_capk_expiry_calendar_dates` covers ambiguous
  CAPK expiry prefixes.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-23T00:12:13Z

- Increment completed: require retrieval dates for signed certification
  provenance.
- Code impact: certification profile and CAPK `source` objects must now carry a
  nonblank, valid, non-future ISO `retrieved` date. Omitted retrieval dates are
  rejected instead of allowing incomplete provenance into audit, replay, and
  lab-submission evidence.
- Evidence updated:
  `config::tests::preserves_and_validates_profile_source_retrieval_dates` now
  covers missing profile-source and CAPK-source retrieval dates, and the ODA
  runtime certification fixture carries explicit retrieval metadata.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-23T00:00:46Z

- Increment completed: bind certification-scope bundled scheme declarations to
  loaded scheme profiles.
- Code impact: certification profile loading now rejects signed scope material
  when a loaded `scheme_profile` is not declared as bundled, or when a bundled
  scheme declaration has no corresponding loaded profile.
- Evidence updated:
  `config::tests::rejects_invalid_certification_scope_boundaries` now covers
  mismatches between declared bundled schemes and actual loaded scheme profiles
  in both directions.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:53:12Z

- Increment completed: reject ambiguous signed provenance metadata.
- Code impact: certification profile and CAPK source metadata now fail closed
  when `owner`, `document`, or `version` contain leading or trailing whitespace,
  preventing visually ambiguous provenance identities from entering profile
  logs, manifests, and trace evidence.
- Evidence updated:
  `config::tests::rejects_blank_certification_profile_source_metadata` now
  covers whitespace-padded source document and version fields alongside blank
  owner and CAPK document cases.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:47:44Z

- Increment completed: canonicalize certification-scope scheme identities
  before duplicate and overlap checks.
- Code impact: signed certification scope arrays now compare trimmed scheme
  names, so whitespace-padded values cannot bypass bundled-versus-lab-required
  overlap checks or duplicate detection.
- Evidence updated:
  `config::tests::rejects_invalid_certification_scope_boundaries` now covers
  whitespace-padded overlaps and duplicates in addition to missing scope,
  whitespace-only values, unsupported material statuses, and missing
  production-bundle requirements.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:40:34Z

- Increment completed: reject whitespace-only signed scheme identity fields.
- Code impact: certification profile loading now treats trimmed-blank
  `scheme_name`, `kernel_type`, and `contact_kernel_type` values as invalid
  signed scheme metadata before interface/kernel mapping can accept them.
- Evidence updated:
  `config::tests::rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces`
  now covers whitespace-only scheme names and kernel mapping labels alongside
  missing contact kernels, C-8 contact-kernel misuse, invalid contactless
  kernel mappings, and duplicate interfaces.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:34:18Z

- Increment completed: reject whitespace-only certification-scope strings.
- Code impact: certification profile loading now treats trimmed-blank bundled
  scheme names, lab-required scheme names, and contactless kernel profile labels
  as invalid signed scope material.
- Evidence updated:
  `config::tests::rejects_invalid_certification_scope_boundaries` now covers
  whitespace-only scope values alongside missing scope, overlapping bundled/lab
  scheme names, unsupported material statuses, and missing production-bundle
  requirements.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:27:37Z

- Increment completed: make ODA certification-vector method IDs
  token-delimited.
- Code impact: certification-mode ODA vector validation now accepts only
  `SDA_`/`SDA-`, `DDA_`/`DDA-`, or `CDA_`/`CDA-` ID tokens with nonempty
  alphanumeric/underscore/hyphen suffixes. Ambiguous prefixes such as
  `SDAX_PASS` no longer satisfy the SDA gate.
- Evidence updated:
  `oda::tests::certification_vector_ids_are_unique_and_method_scoped` now
  covers duplicate IDs, unknown method IDs, ambiguous prefixes, and invalid
  delimiters. `docs/spec.md` documents the token shape.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:22:34Z

- Increment completed: make ODA certification-vector IDs unique and
  method-scoped.
- Code impact: certification-mode ODA vector validation now rejects empty,
  duplicate, or non-ODA-prefixed vector IDs before accepting lab-supplied SDA,
  DDA, and CDA coverage. Structural fixture validation remains available for
  parser and evidence-plumbing tests.
- Evidence updated:
  `oda::tests::certification_vector_ids_are_unique_and_method_scoped` covers
  duplicate IDs and unknown method prefixes. `docs/spec.md` now documents the
  vector-ID rule, both RTM CSVs cite the regression under `KRN-ODATV-001` and
  `KRN-ANNEX-005`, and the traceability foundation asserts those citations.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:16:17Z

- Increment completed: make production profile loading reject fixture-pending
  signed-material statuses.
- Research note: public EMVCo and PCI SSC pages were checked before this slice;
  no repository-controlled licensed behavior was inferred from public bulletins.
  The actionable local gap was keeping production policy stricter than
  pre-lab certification policy for signed profile/CAPK material status.
- Code impact: `BuildMode::Production` now requires certification scopes to
  declare `lab_signed_certification_profile` and `lab_signed_capks`, while
  certification/pre-lab loading can still accept fixture-pending markers for
  controlled engineering evidence.
- Evidence updated:
  `config::tests::production_rejects_fixture_pending_profile_material` covers
  fixture rejection, partial lab-signed rejection, and full lab-signed
  acceptance. `docs/spec.md` now documents the production-only gate, both RTM
  CSVs cite the regression under `KRN-CFG-002`, and the traceability foundation
  asserts the citation.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T23:03:13Z

- Increment completed: preserve signed-profile provenance retrieval dates in
  the loaded profile model and generated review dictionary.
- Code impact: `ProfileSource` now carries the optional `retrieved` date,
  validates it as an ISO date when present, rejects blank/placeholder retrieval
  metadata or dates after the evaluated bundle date, and renders bundle/CAPK
  retrieval dates in `docs/scheme_profile_dictionary.md`.
- Evidence updated:
  `config::tests::preserves_and_validates_profile_source_retrieval_dates` covers
  retained, malformed, blank, and future-dated provenance dates,
  `krn_scheme_profile_dictionary` asserts the rendered retrieval fields without
  exposing raw CAPK/CDOL material, and both RTM CSVs cite the retrieval-date
  regression under `KRN-CFG-002`.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T22:52:51Z

- Increment completed: fail closed on certification/production profile bundles
  that omit the schema marker or carry blank signed-provenance fields.
- Research note: public EMVCo and PCI SSC pages were refreshed before this
  slice. `docs/standards_watch.md` already records the current public C-8,
  contactless bulletin, approval-process, and PCI PTS signals, so the
  repository-controlled action stayed focused on signed-profile gate hardening.
- Code impact: `load_profile_set` now requires `schema_version = "1.0"` outside
  test mode and rejects blank certification profile/CAPK source metadata before
  accepting a profile for use.
- Evidence updated:
  `config::tests::rejects_invalid_profile_schema_version` now covers missing,
  unsupported, and malformed schema markers, and
  `config::tests::rejects_blank_certification_profile_source_metadata` covers
  blank profile and CAPK provenance. Both RTM CSVs cite the provenance
  regression under `KRN-CFG-002`.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T22:42:41Z

- Increment completed: keep issuer-script result status words and execution
  phase atomic inside the FFI runtime.
- Code impact: the context now stores each captured issuer-script result as one
  typed record containing both the SW1/SW2 pair and the Template 71/72 phase,
  while preserving the public count, SW, and phase getter ABI.
- Evidence updated: existing issuer-script result and phase tests now exercise
  the single-record storage path, reducing internal divergence risk without
  changing host-facing behavior or RTM requirement mappings.
- Verification: `cargo fmt`, focused issuer-script result tests,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features -- -D warnings`, generated
  pre-lab/conformance/profile diff checks, and `git diff --check` passed.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T22:34:48Z

- Increment completed: make issuer-script result reporting phase-aware without
  hard-coding a profile-specific `9F5B` layout.
- Code impact: the FFI context now records each script command result with its
  Template 71 before-final-GAC or Template 72 after-final-GAC phase and exposes
  `krn_get_issuer_script_result_phase` alongside the existing SW1/SW2 getter.
- Evidence updated:
  `ffi::tests::issuer_script_result_phase_api_reports_template_phase` and the
  runtime traceability flow prove phase reporting for Level 3 host reporting;
  both RTM CSVs now cite the phase-aware result evidence under `KRN-SCR-006`.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T22:18:20Z

- Increment completed: extend DOL source-precedence evidence into final
  GENERATE AC host-response data.
- Code impact: added an FFI regression proving a rejected AFL record containing
  host-response-owned tags (`89`/`8A`) remains atomic, does not seed card data,
  and cannot poison later CDOL2 construction from the accepted Level 3 host
  response.
- Evidence updated:
  `ffi::tests::final_gac_preserves_host_response_sources_after_rejected_record_tags`
  now appears in both RTM CSVs under `KRN-GAC2-001`, `KRN-GAC2-002`,
  `KRN-DOL-001`, and `KRN-TLV-006`, with traceability guards preventing drift.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T22:05:12Z

- Increment completed: harden AFL record admission against GAC and dynamic
  authentication tag injection.
- Code impact: `parse_read_record_body` now rejects Template 70 children that
  try to seed Application Cryptogram (`9F26`), CID (`9F27`), ATC (`9F36`),
  Signed Dynamic Application Data (`9F4B`), or ICC Dynamic Number (`9F4C`) into
  the transaction data store outside their controlled response contexts.
- Evidence updated:
  `record::tests::rejects_generate_ac_and_dynamic_auth_record_tags_atomically`
  proves rejection is atomic and does not overwrite existing response data, and
  both RTM CSVs cite it under `KRN-TLV-006`.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T22:04:41Z

- Increment completed: bring CDA dynamic-authentication trace handling into the
  controlled logging and TLV catalogue evidence.
- Code impact: production trace masking now suppresses GENERATE AC Signed
  Dynamic Application Data (`9F4B`) and ICC Dynamic Number (`9F4C`) rather than
  emitting dynamic authentication bytes in pre-lab JSON.
- Documentation impact: `docs/spec.md` and `docs/tlv_catalogue.csv` now name
  `9F4B` as Signed Dynamic Application Data, while the lab manifest records the
  new pre-lab masking evidence without closing the full lab trace-pack blocker.
- Evidence updated: the generated pre-lab APDU trace pack now includes a
  CDA-shaped GENERATE AC response with masked `9F4B`/`9F4C`, and both RTM CSVs
  cite the new dynamic-authentication suppression regression under logging
  policy and crash-safety requirements.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:48:26Z

- Increment completed: bring the open-source reference review into the
  repository-controlled provenance gate.
- Documentation impact: the lab manifest now lists `docs/open_source.md` as a
  clean-room learning/provenance artifact with explicit do-not-borrow and
  non-certification-evidence boundaries.
- Evidence updated: `prelab_quality_gates_json` and
  `docs/prelab_quality_gates.json` now include `docs/open_source.md` in the
  build-provenance command, and traceability guards require it in the manifest
  artifact set.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:44:28Z

- Increment completed: align the lab manifest's decoder coverage statement
  with the current `krn_emv_decode` command surface.
- Documentation impact: the pre-lab decoder utility line now names
  `numeric-code` alongside TLV, DOL, primitive tag-list, CVM-list, bitmap,
  CID, GENERATE AC, status-word, command APDU, and response APDU triage.
- Evidence updated: the traceability foundation guard now requires the lab
  manifest to mention `numeric-code`, preventing future drift between decoder
  functionality and submission-facing coverage language.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:41:34Z

- Increment completed: make the repository-controlled pre-lab trace scenarios
  carry explicit APDU command-flow and response-shape expectations.
- Code impact: `krn_prelab_trace_pack` now emits `expected_command_flow` and
  `expected_response_shapes` in each `trace-scenario`, covering SELECT, READ
  RECORD, GPO/GET RESPONSE, GENERATE AC retry, issuer-script retry, and
  status-only failure paths without unmasking APDU payload data.
- Evidence updated: regenerated `docs/prelab_apdu_trace_pack.jsonl`, tightened
  `prelab_apdu_trace_pack_is_replayable_masked_and_scoped`, and updated the
  lab manifest wording while preserving `CERT-OPEN-012` for the external full
  lab/test-tool trace pack.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:36:39Z

- Increment completed: extend parser-backed pre-lab decoding for EMV fixed
  numeric code fields without importing public lookup tables.
- Code impact: `krn_emv_decode numeric-code` now validates two-byte BCD values
  as `0XXX` three-digit codes, reports only non-sensitive shape/output facts,
  and leaves code authority to signed profiles or lab material.
- Evidence updated:
  `krn_emv_decode::tests::numeric_code_output_enforces_three_digit_bcd_shape`
  covers valid `0840`, non-BCD nibbles, wrong lengths, and four-digit BCD
  rejection; both RTM CSV annexes cite it under `KRN-TLV-004`, and the
  open-source adaptation backlog now names numeric-code triage in the decoder
  scope.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:31:26Z

- Increment completed: harden FFI transaction-parameter intake for numeric EMV
  currency and terminal-country values.
- Code impact: `read_transaction_params` now rejects `currency_code` and
  `terminal_country_code` values that cannot fit the three-digit numeric code
  shape encoded into fixed two-byte BCD tags `5F2A` and `9F1A`.
- Evidence updated:
  `ffi::tests::transaction_params_reject_non_three_digit_numeric_codes` covers
  both rejection paths and the valid `840` BCD encoding, and both RTM CSV
  annexes cite it under `KRN-API-003` and `KRN-CFG-002`.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:25:27Z

- Increment completed: make the repository-controlled static-analysis quality
  gate fail closed on clippy warnings.
- Code impact: `prelab_quality_gates_json` now records
  `cargo clippy --all-targets --all-features -- -D warnings` for
  `PRELAB-STATIC`, matching the verification gate used for completed slices.
- Evidence updated: regenerated `docs/prelab_quality_gates.json`, tightened the
  traceability guard to require the warnings-as-failures command, and updated
  the lab manifest to name the stricter local lint gate while preserving
  external static-analysis/fuzzing reports as open certification evidence.
- Remaining external blockers: certification still needs accepted coverage,
  full EMV integration, external static-analysis, fuzzing/no-crash, lab traces,
  scheme/CAPK/profile authority, device/PED evidence, and approval reports.

## 2026-05-22T21:18:54Z

- Increment completed: adapt the open-source tooling pattern of tag-list
  inspection without copying reference code by making Hyperion's own TLV parser
  handle unique primitive tag lists.
- Code impact: `tlv::parse_unique_primitive_tag_list` now centralizes bounded
  primitive tag-list parsing, ODA static-authentication data assembly reuses it
  for tag `9F4A`, and `krn_emv_decode tag-list` exposes masked pre-lab
  inspection for SDA evidence.
- Evidence updated: `docs/tlv_catalogue.csv` now classifies `9F4A` as a
  primitive tag list, both RTM CSVs cite the parser and decoder regressions
  under `KRN-ODA-005` and `KRN-TLV-004`, and the lab manifest/open-source
  review name primitive tag-list triage explicitly.
- Verification so far: focused TLV parser tests, ODA static-authentication
  tag-list regression, `krn_emv_decode` tag-list tests, RTM promotion tests,
  catalogue guard, `krn_emv_decode -- tag-list 829F375F2A`, and
  `cargo fmt --check` passed.
- Remaining external blockers: certification still needs licensed/lab
  reconciliation, scheme/lab-approved profile bundles, production CAPKs, device
  integration evidence, official vectors, full lab traces, and approval
  reports.

## 2026-05-22T21:03:12Z

- Increment completed: validate signed-profile `schema_version` values when
  present instead of merely allowing the root field name.
- Code impact: `load_profile_set` now rejects unsupported profile schema
  versions and malformed non-string schema versions before parsing scheme
  content.
- Evidence updated:
  `config::tests::rejects_invalid_profile_schema_version` covers the new
  fail-closed path, and both RTM CSV annexes plus the traceability guard cite it
  under `KRN-CFG-002`.
- Remaining external blockers: certification still needs signed lab/scheme
  profile authority, production CAPKs, device integration evidence, official
  vectors, and lab reports.

## 2026-05-22T20:52:18Z

- Increment completed: refresh public standards drift tracking with adjacent
  EMVCo bulletin watch-list items discovered during the latest public check.
- Research note: EMVCo public listings still keep C-8 v1.1 / SB 325 and the
  2026-05-21 Book A, Book B, and Kernel 2 RRP signals as the main contactless
  reconciliation items. They also show adjacent SB 314 TRMD, DSB 324 C-4, and
  DSB 308 Contact Features Sunsetting P1 signals that should be tracked without
  driving direct code behavior absent licensed/lab direction.
- Documentation impact: `standards_watch.md`, `certification_open_issues.md`,
  and `lab_submission_manifest.md` now name the adjacent watch-list inputs and
  keep them outside the repository-controlled implementation authority.
- Evidence updated: the traceability guard now requires the SB 314 / DSB 324 /
  DSB 308 watch-list language in the standards watch, manifest, and open-issues
  register.
- Remaining external blockers: certification still needs licensed/lab
  reconciliation, scheme/lab-approved profile bundles, production CAPKs, device
  integration evidence, official vectors, and lab reports before any public
  bulletin can be treated as accepted scope.

## 2026-05-22T20:45:33Z

- Increment completed: extend the generated pre-lab APDU trace pack with a
  status-only GENERATE AC failure case.
- Research note: the open-source reference review favors tool-first trace
  fixtures and explicit request/response evidence. Hyperion adapts that pattern
  by keeping the trace pack generated, masked, and independent of external
  implementation logic.
- Code impact: `krn_prelab_trace_pack` now emits
  `prelab.masking.generate-ac-status-only`, recording a bodyless `6985`
  GENERATE AC response as a status-only failure while preserving full APDU
  suppression and avoiding response-body parsing.
- Evidence updated: `docs/prelab_apdu_trace_pack.jsonl`,
  `docs/lab_submission_manifest.md`, and the traceability guard now require the
  new status-only case and manifest language.
- Remaining external blockers: certification still needs full lab/test-tool APDU
  trace logs, scheme/lab-approved profile bundles, production CAPKs, device
  integration evidence, and official vector/lab reports.

## 2026-05-22T20:36:59Z

- Increment completed: promoted transaction-type floor-limit table bounds from
  TRM construction into signed-profile loading evidence.
- Code impact: added a config-loader regression that rejects profile bundles
  containing more than `MAX_TRANSACTION_TYPE_FLOOR_LIMITS` per-transaction
  floor-limit overrides before terminal risk management can consume them.
- Evidence updated:
  `config::tests::rejects_oversized_transaction_type_floor_limit_profiles`
  now appears in both RTM CSV annexes under `KRN-CFG-002` and `KRN-TRM-001`,
  with traceability guard assertions preventing regression.
- Remaining external blockers: certification still needs scheme/lab-approved
  profile bundles, production CAPKs, device integration evidence, and official
  vector/lab reports.

## 2026-05-22T20:29:33Z

- Increment completed: bound direct AID fallback candidates by the same
  runtime selection cap used for PSE/PPSE directory candidates.
- Research note: direct selection is the fallback path when PSE/PPSE is absent,
  unsupported, or profile-directed. A signed profile bundle with too many
  interface-matching AIDs should fail closed rather than build an unbounded
  direct-selection list.
- Code impact: `direct_profile_candidates` now returns `LengthOverflow` before
  emitting more than `MAX_CANDIDATE_AIDS` contact or contactless candidates,
  preserving deterministic sorting for bounded candidate sets.
- Evidence updated:
  `selection::tests::rejects_direct_profile_candidates_above_limit` covers the
  direct-fallback resource limit, and both RTM CSV annexes cite it under
  `KRN-SEL-003`; the runtime selection RTM guard now requires that citation.
- Verification: `cargo fmt`, `cargo test
  rejects_direct_profile_candidates_above_limit`, `cargo test
  direct_candidates_are_sorted_by_signed_profile_priority`, and `cargo test
  rtm_promotes_runtime_apdu_selection_status_policy_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T20:23:12Z

- Increment completed: allow response APDU triage to classify status-only
  command failures without requiring a response-body parser.
- Research note: lab trace triage must handle both successful response
  templates and status-only card failures. The decoder should adapt the
  tool-first reference pattern while preserving EMV state-specific SW handling
  even when no TLV body exists.
- Code impact: `krn_emv_decode response-apdu generate-ac 6985` now reports the
  `GenerateAc` status action through the generic status-only trace path instead
  of attempting to parse a missing GENERATE AC template body.
- Evidence updated:
  `krn_emv_decode::tests::response_apdu_status_only_errors_do_not_require_body_parsing`
  covers the status-only failure path, while
  `response_apdu_generate_ac_uses_gac_masking_policy` continues to prove
  non-empty GENERATE AC responses use the GAC-specific masking parser.
- Verification: `cargo fmt`,
  `cargo test --example krn_emv_decode
  response_apdu_status_only_errors_do_not_require_body_parsing`, `cargo test
  --example krn_emv_decode response_apdu_generate_ac_uses_gac_masking_policy`,
  and `cargo run --quiet --example krn_emv_decode -- response-apdu generate-ac
  6985`, `cargo test --example krn_emv_decode`, `cargo test --examples`,
  `cargo test`, `cargo fmt --check`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T20:18:01Z

- Increment completed: extend the pre-lab decoder utility with response APDU
  envelope triage.
- Research note: the open-source reference review's strongest borrowable
  pattern remains tool-first trace inspection, not imported kernel logic. This
  slice adapts that idea by decoding complete response envelopes through
  Hyperion's own status classifier and trace masking paths.
- Code impact: `krn_emv_decode` now accepts `response-apdu` / `rapdu` with an
  APDU context and response-body-plus-SW input, splits SW1/SW2 from the body,
  reports the context-specific status action, and lists masked response TLV
  fields without exposing PAN, cryptograms, IAD, or other response-body values.
- Evidence updated:
  `krn_emv_decode::tests::response_apdu_output_masks_tlv_fields_and_classifies_status`,
  `krn_emv_decode::tests::response_apdu_generate_ac_uses_gac_masking_policy`,
  `krn_emv_decode::tests::malformed_response_apdu_is_rejected`, and
  `krn_emv_decode::tests::cli_routes_response_apdu_mode` cover the new route.
  The open-source adaptation backlog and lab submission manifest now name
  response APDU envelope decoding explicitly.
- Verification: `cargo fmt`,
  `cargo test --example krn_emv_decode
  response_apdu_output_masks_tlv_fields_and_classifies_status`, `cargo test
  --example krn_emv_decode response_apdu_generate_ac_uses_gac_masking_policy`,
  `cargo test --example krn_emv_decode malformed_response_apdu_is_rejected`,
  `cargo test --example krn_emv_decode cli_routes_response_apdu_mode`, `cargo
  test --example krn_emv_decode`, `cargo test --examples`, `cargo test`,
  `cargo run --quiet --example krn_emv_decode -- response-apdu generate-ac
  800B40123410111213141516179000`, `cargo fmt --check`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T20:01:07Z

- Increment completed: extend the pre-lab decoder utility with masked GENERATE
  AC response triage.
- Code impact: `krn_emv_decode` now accepts `gac`/`generate-ac-response`,
  parses template `80` and `77` responses through the kernel GAC parser, reports
  response shape, CID classification, and sensitive object lengths, and
  suppresses application cryptogram, IAD, and dynamic authentication values.
- Evidence update: both RTM annexes now cite
  `krn_emv_decode::tests::gac_response_output_parses_without_exposing_values`
  under KRN-GAC-004 and KRN-GAC1-004, and the traceability guard requires that
  decoder evidence.
- Verification: later committed as `f7dd4f3` after `cargo fmt`, focused
  `krn_emv_decode` example tests, `cargo test --examples`, `cargo test`,
  `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and
  `git diff --check` passed.

## 2026-05-22T19:10:48Z

- Increment completed: prevent issuer-script command data from leaking through
  generic flattened TLV/APDU trace masking.
- Research note: the pre-lab trace pack already asserted
  `issuer-script-command-data-suppressed` for issuer-authentication/script
  scenarios, while the generic TLV flattener would still have emitted tag `86`
  issuer script command bytes as raw hex. The same stream could also expose tag
  `9F18` issuer script identifiers, despite issuer script debug output being
  explicitly crash-safe.
- Code impact: `mask_tlv_value` now suppresses issuer authentication data
  (`91`) under an explicit issuer-authentication reason, issuer script command
  data (`86`), and issuer script identifiers (`9F18`) in controlled log
  emission. The
  `trace::tests::production_suppresses_issuer_script_command_data` proves the
  Template `71` flattened-stream path does not emit raw script command or
  identifier bytes.
- Evidence update: `KRN-LOG-003` in both RTM annexes now cites the issuer
  script command masking regression, and the RTM promotion guard requires that
  evidence.
- Verification: `cargo test
  trace::tests::production_suppresses_issuer_script_command_data`, `cargo test
  krn_log_001_masks_sensitive_tlv_and_gac_trace_values`, `cargo test
  rtm_promotes_logging_policy_evidence`, `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and `git
  diff --check` passed.

## 2026-05-22T19:01:04Z

- Increment completed: prevent AFL record data from pre-seeding host-response
  and issuer-script objects that must arrive through the Level 3 online
  response boundary.
- Research note: CDOL2 construction legitimately consumes host-response tags
  such as ARC (`8A`), Authorization Code (`89`), and issuer-authentication data
  (`91`) after `krn_apply_host_response`. The local gap was that READ RECORD
  admission denied terminal/kernel-owned data but did not explicitly reserve
  those host/issuer-response tags against card-record injection.
- Code impact: `parse_read_record_body` now rejects host/issuer-response-owned
  tags `89`, `8A`, `86`, `91`, and `9F18` from card-originated Template 70
  records. The new
  `record::tests::rejects_host_response_record_tags_atomically` proves the
  rejection is atomic and does not overwrite existing host-owned values.
- Evidence update: KRN-TLV-006 now describes and cites host-response-owned tag
  rejection; KRN-ONL-002 and KRN-GAC2-001/002 now cite the same regression to
  prove host-response CDOL2 data comes from the Level 3 path rather than AFL
  records.
- Verification: `cargo test
  record::tests::rejects_host_response_record_tags_atomically`, `cargo test
  rtm_promotes_online_boundary_evidence`, `cargo test
  rtm_promotes_tlv_catalogue_and_dol_classification_evidence`, `cargo test
  rtm_promotes_issuer_authentication_and_final_gac_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T18:51:53Z

- Increment completed: make the AFL record-admission boundary executable for
  every terminal-owned or kernel-owned tag currently denied from card-originated
  Template 70 records.
- Research note: the open-source reference review called out card-originated
  TLV admission as a useful clean-room hardening target. Hyperion already
  rejected terminal/kernel-owned record tags, but evidence directly covered
  only selected examples rather than the complete denylist.
- Code impact: added
  `record::tests::rejects_all_terminal_or_kernel_record_tags_atomically`, which
  iterates the full denylist, verifies the record is rejected, proves prior
  card data is not partially stored, and proves existing terminal/kernel data is
  not overwritten.
- Evidence update: KRN-TLV-006 in both RTM annexes now cites the denylist-wide
  record-admission regression, and the RTM promotion guard requires it.
- Verification: `cargo test
  record::tests::rejects_all_terminal_or_kernel_record_tags_atomically`, `cargo
  test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`, `cargo
  test`, `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T18:45:29Z

- Increment completed: refresh the public contactless standards-watch boundary
  for May 2026 EMVCo bulletin drift and make the repository guard require the
  updated open-evidence framing.
- Research note: EMVCo public listings now show May 21, 2026 contactless-suite
  signals for SB 326, SB 327, and DSB 331. These are tracked as licensed/lab
  reconciliation inputs only; they do not become Hyperion implementation
  authority unless the accepted profile and lab package select that behavior.
- Documentation impact: `standards_watch.md`, `lab_submission_manifest.md`, and
  `certification_open_issues.md` now keep C-8 v1.0 as the engineering target
  while requiring the lab package to accept, exclude, or defer the public Book
  A/Book B and Kernel 2 RRP bulletin signals.
- Evidence update: `certification_open_issues_register_tracks_external_blockers`
  now requires the manifest, open-issues register, and standards watch to
  mention SB 326, SB 327, and DSB 331 without closing the C-8 external blocker.
- Verification: `cargo test
  certification_open_issues_register_tracks_external_blockers`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T18:34:19Z

- Increment completed: prove that TAA default action-code masks are ignored
  while the terminal is online-capable and only participate in the unable-online
  fallback path.
- Research note: the TAA engine already evaluated denial, online, and default
  masks in the intended order; the local evidence gap was that the online
  capable path had no direct regression proving a matching default mask cannot
  override the configured online no-match policy.
- Code impact: added
  `taa::tests::default_action_codes_are_ignored_while_online_capable`, which
  exercises the same default-mask TVR bit in both online-capable and
  offline-unable contexts and asserts the distinct decision reasons.
- Evidence update: KRN-TAA-006 and KRN-TAA-007 in both RTM annexes now cite the
  new regression, and the RTM promotion guard requires it for both TAA ordering
  and deterministic fallback evidence.
- Verification: `cargo test
  taa::tests::default_action_codes_are_ignored_while_online_capable`, `cargo
  test rtm_promotes_terminal_action_analysis_evidence`, `cargo test`, `cargo
  test --examples`, `cargo clippy --all-targets --all-features`, `cargo fmt
  --check`, and `git diff --check` passed.

## 2026-05-22T18:27:56Z

- Increment completed: make KRN-TRM-001's "per profile and transaction type"
  floor-limit claim executable instead of relying on a single AID floor limit.
- Research note: public TRM references describe amount-to-floor-limit
  comparison as a terminal risk management input; the local gap was that the
  RTM claimed transaction-type sensitivity while `TrmInput` had no transaction
  type and profile loading had no typed floor-limit override surface.
- Code impact: `TrmProfile` now accepts bounded transaction-type floor-limit
  overrides keyed by tag `9C` transaction type, `TrmInput` carries the
  transaction type from runtime parameters, and floor-limit evaluation falls
  back to the AID floor limit when no override is present.
- Evidence update: KRN-TRM-001 in both RTM annexes now cites
  `trm::tests::floor_limit_uses_transaction_type_profile_override` plus config
  loader acceptance/rejection coverage for transaction-type override profiles.
- Verification: `cargo test
  trm::tests::floor_limit_uses_transaction_type_profile_override`, `cargo test
  trm::tests`, `cargo test config::tests::loads_profile_annex_when_signature_is_verified`,
  `cargo test config::tests::rejects_cfg_002_profile_schema_and_field_failures`,
  `cargo test rtm_promotes_trm_floor_random_and_tsi_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T18:17:02Z

- Increment completed: expose runtime input for certified-profile TRM random
  selection and prove it drives the online handoff through the C ABI path.
- Research note: `src/trm.rs` already supported deterministic random-selection
  samples, but the runtime path always passed `None`, so a profile percentage
  could not trigger the random-selection TVR bit during an integrated
  transaction.
- Code impact: added `krn_set_trm_random_selection_sample`, stored the
  transaction-scoped basis-point sample in `KrnContext`, cleared it on new
  transaction parameters, and passed it into `evaluate_trm`.
- Evidence update: KRN-TRM-002 in both RTM annexes now cites the ABI setter and
  `ffi::tests::trm_random_selection_sample_drives_online_handoff`, which
  verifies sample validation, TVR random-selection bit setting, S8 to S9 TRM
  transition, and TAA ARQC handoff through IAC online matching.
- Verification: `cargo test
  ffi::tests::trm_random_selection_sample_drives_online_handoff`, `cargo test
  trm::tests::random_selection_is_deterministic_from_external_sample`, `cargo
  test rtm_promotes_trm_floor_random_and_tsi_evidence`, `cargo test`, `cargo
  test --examples`, `cargo clippy --all-targets --all-features`, `cargo fmt
  --check`, and `git diff --check` passed.

## 2026-05-22T18:08:18Z

- Increment completed: promote TVR byte 5 bit 8 from an RFU placeholder to the
  symbolic `B5_DEFAULT_TDOL_USED` bit in code and the executable bitmap
  catalogue.
- Research note: the TDOL evidence pass exposed a stale local mask: byte 5 bit
  8 represents "Default TDOL used", so treating it as RFU made the bitmap
  catalogue and runtime TVR mask stricter than the claimed EMV bit model.
- Code impact: `Tvr::ALLOWED_MASKS` now permits byte 5 bit 8, `Tvr` exposes a
  named `B5_DEFAULT_TDOL_USED` constant, and RFU regression tests still reject
  the true reserved low nibble and out-of-range byte indexes.
- Evidence update: `bitmap_catalogue_defines_tvr_tsi_symbols_and_rfu_masks`
  now requires the `B5_DEFAULT_TDOL_USED` catalogue symbol and cross-checks the
  bitmap catalogue against the runtime TVR masks.
- Verification: `cargo test state::tests::tvr_and_tsi_mutation_masks_rfu_bits`,
  `cargo test bitmap_catalogue_defines_tvr_tsi_symbols_and_rfu_masks`, `cargo
  test krn_tvr_003_tsi_001_state_bits_are_defined_and_rfu_safe`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T18:01:16Z

- Increment completed: add tag `97` Transaction Certificate Data Object List
  (TDOL) to the executable TLV catalogue and DOL evidence set.
- Research note: public tag lookup confirms TDOL is tag `97`; the local gap was
  that KRN-DOL-001 claimed TDOL construction while the catalogue and tests only
  exercised PDOL, CDOL1, CDOL2, and DDOL explicitly. This adapts the
  reference-review pattern of fixture-heavy DOL validation without copying
  external implementation code.
- Code impact: added
  `dol::tests::parses_and_builds_tdol_deterministically`, which proves the
  existing DOL builder constructs TDOL bytes deterministically from amount, TVR,
  and TSI inputs under the exact-value policy.
- Evidence update: the TLV catalogue now carries 63 rows; both RTM annexes cite
  the TDOL regression under KRN-DOL-001; and the traceability guard requires the
  TDOL catalogue row, test evidence, and DOL-family catalogue coverage.
- Verification: `cargo test
  dol::tests::parses_and_builds_tdol_deterministically`, `cargo test
  tlv_catalogue_contains_required_foundation_tags`, `cargo test
  tlv_catalogue_uses_required_schema_and_profile_defined_markers`, `cargo test
  rtm_promotes_dol_construction_policy_evidence`, `cargo test
  lab_manifest_leaves_unattached_external_reports_unchecked`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T17:52:09Z

- Increment completed: align EXTERNAL AUTHENTICATE APDU construction with the
  issuer-authentication data length domain already enforced at the host-response
  parser boundary.
- Research note: local evidence review found a bypass in direct internal tests:
  tag `91` host responses were constrained to 8-16 bytes, but the lower APDU
  builder and direct issuer-authentication fixtures still accepted four-byte
  payloads.
- Code impact: `external_authenticate` now rejects issuer-authentication data
  outside 8-16 bytes before APDU encoding; FFI issuer-authentication
  regressions now use eight-byte payloads and assert the longer command length.
- Evidence update: existing KRN-IAUTH-001 evidence
  `apdu::tests::builds_external_authenticate_for_issuer_authentication_data`
  now covers too-short and too-long issuer-authentication data rejection as well
  as valid APDU construction.
- Verification: `cargo test
  apdu::tests::builds_external_authenticate_for_issuer_authentication_data`,
  `cargo test apdu::tests::encodes_kernel_command_apdu_matrix`, `cargo test
  ffi::tests::issuer_authentication_failure_sets_tvr_and_reaches_scripts`,
  `cargo test ffi::tests::issuer_authentication_resolves_get_response_followup`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T17:45:56Z

- Increment completed: prove that an applied host-response Authorization Code
  can feed second GENERATE AC CDOL2 construction when CDOL2 requests tag `89`.
- Research note: this follows the reference-review pattern of fixture-heavy
  end-to-end boundary tests while keeping the behavior expressed in Hyperion's
  own FFI/state-machine flow.
- Code impact: added
  `ffi::tests::final_generate_ac_uses_authorization_code_from_applied_host_response`,
  which applies a host response through the S11 boundary, advances through the
  no-script path, and verifies the generated CDOL2 bytes include ARC, tag `89`,
  TVR, and TSI in the requested order.
- Evidence update: both RTM annexes cite the new regression under KRN-GAC2-001
  and KRN-GAC2-002, and the RTM guard now requires that evidence.
- Verification: `cargo test
  final_generate_ac_uses_authorization_code_from_applied_host_response`, `cargo
  test rtm_promotes_issuer_authentication_and_final_gac_evidence`, `cargo
  test`, `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T17:37:52Z

- Increment completed: make tag `89` Authorization Code an explicit
  host-response object instead of silently ignoring issuer-supplied approval
  code data.
- Research note: public standards drift was rechecked against the current
  `standards_watch.md` boundary; the open-source reference review still points
  to explicit host-response contracts and fixture-backed parser validation, so
  this slice adapts that shape without copying external implementation code.
- Code impact: `parse_host_response` now validates six-byte alphanumeric
  Authorization Code values, rejects duplicate or unsupported top-level
  host-response objects, and `krn_apply_host_response` admits validated `89`
  into the shared data store for downstream CDOL2 construction.
- Evidence update: the executable TLV catalogue now includes tag `89`; both RTM
  annexes cite malformed authorization-code and unsupported-host-object
  regressions under KRN-ONL-002; the lab manifest TLV count is derived at 62
  tags.
- Verification: `cargo test issuer::tests`, `cargo test
  ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac`,
  `cargo test tlv_catalogue_contains_required_foundation_tags`, `cargo test
  rtm_promotes_online_boundary_evidence`, `cargo test
  tlv_catalogue_uses_required_schema_and_profile_defined_markers`, `cargo test
  lab_manifest_leaves_unattached_external_reports_unchecked`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T17:29:43Z

- Increment completed: bound and validate the shared EMV data store before
  values can feed DOL construction, ODA, GAC parsing, or online authorization
  packaging.
- Research note: the open-source reference review favors strict source
  admission and bounded fixture-heavy validation; this slice adapts that
  approach locally by enforcing BER tag shape and resource limits at the shared
  store boundary rather than only at individual parsers.
- Code impact: `DataStore::put` now rejects invalid EMV tag encodings, values
  above 4096 bytes, and more than 512 stored tag/value objects while preserving
  existing overwrite semantics for valid tags.
- Evidence update: `dol::tests::datastore_rejects_invalid_tags_and_resource_limits`
  covers invalid tags, oversized values, and entry-count overflow; both RTM
  annexes cite that evidence under KRN-DOL-001.
- Verification: `cargo test dol::tests`, `cargo test
  rtm_promotes_dol_construction_policy_evidence`, `cargo test`, `cargo test
  --examples`, `cargo clippy --all-targets --all-features`, `cargo fmt
  --check`, and `git diff --check` passed.

## 2026-05-22T17:19:31Z

- Increment completed: suppress profile-defined issuer application data (`9F10`)
  in production trace output while keeping verified non-production support logs
  available for authorized troubleshooting.
- Research note: the executable TLV catalogue classifies `9F10` as
  profile-defined, and the open-source reference review reinforces fixture-led
  masked trace validation rather than raw APDU logging as certification-facing
  evidence.
- Code impact: `mask_tlv_value` now treats `9F10` separately from ordinary TLV
  values, and the deterministic pre-lab GENERATE AC trace fixture uses a
  template-77 response carrying `9F10` to prove the production masking rule.
- Evidence update: KRN-LOG-001 in both RTM annexes cites
  `trace::tests::production_suppresses_profile_defined_issuer_application_data`,
  and the lab manifest now states that the pre-lab trace fixture covers
  profile-defined issuer application data suppression.
- Verification: `cargo test
  production_suppresses_profile_defined_issuer_application_data`, `cargo test
  krn_log_001_masks_sensitive_tlv_and_gac_trace_values`, `cargo test
  krn_log_001_exposes_masked_apdu_trace_json_via_abi`, `cargo test
  prelab_apdu_trace_pack_is_replayable_masked_and_scoped`, `cargo test
  rtm_promotes_reference_config_log_evidence`, `cargo test`, `cargo test
  --examples`, `cargo clippy --all-targets --all-features`, `cargo fmt
  --check`, `cargo run --quiet --example krn_prelab_trace_pack | diff -u
  docs/prelab_apdu_trace_pack.jsonl -`, and `git diff --check` passed.

## 2026-05-22T17:03:44Z

- Increment completed: make certification-scope metadata executable in the
  signed profile loader instead of accepting any object with allowed field
  names.
- Research note: the current certification boundary still depends on
  lab-signed profiles, CAPKs, C-8 package material, and explicit fixture
  disclaimers; this slice tightens the local profile schema so repository
  fixtures cannot silently claim unsupported scope or material status.
- Code impact: `load_profile_set` now requires certification profiles to carry
  a typed `certification_scope` with non-overlapping bundled/lab-required
  scheme lists, explicit C-8 profile scope, approved material-status markers,
  and `production_profile_bundle_required = true`.
- Evidence update: `config::tests::rejects_invalid_certification_scope_boundaries`
  covers missing scope, overlapping scheme claims, false production-bundle
  requirements, and unsupported material-status claims; both RTM annexes cite
  that evidence under KRN-CFG-002.
- Verification: `cargo test config::tests`, `cargo test
  supported_contactless_profiles_use_c8_certification_scope`, `cargo test
  rtm_promotes_cfg_schema_and_terminal_param_evidence`, `cargo test`, `cargo
  test --examples`, `cargo clippy --all-targets --all-features`, `cargo fmt
  --check`, and `git diff --check` passed.

## 2026-05-22T16:52:03Z

- Increment completed: expand the repository-controlled masked pre-lab trace
  pack with an issuer-script retry/status scenario while preserving the
  `CERT-OPEN-012` boundary for full lab traces.
- Research note: the open-source reference review favors fixture-driven APDU
  replay evidence and visible follow-up status handling; Hyperion adapts that
  testing shape without copying source or treating public examples as
  certification evidence.
- Code impact: `examples/krn_prelab_trace_pack.rs` now emits a fifth masked
  scenario covering issuer-script `6Cxx` retry handling followed by a warning
  script status, and `docs/prelab_apdu_trace_pack.jsonl` is regenerated from
  that executable fixture.
- Evidence update: `prelab_apdu_trace_pack_is_replayable_masked_and_scoped`
  now checks the fifth scenario, five metadata/identity/scenario records, and
  the issuer-script retry status words while keeping raw script APDU data
  suppressed.
- Verification: `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`,
  `cargo test rtm_promotes_fsm_annex_replay_and_error_transition_evidence`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T16:48:37Z

- Increment completed: lock the lab manifest TLV catalogue count to the
  executable catalogue so repository-controlled evidence does not silently drift
  after catalogue hardening.
- Research note: local evidence review found the manifest still claimed 58 TLV
  rows after the executable catalogue reached 61 data rows.
- Code impact: `docs/lab_submission_manifest.md` now reports the same 61-tag
  TLV count as the executable catalogue.
- Evidence update: `lab_manifest_leaves_unattached_external_reports_unchecked`
  now derives the expected TLV count from `docs/tlv_catalogue.csv` and checks
  the manifest text against it.
- Verification: `cargo test lab_manifest_leaves_unattached_external_reports_unchecked`,
  `cargo test tlv_catalogue_uses_required_schema_and_profile_defined_markers`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T16:43:45Z

- Increment completed: extend the executable TLV catalogue coverage for
  issuer-script command and result objects without inventing a scheme-specific
  `9F5B` value layout.
- Research note: local reference review identifies tag `86` as Issuer Script
  Command and tag `9F5B` as Issuer Script Results in contact contexts, while
  contactless references also use `9F5B` as DSDOL; Hyperion records that
  ambiguity as profile-defined catalogue metadata instead of hard-coding one
  universal meaning.
- Code impact: `docs/tlv_catalogue.csv` now covers tag `86` as issuer-script
  command data and tag `9F5B` as profile-defined issuer-script-result/contactless
  DSDOL metadata, preserving the current ABI SW1/SW2 reporting model.
- Evidence update: `tlv_catalogue_contains_required_foundation_tags` now guards
  `86`, `9F18`, and `9F5B`, and both RTM annexes cite that evidence under
  KRN-SCR-006.
- Verification: `cargo test tlv_catalogue_contains_required_foundation_tags`,
  `cargo test tlv_catalogue_uses_required_schema_and_profile_defined_markers`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo test
  rtm_promotes_tlv_catalogue_and_dol_classification_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T16:34:54Z

- Increment completed: correct the executable state-machine annex so the S11
  host response path without tag `91` no longer claims that the second
  GENERATE AC is skipped.
- Research note: dcemv's contact-kernel flow stores host ARC (`8A`) and script
  templates, skips issuer authentication when no issuer authentication data is
  available, and still proceeds through before-final scripts before card action
  analysis; Hyperion adapts the state-machine wording to match its own runtime
  transition model.
- Code impact: `docs/state_machine.csv` now labels the S11 no-`91` path as
  skipping issuer authentication, and `fsm::parse_event`/`parse_action` accept
  the corrected event/action wording.
- Evidence update: both RTM annexes cite
  `fsm::tests::host_response_without_issuer_authentication_does_not_claim_gac2_skip`
  for KRN-ANNEX-002 and KRN-FSM-001.
- Verification: `cargo test
  host_response_without_issuer_authentication_does_not_claim_gac2_skip`, `cargo
  test validates_machine_readable_state_annex`, `cargo test
  rtm_promotes_state_machine_annex_validation_evidence`, `cargo test
  rtm_promotes_fsm_annex_replay_and_error_transition_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T16:31:20Z

- Increment completed: collapse the parsed host-response ARC from an optional
  field into a mandatory fixed two-byte value after the parser-level `8A`
  requirement.
- Research note: the public reference metadata reviewed for the prior slice and
  Hyperion's Level 3 ABI contract both treat `8A` as mandatory host-response
  data; this slice adapts that into the in-memory model rather than preserving
  an impossible `None` state.
- Code impact: `HostResponse.authorization_response_code` is now `[u8; 2]`;
  parser diagnostics still validate malformed issuer scripts before reporting a
  missing ARC, preserving existing fail-closed evidence.
- Evidence update: existing parser and final-GAC tests now exercise the
  non-optional ARC model directly without `Option` unwrap paths.
- Verification: `cargo test rejects_host_response_without_authorization_response_code`,
  `cargo test parses_arpc_arc_and_issuer_scripts`, `cargo test
  final_generate_ac_builds_cdol2_from_host_response_and_state`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T16:23:09Z

- Increment completed: require Level 3 online host responses to carry
  Authorization Response Code (`8A`) before issuer-authentication or script data
  can be accepted.
- Research note: public reference metadata identifies `8A` as a fixed two-byte
  authorisation/authorization response code, and the existing Hyperion ABI
  contract already states host responses contain at least `8A`; this slice
  aligns the parser with that fail-closed boundary.
- Code impact: `parse_host_response` now rejects host responses missing `8A`
  with `MissingMandatoryTag` after validating any malformed script data, while
  preserving strict ARC character validation and existing issuer-auth/script
  parsing bounds.
- Evidence update: both RTM annexes cite
  `issuer::tests::rejects_host_response_without_authorization_response_code`
  under KRN-ONL-002 and KRN-IAUTH-001.
- Verification: `cargo test
  rejects_host_response_without_authorization_response_code`, `cargo test
  rtm_promotes_online_boundary_evidence`, `cargo test
  rtm_promotes_issuer_authentication_and_final_gac_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, `cargo
  fmt --check`, and `git diff --check` passed.

## 2026-05-22T16:16:40Z

- Increment completed: bound GENERATE AC Issuer Application Data (`9F10`)
  parsing to the EMV response-template shape.
- Research note: public reference review found `emv-utils` validating
  GENERATE AC format-1 length as `1 + 2 + 8 + 32`, `dcemv` rejecting format-1
  responses above 43 bytes, and MohamedHassanNasr/emv metadata declaring
  `9F10` as 0..32 bytes; Hyperion is adapting the validation rule, not copying
  implementation code.
- Code impact: `parse_generate_ac_response` now accepts `9F10` only up to 32
  bytes in both response template `80` and template `77`, preserving the
  minimum 11-byte format-1 body while rejecting overlong issuer data.
- Evidence update: both RTM annexes cite
  `gac::tests::rejects_generate_ac_issuer_application_data_above_emv_bound`
  under KRN-GAC-004 and KRN-GAC1-004.
- Verification: `cargo test
  rejects_generate_ac_issuer_application_data_above_emv_bound`, `cargo test
  rtm_promotes_gac_cdol_encoding_and_response_evidence`, `cargo test`, `cargo
  test --examples`, `cargo clippy --all-targets --all-features`, `cargo fmt
  --check`, and `git diff --check` passed.

## 2026-05-22T16:07:58Z

- Increment completed: align Application Usage Control (`9F07`) service checks
  with terminal-channel and region-specific cashback bits.
- Code impact: `ApplicationUsageControl::allows` now checks the EMV AUC
  terminal-channel bits alongside service bits: non-ATM cash/goods/services and
  cashback require `valid other than ATM`, ATM transactions require `valid at
  ATM`, and cashback uses domestic/international byte-2 bits.
- Evidence update: both RTM annexes cite
  `restrictions::tests::auc_enforces_terminal_channel_and_region_specific_cashback_bits`
  under KRN-REST-002.
- Verification: `cargo test
  auc_enforces_terminal_channel_and_region_specific_cashback_bits`, `cargo test
  evaluates_version_dates_auc_and_new_card_bits`, `cargo test
  rtm_promotes_processing_restriction_evidence`, `cargo fmt --check`, `cargo
  test`, `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  and `git diff --check` passed.

## 2026-05-22T15:57:33Z

- Increment completed: reject impossible card-supplied BCD dates used by
  processing restrictions, and share the same YY/MM/DD validation with profile
  date parsing.
- Code impact: `EmvDate::new` now owns month/day validation for the kernel's
  two-digit date model; `EmvDate::from_bcd` and certification profile ISO date
  parsing both reject day zero, month zero, and impossible month/day pairs.
- Evidence update: both RTM annexes cite
  `restrictions::tests::parses_valid_bcd_dates_and_rejects_invalid_values`
  under KRN-REST-001.
- Verification: `cargo test
  parses_valid_bcd_dates_and_rejects_invalid_values`, `cargo test
  rejects_invalid_capk_expiry_calendar_dates`, `cargo test
  rtm_promotes_processing_restriction_evidence`, `cargo fmt --check`, `cargo
  test`, `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  and `git diff --check` passed.

## 2026-05-22T15:53:15Z

- Increment completed: validate host authorization response code (`8A`)
  character class before storing Level 3 online response data.
- Code impact: host response parsing now requires `8A` to be exactly two ASCII
  alphanumeric-or-space bytes, matching the EMV alphanumeric ARC shape used by
  online response and CDOL2 handling.
- Evidence update: both RTM annexes cite
  `issuer::tests::rejects_non_alphanumeric_authorization_response_codes` under
  KRN-ONL-002.
- Verification: `cargo test
  rejects_non_alphanumeric_authorization_response_codes`, `cargo test
  rtm_promotes_online_boundary_evidence`, `cargo fmt --check`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, and
  `git diff --check` passed.

## 2026-05-22T15:47:42Z

- Increment completed: reject impossible CAPK expiry calendar dates in signed
  scheme profiles instead of accepting every `YYYY-MM-DD` shape with day
  `01` through `31`.
- Code impact: profile date parsing now enforces month-specific day maxima,
  rejects day zero, rejects month zero, and preserves permissive `02-29`
  handling for the existing two-digit `EmvDate` year model.
- Evidence update: both RTM annexes cite
  `config::tests::rejects_invalid_capk_expiry_calendar_dates` under
  KRN-CFG-002.
- Verification: `cargo test rejects_invalid_capk_expiry_calendar_dates`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`, `cargo
  fmt --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T15:41:28Z

- Increment completed: reject malformed profile-defined relay-resistance
  command APDUs before contactless C-8 runtime handling.
- Code impact: `RelayResistanceProfile::new` now validates the short-APDU
  command layout, including Lc/data/optional-Le consistency, in addition to
  the existing command length, response length, and timing bounds.
- Evidence update: both RTM annexes cite
  `c8::tests::rejects_malformed_relay_resistance_command_apdus` under
  KRN-CLESS-005.
- Verification: `cargo test rejects_malformed_relay_resistance_command_apdus`,
  `cargo test krn_cless_005_relay_resistance_is_profile_required_and_traced`,
  `cargo fmt --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T15:35:44Z

- Increment completed: reject empty `9F4C` ICC Dynamic Number objects in DDA
  INTERNAL AUTHENTICATE responses.
- Code impact: DDA response parsing now treats a present-but-empty ICC Dynamic
  Number as malformed, matching the fail-closed dynamic-number policy already
  used for GENERATE AC response parsing.
- Evidence update: both RTM annexes cite
  `oda::tests::rejects_empty_internal_authenticate_icc_dynamic_number` under
  KRN-DDA-002.
- Verification: `cargo test
  rejects_empty_internal_authenticate_icc_dynamic_number`, `cargo test
  rtm_promotes_dda_internal_authenticate_evidence`, `cargo test
  krn_dda_002_oda_006_requires_signed_dynamic_application_data`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T15:28:44Z

- Increment completed: reject non-minimal BER-TLV long-form length encodings
  while preserving valid definite long-form lengths at the 128-byte boundary.
- Code impact: TLV length parsing now fails closed on long-form encodings that
  should have used short form or fewer length octets, reducing malformed card
  response variants before module-specific parsers consume TLV data.
- Evidence update: both RTM annexes cite
  `tlv::tests::rejects_non_minimal_long_form_lengths` under KRN-TLV-003.
- Verification: `cargo test rejects_non_minimal_long_form_lengths`, `cargo test
  rtm_promotes_tlv_catalogue_and_dol_classification_evidence`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T15:22:42Z

- Increment completed: reject signed profile contactless limit configurations
  where the CVM limit exceeds the active contactless transaction limit.
- Code impact: AID profile parsing now validates the relationship between
  `contactless_transaction_limit` and `contactless_cvm_limit` before storing
  profile values used by the contactless C-8 limit decision path.
- Evidence update: both RTM annexes cite
  `config::tests::rejects_inconsistent_contactless_limit_ordering` under
  KRN-CFG-002 and KRN-CLESS-003.
- Verification: `cargo test rejects_inconsistent_contactless_limit_ordering`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`, `cargo test
  rtm_promotes_contactless_entry_outcome_limit_and_cdcvm_evidence`, `cargo
  fmt --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T15:16:34Z

- Increment completed: reject duplicate issuer-script critical INS policy bytes
  in signed scheme profiles.
- Code impact: `critical_issuer_script_ins` parsing now keeps the one-byte
  shape check and also fails closed when the same INS appears more than once,
  preserving deterministic script criticality policy before runtime issuer
  script execution.
- Evidence update: both RTM annexes cite the duplicate critical-script-policy
  regression under KRN-CFG-002.
- Verification: `cargo test
  rejects_invalid_or_duplicate_critical_script_ins_policy`, `cargo test
  rtm_promotes_cfg_schema_and_terminal_param_evidence`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T15:08:25Z

- Increment completed: make runtime GENERATE AC CDOL1/CDOL2 construction fail
  closed on missing DOL sources instead of silently zero-padding active CDOL
  inputs.
- Code impact: first and final GENERATE AC now use the exact-value DOL policy;
  missing CDOL1 or CDOL2 source data returns `MissingMandatoryTag` before APDU
  transmission.
- Evidence update: both RTM annexes cite first-GAC and final-GAC missing-source
  regressions under KRN-GAC-001, KRN-GAC1-002, KRN-GAC2-001, and KRN-GAC2-002;
  the open-source review records the clean-room DOL validation concept.
- Verification: `cargo test
  first_gac_rejects_missing_cdol1_source_without_zero_padding`, `cargo test
  final_gac_rejects_missing_cdol2_source_without_zero_padding`, `cargo test
  rtm_promotes_gac_cdol_encoding_and_response_evidence`, `cargo test
  rtm_promotes_issuer_authentication_and_final_gac_evidence`, `cargo test`,
  `cargo fmt --check`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T14:58:32Z

- Increment completed: align the AFL parser bound with the full 252-byte AFL
  field domain while keeping READ RECORD execution bounded by the separate
  record-locator cap.
- Code impact: `MAX_AFL_ENTRIES` is now derived from the 252-byte AFL envelope
  as 63 four-byte entries; the record plan still rejects locator expansion
  beyond `MAX_RECORD_LOCATORS` and duplicate SFI/record locators.
- Evidence update: both RTM annexes cite the new maximum-entry acceptance
  regression under KRN-RR-001, and the open-source review records the
  clean-room validation concept adapted from reference utility review.
- Verification: `cargo test
  accepts_maximum_afl_entry_count_without_overflow`, `cargo test
  rejects_afl_lists_above_entry_limit`, and `cargo test
  rtm_promotes_gpo_and_read_record_evidence`, `cargo fmt --check`, `cargo
  test`, `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  and `git diff --check` passed.

## 2026-05-22T14:47:56Z

- Increment completed: reject conflicting cross-record card data rewrites
  before a later AFL record can replace an earlier accepted card-originated
  tag value.
- Code impact: READ RECORD admission now checks every direct primitive record
  tag against the existing transaction data store before mutation, still
  allowing identical repeated values while rejecting conflicting repeats
  without partial store updates.
- Evidence update: both RTM annexes cite the conflicting-rewrite regression
  and identical-repeat regression under KRN-RR-003 and KRN-TLV-006.
- Verification: `cargo test
  rejects_conflicting_record_data_rewrite_without_partial_store`, `cargo test
  accepts_repeated_record_data_when_value_is_identical`, `cargo test
  rtm_promotes_gpo_and_read_record_evidence`, `cargo test
  rtm_promotes_tlv_catalogue_and_dol_classification_evidence`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T14:40:39Z

- Increment completed: reject constructed direct children in GPO Template 77
  responses instead of accepting nested discretionary objects once mandatory
  AIP/AFL objects are present.
- Code impact: GPO response parsing now applies the same direct-child
  primitive-data admission stance used by other certification-critical response
  parsers.
- Evidence update: both RTM annexes cite the new constructed-child rejection
  regression under KRN-GPO-001 and KRN-GPO-002.
- Verification: `cargo test
  rejects_constructed_gpo_response_children_even_with_mandatory_data`, `cargo
  test rtm_promotes_gpo_and_read_record_evidence`, `cargo test
  krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T14:32:58Z

- Increment completed: preserve the card directory ADF name for final SELECT
  when a signed profile AID matches by partial selection.
- Code impact: selection candidates now carry both the signed profile AID used
  for rule/profile lookup and the actual ADF name used for SELECT; runtime
  selection sends the card-provided ADF while retaining profile indices for
  scheme configuration.
- Evidence update: both RTM annexes now cite selection and runtime regressions
  proving partial-selection ADF preservation under KRN-SEL-001.
- Verification: `cargo test
  partial_selection_preserves_card_adf_name_for_final_select`, `cargo test
  runtime_partial_selection_uses_card_adf_name_for_select`, `cargo test
  rtm_promotes_runtime_apdu_selection_status_policy_evidence`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T14:20:33Z

- Increment completed: prevent cross-record rewrites of cardholder PAN and
  Track 2 data from silently replacing previously accepted values.
- Code impact: READ RECORD admission now rejects conflicting duplicate 5A or
  57 values before any data-store update, while still allowing later records to
  supply the missing counterpart when the values are consistent.
- Evidence update: both RTM annexes now cite the new cardholder-data rewrite
  regression under KRN-RR-004.
- Verification: `cargo test
  rejects_conflicting_cardholder_data_rewrite_without_partial_store`, `cargo
  test rtm_promotes_gpo_and_read_record_evidence`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T14:15:18Z

- Increment completed: extend the pre-lab decoder with operator-facing
  capability bitmap triage for Terminal Capabilities, TTQ, and CTQ.
- Code impact: `krn_emv_decode` now decodes `termcap`/`terminal-capabilities`
  with standard 9F33 capability names and RFU detection, while decoding TTQ and
  CTQ as profile-defined bitmaps without importing scheme-specific semantics.
- Evidence update: both RTM annexes now cite decoder regressions for 9F33 and
  9F66 trace triage alongside the existing ABI/DOL handoff evidence.
- Verification: `cargo test --example krn_emv_decode
  terminal_capabilities_output_names_standard_bits_and_flags_rfu`, `cargo test
  --example krn_emv_decode ttq_and_ctq_output_profile_defined_bitmaps`, `cargo
  test rtm_promotes_terminal_capability_and_ttq_evidence`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T14:08:29Z

- Increment completed: extend the pre-lab decoder's CVM-list output with
  method requirement flags for PIN and signature triage.
- Code impact: `krn_emv_decode cvm-list` now reports whether each rule requires
  offline PIN and signature while continuing to suppress PED handles and other
  sensitive values.
- Evidence update: both RTM annexes now cite the decoder regression for CVM
  list parsing/evaluation evidence, and the traceability guard requires the
  decoder citation.
- Verification: `cargo test --example krn_emv_decode
  cvm_list_output_names_rules_without_handles`, `cargo test
  rtm_promotes_cvm_outcome_evidence`, `cargo fmt --check`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, and
  `git diff --check` passed.

## 2026-05-22T14:04:45Z

- Increment completed: preserve PIN-and-signature CVM methods as composite
  internal actions instead of collapsing them to PIN-only actions.
- Code impact: `CvmAction` now distinguishes offline plaintext PIN plus
  signature and offline enciphered PIN plus signature, while keeping PED handles
  opaque and redacted in debug output. New CVM coverage proves both composite
  actions require the matching offline PIN handle and signature capability.
- Evidence update: both RTM annexes now cite the composite CVM regression for
  CVM list evaluation and PIN-method distinction, and the traceability guard
  requires those citations.
- Verification: `cargo test offline_pin_and_signature_selects_composite_actions`,
  `cargo test rtm_promotes_cvm_outcome_evidence`, `cargo test
  rtm_promotes_cvm_pin_capability_evidence`, `cargo fmt --check`, `cargo
  test`, `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  and `git diff --check` passed.

## 2026-05-22T13:58:14Z

- Increment completed: lock critical issuer-script failure handling so a failed
  critical command stops remaining commands in that script.
- Code impact: added an FFI regression that drives a post-final Template `72`
  script with two critical commands, forces the first command to fail, and
  verifies that only the failed command is transmitted and reported while the
  FSM enters error with the after-final script-failure TVR bit and script TSI
  persisted.
- Evidence update: both RTM annexes now cite the regression for issuer-script
  ordering, SW capture/reporting, and after-final-GAC failure evidence, and the
  traceability guard requires those citations.
- Verification: `cargo test critical_issuer_script_failure_stops_remaining_commands`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T13:53:45Z

- Increment completed: align the lab manifest with the expanded standards-watch
  scope and Rust submission context.
- Evidence update: `docs/lab_submission_manifest.md` now states that the public
  standards watch covers both C-8 drift and PCI PTS/PED evidence boundaries
  while preserving licensed/lab reconciliation for final claims; the pending
  static-analysis attachment no longer claims a C-specific MISRA report for the
  Rust kernel.
- Guardrail update: traceability assertions now require the PCI/PED standards
  watch scope, licensed/lab reconciliation wording, Rust/product static-analysis
  attachment wording, and absence of the misleading `MISRA C compliant` manifest
  claim.
- Verification: `cargo test lab_manifest`, `cargo fmt --check`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`, and
  `git diff --check` passed.

## 2026-05-22T13:49:56Z

- Increment completed: refresh public PCI PTS/PED standards-watch evidence for
  the secure PIN boundary.
- Research note: checked PCI SSC public PTS POI standards, document library,
  PTS POI v7.0 publication note, and approved PTS device listing pages. The
  repository keeps PCI PTS POI v7.0 as the public alignment target while
  preserving `CERT-OPEN-007` for the actual PED integration statement, approved
  device evidence, and device security review.
- Evidence update: `docs/standards_watch.md` now records the PCI PTS/PED public
  check and a `CERT-OPEN-007` gating rule; traceability assertions require the
  watch to preserve the approved-device, PCI-recognized laboratory, opaque PED
  handle, and no-clear-PIN boundary signals.
- Verification: `cargo test
  certification_open_issues_register_tracks_external_blockers`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T13:44:54Z

- Increment completed: extend DOL source-precedence coverage to generated
  unpredictable numbers used in first GENERATE AC.
- Code impact: added an FFI regression proving a card-originated record that
  attempts to write tag `9F37` is rejected without partial store mutation and
  that first GAC CDOL construction still carries the generated unpredictable
  number value.
- Evidence update: both RTM annexes now cite the generated-UN precedence
  regression for DOL construction, first-GAC CDOL data, and card-originated TLV
  admission; traceability guards assert those citations, and the open-source
  adaptation backlog now records generated `9F37` as maintained coverage.
- Verification: `cargo test
  first_gac_preserves_generated_unpredictable_number_after_rejected_record_tags`,
  `cargo test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`,
  `cargo test rtm_promotes_dol_construction_policy_evidence`, `cargo test
  rtm_promotes_gac_cdol_encoding_and_response_evidence`, `cargo test`, `cargo
  fmt --check`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T13:38:25Z

- Increment completed: expand the repository-controlled pre-lab APDU trace pack
  with Track 2 masking coverage for READ RECORD responses.
- Code impact: `examples/krn_prelab_trace_pack.rs` now emits a
  `prelab.masking.track2-record` case with deterministic scenario metadata,
  trace identity, a READ RECORD command, and a Template `70` response carrying
  tag `57`; production masking suppresses Track 2 data before JSONL emission.
- Evidence update: `docs/prelab_apdu_trace_pack.jsonl` regenerates exactly
  from the example, traceability assertions prove four scoped trace-pack cases
  and reject raw Track 2 substrings, the lab manifest now names Track 2
  suppression, and the open-source adaptation backlog records it as maintained
  trace-pack coverage without closing `CERT-OPEN-012`.
- Verification: `cargo run --quiet --example krn_prelab_trace_pack | diff -u
  docs/prelab_apdu_trace_pack.jsonl -`, `cargo test
  prelab_apdu_trace_pack_is_replayable_masked_and_scoped`, `cargo test
  lab_manifest_and_provenance_cover_reproducible_build_artifacts`, `cargo test`,
  `cargo fmt --check`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T13:32:09Z

- Increment completed: extend the pre-lab decoder utility with CID inspection
  for GENERATE AC response triage.
- Code impact: `examples/krn_emv_decode.rs` now accepts `cid <hex>`, routes
  through the kernel `Cid` decoder, reports the raw CID byte, cryptogram type
  derived by the `0xC0` mask, advice-required flag, and reason/advice code
  without adding scheme-private semantics.
- Evidence update: the lab submission manifest lists CID in the controlled
  decoder scope, both RTM annexes cite the decoder regression for `KRN-CID-001`
  and `KRN-CID-002`, and the open-source adaptation backlog records CID as one
  of the maintained operator-facing decodes.
- Verification: `cargo test --example krn_emv_decode`, `cargo run --quiet
  --example krn_emv_decode -- cid 8F`, `cargo test
  rtm_promotes_cid_decode_and_preservation_evidence`, `cargo test
  lab_manifest_and_provenance_cover_reproducible_build_artifacts`, `cargo fmt
  --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T13:27:03Z

- Increment completed: reject inconsistent or malformed cardholder PAN data
  before READ RECORD record data can enter the shared card data store.
- Code impact: Template `70` admission now parses tag `5A` PAN digits and tag
  `57` Track 2 equivalent data, rejects malformed BCD/separator/padding shapes,
  rejects mismatched PAN values across current-record or already-stored data,
  and preserves the existing no-partial-store behavior on failure.
- Evidence update: the corrected spec adds `KRN-RR-004`, both RTM annexes cite
  executable PAN/Track 2 admission tests, the traceability guard checks those
  citations, and the open-source adaptation backlog now treats PAN/track
  consistency as maintained clean-room coverage.
- Verification: `cargo test pan_and_track2`, `cargo test
  malformed_pan_or_track2`, `cargo test
  rtm_promotes_gpo_and_read_record_evidence`, `cargo test
  corrected_spec_requirement_ids_are_all_in_rtm_annexes`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T13:16:08Z

- Increment completed: add a deterministic C ABI APDU script adapter for
  pre-lab integration smoke tests without pulling PC/SC, mobile NFC, or device
  drivers into the kernel core.
- Code impact: `examples/krn_cabi_script_adapter.rs` drives `krn_init`,
  verified profile loading, transaction parameter setup, and
  `krn_run_transaction` through `KrnRuntime` APDU/RNG callbacks, records command
  order and callback timeouts, and fails closed when the kernel sends an
  unexpected APDU.
- Evidence update: the lab manifest, pre-lab quality gate provenance command,
  both RTM annexes, and traceability guards now include the adapter as a
  repository-controlled integration fixture while preserving the external full
  lab trace-pack blocker.
- Verification: `cargo test --example krn_cabi_script_adapter`, `cargo run
  --quiet --example krn_cabi_script_adapter`, `cargo run --quiet --example
  krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -`, `cargo
  test lab_manifest_and_provenance_cover_reproducible_build_artifacts`, and
  `cargo test rtm_promotes_api_error_boundary_evidence` passed, followed by
  `cargo fmt --check`, `cargo test`, `cargo test --examples`, `cargo clippy
  --all-targets --all-features`, and `git diff --check`.

## 2026-05-22T13:05:12Z

- Increment completed: add a card-originated record admission boundary and DOL
  source-precedence regression for terminal/kernel-owned transaction data.
- Code impact: AFL record parsing now rejects direct Template `70` children for
  terminal/kernel-owned tags such as amount, date, type, TVR, TSI, terminal
  country, CVM results, and unpredictable number before any partial data-store
  update occurs.
- Evidence update: the corrected spec adds `KRN-TLV-006`, both RTM annexes map
  the new policy to record-parser and first-GAC regressions, and the
  open-source adaptation backlog now treats TLV admission and DOL precedence as
  maintained coverage rather than unstarted work.
- Verification: `cargo test rejects_terminal_owned_record_data_without_partial_store`,
  `cargo test first_gac_preserves_terminal_dol_sources_after_rejected_record_tags`,
  `cargo test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`,
  `cargo test rtm_promotes_dol_construction_policy_evidence`, `cargo test
  rtm_promotes_gac_cdol_encoding_and_response_evidence`, `cargo test
  corrected_spec_requirement_ids_are_all_in_rtm_annexes`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`, `cargo clippy --all-targets
  --all-features`, and `git diff --check` passed.

## 2026-05-22T12:43:54Z

- Increment completed: add a human-readable scheme profile dictionary generated
  from `docs/scheme_profiles.cert.json` for profile review and lab handoff.
- Code impact: `examples/krn_scheme_profile_dictionary.rs` loads the signed
  profile bundle through the certification profile loader and renders AID,
  kernel/interface, terminal capability/TTQ boundary, limit, CVM, TAA/TAC/IAC,
  and CAPK provenance details without raw CAPK modulus or CDOL value disclosure.
- Evidence update: `docs/scheme_profile_dictionary.md`, conformance inputs,
  build provenance, quality gates, lab manifest, and traceability tests now
  cover the generated dictionary while preserving `CERT-OPEN-002` and
  `CERT-OPEN-003` for external profile/CAPK authority.
- Verification: `cargo run --quiet --example krn_scheme_profile_dictionary |
  diff -u docs/scheme_profile_dictionary.md -`, `cargo run --quiet --example
  krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json
  -`, `cargo run --quiet --example krn_prelab_quality_gates | diff -u
  docs/prelab_quality_gates.json -`, `cargo test --example
  krn_scheme_profile_dictionary`, `cargo test
  scheme_profile_dictionary_is_generated_masked_and_scoped`, `cargo test
  lab_manifest_and_provenance_cover_reproducible_build_artifacts`, `cargo test
  prelab_quality_gates_are_reproducible_and_do_not_close_external_reports`,
  `cargo fmt --check`, `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T12:33:24Z

- Increment completed: extend the pre-lab APDU trace fixture from masked replay
  records into a scenario pack with explicit expected FSM events/actions, APDU
  status actions, terminal outcomes, and masking assertions for each bundled
  case.
- Code impact: `examples/krn_prelab_trace_pack.rs` now emits a
  `trace-scenario` JSONL record next to each case metadata record before the
  masked trace identity and APDU records.
- Evidence update: `docs/prelab_apdu_trace_pack.jsonl`, the lab submission
  manifest, the open-source follow-up backlog, and the traceability guard now
  prove the scenario expectation records while preserving `CERT-OPEN-012` for
  the external lab/test-tool trace pack.
- Verification: `cargo run --quiet --example krn_prelab_trace_pack | diff -u
  docs/prelab_apdu_trace_pack.jsonl -`,
  `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`,
  `cargo fmt --check`, `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T12:21:30Z

- Increment completed: adapt the open-source reference review's tool-first
  validation idea without copying external code by adding a Hyperion-owned
  pre-lab decoder for local trace triage.
- Code impact: `examples/krn_emv_decode.rs` decodes TLV, DOL, CVM-list, TVR,
  TSI, SW1/SW2, and short APDU-envelope inputs using existing Hyperion parsers
  and symbolic constants where available. Payload bytes remain suppressed by
  default.
- Evidence update: added the decoder to reproducible build provenance, the lab
  submission manifest, and traceability assertions; the open-source review
  backlog now treats the decoder as an artifact to maintain and extend.
- Verification: `cargo test --example krn_emv_decode`, `cargo run --quiet
  --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json
  -`, `cargo test lab_manifest_and_provenance_cover_reproducible_build_artifacts`,
  `cargo test prelab_quality_gates_are_reproducible_and_do_not_close_external_reports`,
  `cargo fmt --check`, `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T12:14:48Z

- Increment completed: review adjacent open-source/source-available EMV projects
  for ideas Hyperion can adapt without copying code or importing uncertified
  behavior.
- Research note: public EMV projects are most useful as architecture, adapter,
  trace-fixture, decoder, and process references. They are not certification
  authorities, and their public CAPKs, test keys, mocks, and scheme behaviors
  must stay outside Hyperion's certification evidence chain.
- Documentation impact: `docs/open_source.md` now records inspected revisions,
  license posture, project-specific borrowable ideas, "do not borrow" risks,
  and a Hyperion backlog for CLI decoders, APDU scenario packs, adapter
  boundaries, profile dictionaries, TLV admission policy, and DOL source
  precedence tests.
- Verification: `cargo fmt --check`, `git diff --check`, `cargo test`,
  `cargo test --examples`, and `cargo clippy --all-targets --all-features`
  passed.

## 2026-05-22T08:07:11Z

- Increment completed: require issuer script identifier tag `9F18` to be exactly
  four bytes before accepting a host script template.
- Research note: issuer script identifiers cross from the host into Level 2
  script processing evidence. Accepting arbitrary non-empty identifier lengths
  weakens deterministic template validation and can hide malformed host-response
  fixtures until lab or acquirer review.
- Code impact: issuer script parsing now rejects short and overlong `9F18`
  values while preserving valid Template 71/72 command execution behavior.
- Evidence updated: the TLV catalogue now records `9F18` as a four-byte
  primitive, both RTM annexes cite the malformed identifier regression, and the
  issuer-script RTM guard asserts that evidence remains present.
- Verification: `cargo test rejects_malformed_issuer_script_identifier_lengths`,
  `cargo test parses_arpc_arc_and_issuer_scripts`, and
  `cargo test rtm_promotes_issuer_script_evidence` passed, followed by
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`.

## 2026-05-22T07:17:06Z

- Increment completed: add a public standards-watch annex and wire it into the
  lab manifest, open-issues register, ABI conformance statement, quality gates,
  and build-provenance command.
- Research note: the EMVCo public specifications surface now shows Book C-8
  Kernel Specification v1.1 and SB 325 updates to Book C-8 v1.0. The repository
  remains scoped to C-8 v1.0 until licensed review and lab target selection, so
  public drift is now tracked explicitly instead of silently broadening the
  contactless claim.
- Code impact: `baseline_conformance_statement` and
  `prelab_quality_gates_json` now include `docs/standards_watch.md`, and
  `CERT-OPEN-005` requires licensed v1.0/v1.1 and SB 325 reconciliation before
  any final C-8 certification claim.
- Evidence updated: `standards_watch.md`, `spec.md`, the lab manifest, the
  open-issues register, generated ABI JSON, generated quality gates, and
  traceability guards now preserve the current public-standard drift boundary.
- Verification: `cargo run --quiet --example krn_abi_conformance_statement |
  diff -u docs/abi_conformance_statement.json -`,
  `cargo run --quiet --example krn_prelab_quality_gates | diff -u
  docs/prelab_quality_gates.json -`, `cargo run --quiet --example
  krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md
  docs/lab_submission_manifest.md docs/requirements_traceability.csv
  docs/scheme_profiles.cert.json docs/oda_test_vectors.json
  docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv
  docs/performance_profile.csv docs/abi_conformance_statement.json
  docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json
  docs/certification_open_issues.md docs/standards_watch.md
  examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs
  examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs`,
  `cargo test certification_open_issues_register_tracks_external_blockers`,
  `cargo test lab_manifest_and_provenance_cover_reproducible_build_artifacts`,
  `cargo test krn_ref_001_conformance_statement_declares_normative_hierarchy`,
  and `cargo test prelab_quality_gates_are_reproducible_and_do_not_close_external_reports`
  passed, followed by `cargo test`, `cargo test --examples`,
  `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and
  `git diff --check`.

## 2026-05-22T07:10:05Z

- Increment completed: make the pre-lab GENERATE AC replay fixture use a
  data-bearing short-form command APDU instead of a header-plus-Le-only command.
- Research note: GENERATE AC evidence is more useful when the request side
  exercises CDOL-style command data while still proving that production trace
  policy suppresses command payload bytes and card-returned transaction
  cryptograms.
- Code impact: `krn_prelab_trace_pack` now emits first GAC as
  `80 AE 80 00 03 ... 00`; the replay fixture remains deterministic and the
  checked-in JSONL does not expose the synthetic CDOL bytes or application
  cryptogram.
- Evidence updated: the trace-pack generator and traceability guard now prove
  both request data suppression and response cryptogram suppression; the
  checked-in JSONL remains byte-stable because the synthetic CDOL bytes are
  suppressed by policy.
- Verification: `cargo run --quiet --example krn_prelab_trace_pack | diff -u
  docs/prelab_apdu_trace_pack.jsonl -`,
  `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`, and
  `cargo test replay_rejects_structurally_invalid_command_apdus` passed,
  followed by `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`.

## 2026-05-22T07:06:30Z

- Increment completed: reject structurally invalid APDU replay commands before
  they can be traced or executed by deterministic replay evidence.
- Research note: pre-lab replay scripts are certification evidence inputs, so
  accepting fewer than four command-header bytes, truncated Lc payloads, or
  unsupported extended/extra command bytes would weaken APDU injection
  hardening even when raw APDU logging remains masked.
- Code impact: `ReplayExchange::new` and direct APDU command masking now share
  short-form command structure validation before extracting command fields or
  accepting replay steps.
- Evidence updated: the penetration/APDU-injection RTM row now cites
  `trace::tests::replay_rejects_structurally_invalid_command_apdus` while
  preserving the external third-party assessment requirement.
- Verification: `cargo test replay_rejects_structurally_invalid_command_apdus`,
  `cargo test replay_rejects_pin_verify_payload_custody`,
  `cargo test rtm_promotes_certification_evidence_boundaries`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T07:01:07Z

- Increment completed: tighten the ABI conformance statement scope so the
  generated JSON names the lab manifest, open-issues register, pre-lab trace
  fixture, quality gates, bitmap catalogue, and performance profile alongside
  the core specification annexes.
- Research note: a repository-generated conformance statement is useful only
  when it states its evidence boundary. The signed EMVCo/lab conformance
  template remains an external certification artifact and must stay open as
  `CERT-OPEN-011`.
- Code impact: `baseline_conformance_statement` now includes the complete
  repository-controlled evidence boundary and an explicit certification
  condition that the ABI JSON does not close the signed-template requirement.
- Evidence updated: `abi_conformance_statement.json` was regenerated, and
  traceability guards now require the expanded evidence scope and open-issues
  condition.
- Verification: `cargo run --quiet --example krn_abi_conformance_statement |
  diff -u docs/abi_conformance_statement.json -`,
  `cargo test krn_ref_001_conformance_statement_declares_normative_hierarchy`,
  and `cargo test conformance_statement_json_is_deterministic_and_scoped`
  passed, followed by `cargo test`, `cargo test --examples`,
  `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and
  `git diff --check`.

## 2026-05-22T06:57:08Z

- Increment completed: extend the repository-generated pre-lab APDU trace
  fixture to cover first GENERATE AC response masking, not only selection and
  record/PAN masking.
- Research note: lab trace evidence must demonstrate that transaction
  cryptograms are handled as sensitive values. A pre-lab fixture can prove the
  repository masking policy and replay identity, but it still does not close the
  full lab/test-tool trace pack requirement.
- Code impact: `krn_prelab_trace_pack` now emits a deterministic GENERATE AC
  response exchange in `generate-ac-response` context, and the traceability
  guard asserts that tag `9F26` is present only as a suppressed
  transaction-cryptogram value.
- Evidence updated: `prelab_apdu_trace_pack.jsonl` and the lab manifest now
  describe trace identity, PAN masking, and GENERATE AC cryptogram suppression
  while preserving `CERT-OPEN-012`.
- Verification: `cargo run --quiet --example krn_prelab_trace_pack | diff -u
  docs/prelab_apdu_trace_pack.jsonl -`,
  `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:50:10Z

- Increment completed: expand the pre-lab quality gate manifest to explicitly
  cover every repository-generated submission artifact, not just broad example
  compilation.
- Action log: persisted the active certification objective and operating
  commitments in `goal.txt` per the 2026-05-22 user directive, while continuing
  the verified incremental commit workflow.
- Research note: generated evidence artifacts are only useful for a lab package
  if their exact checked-in bytes can be regenerated and compared by a stable
  command. The quality gate manifest still remains repository-controlled
  engineering evidence and does not close external coverage, static-analysis,
  fuzzing, or lab-report attachments.
- Code impact: `prelab_quality_gates_json` now includes deterministic gates for
  ABI conformance JSON regeneration, masked APDU trace regeneration, quality
  manifest self-regeneration, and canonical build-provenance emission across
  source, controlled annexes, and evidence generators.
- Evidence updated: `prelab_quality_gates.json`, the lab manifest, and
  traceability guards now require the explicit generated-artifact gates while
  preserving `CERT-OPEN-009` and `CERT-OPEN-010`.
- Verification: `cargo run --quiet --example krn_abi_conformance_statement |
  diff -u docs/abi_conformance_statement.json -`, `cargo run --quiet
  --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl
  -`, `cargo run --quiet --example krn_prelab_quality_gates | diff -u
  docs/prelab_quality_gates.json -`, `cargo run --quiet --example
  krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md
  docs/lab_submission_manifest.md docs/requirements_traceability.csv
  docs/scheme_profiles.cert.json docs/oda_test_vectors.json
  docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv
  docs/performance_profile.csv docs/abi_conformance_statement.json
  docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json
  docs/certification_open_issues.md examples/krn_build_manifest.rs
  examples/krn_abi_conformance_statement.rs
  examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs`,
  `cargo test prelab_quality_gates_are_reproducible_and_do_not_close_external_reports`,
  `cargo test lab_manifest_and_provenance_cover_reproducible_build_artifacts`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:41:08Z

- Increment completed: reject inconsistent interface/kernel mappings during
  signed profile loading, before a transaction can select the affected AID.
- Research note: C-8 is a contactless kernel path that co-exists with legacy
  kernels during transition. Certification profiles that declare contactless
  support therefore need an explicit C-8 mapping, while contact support needs a
  separate non-C-8 contact kernel mapping.
- Code impact: certification and production profile loading now fails closed
  when a contactless AID is not mapped to `c8_contactless`, when a contact AID
  omits its contact kernel mapping, or when an AID interface list repeats the
  same interface name.
- Evidence updated: configuration, C-8, and interface/kernel RTM rows now cite
  load-time profile mapping rejection coverage alongside the existing runtime
  selected-kernel guard.
- Verification: `cargo test rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces`,
  `cargo test krn_gac_010_cda_request_is_profile_defined_or_unsupported`,
  `cargo test rtm_promotes_c8_kernel_outcome_evidence`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test rtm_promotes_interface_kernel_mapping_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:28:04Z

- Increment completed: derive runtime TAA online capability from EMV terminal
  type (`9F35`) instead of hardcoding every terminal as online-capable.
- Research note: terminal type carries the terminal environment and
  communication capability. TAA online/default branches depend on whether the
  terminal can go online, so an offline-only terminal must not request ARQC just
  because TAC/IAC online bits match.
- Code impact: transaction parameter loading rejects unsupported terminal type
  values, runtime TAA maps known terminal types to online-capable or
  offline-only behavior, and offline-only TAA now follows configured default
  fallback instead of the online ARQC path.
- Evidence updated: runtime TAA regression coverage and both RTM annexes now
  cite terminal-type-driven online capability under `KRN-TAA-006` and
  `KRN-GAC1-003`.
- Verification: `cargo test transaction_params_bind_minor_units_to_currency_exponent`,
  `cargo test taa_uses_terminal_type_online_capability`,
  `cargo test rtm_promotes_terminal_action_analysis_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:20:21Z

- Increment completed: carry signed profile IAC fallback values through profile
  loading and into Terminal Action Analysis when the card omits an IAC tag.
- Research note: IAC Default (`9F0D`), IAC Denial (`9F0E`), and IAC Online
  (`9F0F`) participate in TAA alongside TAC and TVR. Accepting `iac_*` profile
  fields but not retaining them made signed fallback behavior impossible.
- Code impact: `AidProfile` now stores profile issuer action codes, runtime TAA
  uses card-returned IAC tags when present, and falls back per-field to signed
  profile IAC values when the card omits a tag.
- Evidence updated: configuration, runtime TAA, card-override, and both RTM
  annexes now cite signed profile IAC fallback behavior under `KRN-TAA-002` and
  `KRN-TAA-004`.
- Verification: `cargo test loads_profile_issuer_action_code_fallbacks`,
  `cargo test taa_uses_profile_iac_fallbacks_when_card_omits_iacs`,
  `cargo test card_iac_tags_override_profile_fallbacks`,
  `cargo test rtm_promotes_terminal_action_analysis_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:13:37Z

- Increment completed: reject scheme profile AIDs whose first five bytes do not
  match the containing scheme RID.
- Research note: AID namespace ownership is RID-rooted, while ODA CAPK lookup is
  RID/key-index rooted. A mismatched scheme RID and AID prefix can make selection
  provenance diverge from CAPK provenance before transaction processing.
- Code impact: `parse_scheme` now rejects signed profile entries where any AID
  sits outside the scheme RID namespace, before duplicate AID/CAPK checks and
  before the profile is exposed to runtime selection.
- Evidence updated: configuration regression coverage and both RTM annexes now
  cite mismatched AID/RID namespace rejection under `KRN-CFG-002`.
- Verification: `cargo test rejects_aids_outside_scheme_rid_namespace`,
  `cargo test rejects_duplicate_scheme_rids`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:08:49Z

- Increment completed: reject duplicate scheme RIDs across signed profile
  bundles before exposing profiles to selection or CAPK lookup.
- Research note: RID is part of both AID ownership and CAPK lookup identity.
  Allowing two scheme profiles with the same RID makes first-match CAPK
  selection and profile provenance dependent on JSON array order.
- Code impact: `load_profile_set` now fails closed when a signed profile bundle
  contains repeated scheme RIDs, preserving one unambiguous profile namespace for
  each RID.
- Evidence updated: configuration regression coverage and both RTM annexes now
  cite duplicate scheme RID rejection under `KRN-CFG-002`.
- Verification: `cargo test rejects_duplicate_scheme_rids`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test rejects_duplicate_profile_aids_and_capk_indexes`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T06:04:20Z

- Increment completed: reject duplicate profile AID values and duplicate
  CAPK RID/key-index identities inside a signed scheme profile.
- Research note: scheme profile material binds terminal selection and CAPK
  lookup behavior before transaction processing. Repeated identities in one
  signed profile leave deterministic provenance ambiguous even when every
  individual field and checksum is valid.
- Code impact: profile loading now fails closed after decoding AID and CAPK
  arrays if any scheme repeats a selectable AID or CAPK lookup identity.
- Evidence updated: configuration regression coverage and both RTM annexes now
  cite duplicate profile AID/CAPK identity rejection under `KRN-CFG-002`.
- Verification: `cargo test rejects_duplicate_profile_aids_and_capk_indexes`,
  `cargo test rejects_cfg_002_profile_schema_and_field_failures`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T05:55:33Z

- Increment completed: reject constructed children inside INTERNAL AUTHENTICATE
  response template `77` before extracting signed dynamic application data.
- Research note: DDA/CDA verification depends on the card-returned Signed
  Dynamic Application Data (`9F4B`) and optional ICC Dynamic Number (`9F4C`).
  Allowing constructed descendants can hide conflicting signed data with
  ambiguous provenance before recovered-ICC-key verification.
- Code impact: `parse_internal_authenticate_response` now fails closed on any
  constructed child of template `77`, so DDA/CDA verification inputs are direct
  primitive card-returned objects.
- Evidence updated: ODA parser regression tests and DDA traceability guards now
  exercise nested conflicting signed dynamic data rejection; existing RTM rows
  already cite the strengthened internal-authenticate nested/duplicate evidence.
- Verification: `cargo test rejects_nested_or_duplicate_internal_authenticate_data`,
  `cargo test parses_internal_authenticate_response_signed_dynamic_data`,
  `cargo test krn_dda_002_oda_006_requires_signed_dynamic_application_data`,
  `cargo test rtm_promotes_dda_internal_authenticate_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T05:49:00Z

- Increment completed: reject constructed children inside GENERATE AC response
  format 2 template `77` before parsing card-returned cryptogram data.
- Research note: GENERATE AC format 2 carries direct TLV-coded response data
  objects under template `77`, including CID, ATC, Application Cryptogram, and
  optional issuer/dynamic authentication data. Allowing constructed descendants
  can hide conflicting cryptogram data with ambiguous provenance.
- Code impact: `parse_generate_ac_response` now fails closed on any constructed
  child of template `77`, so GAC decisions and online authorization packages are
  built only from direct primitive card-returned objects.
- Evidence updated: GAC parser regression tests and traceability guards now
  exercise nested conflicting cryptogram rejection; existing RTM rows already
  cite the strengthened GAC nested/duplicate response-data evidence.
- Verification: `cargo test rejects_nested_or_duplicate_generate_ac_format_2_data`,
  `cargo test parses_generate_ac_format_2_template_77`,
  `cargo test gac_parsing_uses_card_returned_cryptogram_for_online_handoff`,
  `cargo test rtm_promotes_gac_cdol_encoding_and_response_evidence`,
  `cargo test krn_cid_001_002_decodes_type_and_preserves_non_type_bits`,
  `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and
  `git diff --check` passed.

## 2026-05-22T05:42:27Z

- Increment completed: validate issuer script tag `86` values as short-form
  command APDUs before retaining them for script execution.
- Research note: issuer script commands cross the Level 3 to kernel boundary as
  host-supplied APDU bytes. Accepting arbitrary non-empty values delays malformed
  script detection until runtime exchange and weakens deterministic host-response
  evidence.
- Code impact: issuer script parsing now rejects undersized commands, zero-Lc
  extended-length encodings, and Lc/data length mismatches while preserving valid
  case 1, case 2, and short case 3/4 command APDUs.
- Evidence updated: issuer parser regression tests, host-response traceability
  coverage, and both RTM annexes now cite malformed issuer script command APDU
  rejection.
- Verification: `cargo test rejects_malformed_issuer_script_command_apdus`,
  `cargo test parses_arpc_arc_and_issuer_scripts`,
  `cargo test host_response_extracts_arpc_and_phase_specific_script_results`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T05:36:05Z

- Increment completed: reject duplicate ADF names repeated across PSE/PPSE
  directory entries instead of silently de-duplicating them.
- Research note: application selection promotes card ADF names from directory
  entries into the terminal candidate list. Treating repeated ADF names as a
  parse error keeps candidate provenance deterministic before profile matching.
- Code impact: `parse_fci_candidate_aids` now returns `ParseError` when a
  directory response repeats an AID, whether the duplicate appears inside one
  directory entry or across multiple entries.
- Evidence updated: selection parser regression tests, selection traceability
  guards, and both RTM annexes now cite across-entry duplicate ADF rejection.
- Verification: `cargo test rejects_duplicate_adf_names_across_directory_entries`,
  `cargo test rejects_duplicate_adf_names_in_directory_entries`,
  `cargo test krn_sel_001_002_003_parses_candidates_and_matches_signed_profiles`,
  `cargo test rtm_promotes_runtime_apdu_selection_status_policy_evidence`,
  `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and
  `git diff --check` passed.

## 2026-05-22T05:27:51Z

- Increment completed: reject nested constructed objects inside READ RECORD
  template `70` before storing card data.
- Research note: EMV READ RECORD data for application files is parsed from the
  record template as primitive BER-TLV data objects. Flattening through nested
  constructed objects can import data with ambiguous provenance into later
  restriction, risk, and ODA paths.
- Code impact: `parse_read_record_body` now accepts only direct primitive
  children of template `70` and rejects nested constructed record data without
  partially updating the card data store.
- Evidence updated: record parser unit tests, READ RECORD traceability guards,
  and both RTM annexes now cite nested-record rejection coverage.
- Verification: `cargo test rejects_nested_record_data_without_partial_store`,
  `cargo test rejects_duplicate_record_data_without_partial_store`,
  `cargo test parses_record_template_into_card_data_store`,
  `cargo test krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo clippy --all-targets --all-features`,
  `cargo fmt --check`, and `git diff --check` passed.

## 2026-05-22T05:17:52Z

- Increment completed: reject invalid BER-TLV tag field bytes before card or
  DOL data reaches downstream EMV parsers.
- Research note: ISO 7816 BER-TLV references reserve `00` and `FF` from tag
  values. Those encodings otherwise create malformed or ambiguous tag identities
  at parser boundaries.
- Code impact: the TLV, DOL, and ODA static-authentication tag-list readers now
  reject invalid first tag bytes while preserving valid EMV high-tag-number
  tags such as `9F1E`.
- Evidence updated: TLV/DOL unit tests, ODA malformed tag-list coverage, TLV RTM
  guards, and both RTM annexes now cite invalid tag-field rejection.
- Verification: `cargo test rejects_invalid_tag_field_bytes`,
  `cargo test parses_and_builds_pdol_deterministically`,
  `cargo test rejects_malformed_static_authentication_tag_list`,
  `cargo test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`,
  `cargo test`, `cargo test --examples`, and
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and
  `git diff --check` passed.

## 2026-05-22T05:07:31Z

- Increment completed: reject malformed high-tag-number encodings whose first
  continuation byte carries a zero tag-number group.
- Research note: ISO 7816 BER-TLV tag rules reserve the high-tag-number form
  for tag numbers whose first subsequent byte has a non-zero tag-number group.
  Accepting `9F 80 04` would allow a non-canonical tag spelling into card and
  DOL parser boundaries.
- Code impact: the TLV, DOL, and ODA static-authentication tag-list readers now
  fail closed on zero-prefixed high-tag-number encodings.
- Evidence updated: TLV/DOL unit tests, ODA malformed tag-list coverage, TLV RTM
  guards, and both RTM annexes now cite zero-prefixed high-tag rejection.
- Verification: `cargo test rejects_zero_prefixed_high_tag_numbers`,
  `cargo test rejects_malformed_static_authentication_tag_list`,
  `cargo test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`,
  `cargo test`, `cargo test --examples`, and
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and
  `git diff --check` passed.

## 2026-05-22T05:00:40Z

- Increment completed: reject non-canonical JSON numbers with leading zeroes in
  signed scheme/profile inputs.
- Research note: the profile loader is a certification boundary for AID
  priority, limits, CAPK metadata, and policy fields. Accepting `01` as `1`
  weakens byte-level profile provenance and can hide malformed signed input.
- Code impact: the internal JSON parser now rejects multi-digit numeric tokens
  that start with `0` before profile schema validation consumes them.
- Evidence updated: CFG schema rejection coverage now includes a profile
  priority encoded as `01`; existing RTM rows already cite that test.
- Verification: `cargo test rejects_cfg_002_profile_schema_and_field_failures`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test`, `cargo test --examples`, and
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and
  `git diff --check` passed.

## 2026-05-22T04:54:19Z

- Increment completed: reject malformed Static Data Authentication Tag List
  values before appending extra SDA authentication data.
- Research note: public EMV tag references describe `9F4A` as the Static Data
  Authentication Tag List used by SDA. Constructed or repeated tags in this
  tag-only value would make authentication-data assembly ambiguous.
- Code impact: `parse_static_authentication_tag_list` now accepts only unique
  primitive tags before `build_static_authentication_data` appends their values.
- Evidence updated: ODA unit tests, SDA traceability guards, and both RTM
  annexes now cite malformed SDA tag-list rejection coverage.
- Verification: `cargo test rejects_malformed_static_authentication_tag_list`,
  `cargo test builds_static_authentication_data_from_afl_records_and_tag_list`,
  `cargo test krn_oda_005_static_authentication_data_uses_afl_order_and_tag_list`,
  `cargo test rtm_promotes_oda_capk_tvr_cda_evidence`, `cargo test`,
  `cargo test --examples`, and
  `cargo clippy --all-targets --all-features`, `cargo fmt --check`, and
  `git diff --check` passed.

## 2026-05-22T04:47:42Z

- Increment completed: reject duplicate AFL-derived record locators before
  issuing READ RECORD commands.
- Research note: public EMV AFL material describes the AFL as the card-provided
  guide for which SFI/record ranges the terminal reads. Overlapping AFL ranges
  create duplicate `(SFI, record)` locators, which would otherwise make record
  reads and offline-authentication contribution order ambiguous.
- Code impact: `record_plan` now rejects duplicate record locators across AFL
  entries, and `read_record_commands` inherits the same validation before
  producing APDUs.
- Evidence updated: AFL unit tests, lifecycle/READ RECORD traceability guards,
  and both RTM annexes now cite duplicate-locator rejection coverage.
- Verification: `cargo test rejects_duplicate_afl_record_locators`,
  `cargo test builds_read_record_commands_from_afl_order`,
  `cargo test lifecycle_afl_plan_produces_read_record_sequence_and_oda_flags`,
  `cargo test krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T04:42:36Z

- Increment completed: reject AFL entries whose encoded SFI byte has non-zero
  low bits before deriving READ RECORD commands.
- Research note: public EMV AFL references describe each AFL entry as four
  bytes and encode SFI in the upper five bits of byte 1, with the lower three
  bits set to zero. Accepting non-zero low bits lets a malformed AFL byte map
  to a valid SFI after shifting, weakening record-location provenance.
- Code impact: `parse_afl` now rejects byte-1 encodings where bits 3-1 are not
  zero, preserving existing SFI range, record range, and offline-authentication
  record-count checks.
- Evidence updated: AFL unit tests, READ RECORD traceability guards, and both
  RTM annexes now cite reserved-low-bit rejection coverage.
- Verification: `cargo test rejects_afl_sfi_bytes_with_nonzero_low_bits`,
  `cargo test rejects_malformed_afl_entries`,
  `cargo test lifecycle_afl_plan_produces_read_record_sequence_and_oda_flags`,
  `cargo test krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T04:37:41Z

- Increment completed: reject duplicate selected-application PDOL (`9F38`)
  objects before constructing GET PROCESSING OPTIONS input.
- Research note: public EMV references describe PDOL as tag `9F38` in the
  selected ADF FCI and as the card-declared list of terminal data objects for
  GPO. Multiple direct PDOL objects in selected FCI are ambiguous because the
  terminal must build one deterministic GPO command from one card-declared DOL.
- Code impact: `parse_pdol_from_fci` now uses duplicate-detecting direct-child
  TLV lookup under FCI proprietary templates, rejects duplicate direct PDOLs in
  one `A5` or across multiple direct `A5` templates, and preserves the existing
  policy of ignoring nested/misplaced PDOL-like objects.
- Evidence updated: GPO unit tests, GPO traceability guards, and both RTM
  annexes now cite duplicate-PDOL rejection coverage.
- Verification: `cargo test rejects_duplicate_pdol_objects_in_selected_fci`,
  `cargo test extracts_pdol_from_selected_application_fci`,
  `cargo test krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T04:31:58Z

- Increment completed: reject ambiguous duplicate ADF names inside a single
  PSE/PPSE directory entry before producing the candidate AID list.
- Research note: the existing selection parser intentionally limits candidate
  extraction to `61` directory entries under the FCI proprietary template and
  treats tag `4F` as the selectable ADF name. Multiple direct `4F` objects in
  one directory entry are ambiguous because the kernel must bind selection to a
  single card-declared application name.
- Code impact: `parse_fci_candidate_aids` now uses duplicate-detecting
  direct-child TLV lookup for directory-entry `4F` values, preserving existing
  nested-template exclusion and candidate de-duplication behavior.
- Evidence updated: selection unit tests, selection traceability guards, and
  both RTM annexes now cite duplicate ADF-name rejection coverage.
- Verification: `cargo test rejects_duplicate_adf_names_in_directory_entries`,
  `cargo test extracts_candidate_aids_from_directory_fci`,
  `cargo test krn_sel_001_002_003_parses_candidates_and_matches_signed_profiles`,
  `cargo test rtm_promotes_runtime_apdu_selection_status_policy_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed. `cargo fmt` was applied before the final format check.

## 2026-05-22T04:26:39Z

- Increment completed: reject duplicate primitive data objects in a single READ
  RECORD response before storing card data.
- Research note: public EMV read-record material describes tag `70` as the
  record template whose value is stored as card data without the outer record
  wrapper. A duplicate primitive tag inside one record is ambiguous because the
  kernel data store is tag-keyed, so silently overwriting the earlier value
  weakens card-data provenance.
- Code impact: `parse_read_record_body` now validates all primitive record data
  object tags for uniqueness before writing to `DataStore`, preserving existing
  nested BER-TLV traversal for unique primitive descendants while rejecting
  duplicate direct or nested primitive tags without partial writes.
- Evidence updated: record unit tests, READ RECORD traceability guards, and both
  RTM annexes now cite duplicate-record-data rejection coverage.
- Verification: `cargo test rejects_duplicate_record_data_without_partial_store`,
  `cargo test rejects_unwrapped_or_extra_record_data`,
  `cargo test krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T04:18:31Z

- Increment completed: require issuer host-response ARC (`8A`) and issuer
  authentication data (`91`) to be direct, unique top-level response objects.
- Research note: public processor integration material identifies ARC `8A`,
  issuer authentication data `91`, and optional issuer scripts `71`/`72` as EMV
  response tags passed back to the kernel. The kernel should not recursively
  mine issuer authentication material from unrelated constructed templates.
- Code impact: `parse_host_response` now uses duplicate-detecting direct-child
  lookup for `8A` and `91`, rejects nested `8A`/`91` objects, and preserves the
  existing direct-only issuer script template policy.
- Evidence updated: issuer unit tests, host-response traceability guards, and
  both RTM annexes now prove nested or duplicate host-response authentication
  objects are rejected.
- Verification: `cargo test rejects_nested_or_duplicate_host_response_auth_objects`,
  `cargo test parses_arpc_arc_and_issuer_scripts`,
  `cargo test host_response_extracts_arpc_and_phase_specific_script_results`,
  `cargo test rtm_promotes_online_boundary_evidence`,
  `cargo test rtm_promotes_issuer_authentication_and_final_gac_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T04:07:14Z

- Increment completed: require response-template data objects to be direct and
  unique when parsing GPO, GENERATE AC, and INTERNAL AUTHENTICATE responses.
- Research note: public EMV transaction examples describe Template `77` as the
  constructed response wrapper whose value contains the TLV-coded response data
  objects; accepting mandatory objects from nested constructed subtrees weakens
  response provenance and can hide malformed card responses.
- Code impact: the TLV module now has a duplicate-detecting direct-child lookup
  helper. GPO Template `77`, GENERATE AC Format 2, and INTERNAL AUTHENTICATE
  parsers now reject nested mandatory response data and duplicate recognized
  response objects instead of recursively accepting the first match.
- Evidence updated: TLV, GPO, GAC, and ODA unit tests, traceability guards, and
  both RTM annexes now cite direct-child and duplicate rejection coverage.
- Verification: `cargo test rejects_nested_or_duplicate_gpo_response_data`,
  `cargo test rejects_nested_or_duplicate_generate_ac_format_2_data`,
  `cargo test rejects_nested_or_duplicate_internal_authenticate_data`,
  `cargo test finds_unique_direct_values_without_descending`,
  `cargo test krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates`,
  `cargo test krn_cid_001_002_decodes_type_and_preserves_non_type_bits`,
  `cargo test krn_dda_002_oda_006_requires_signed_dynamic_application_data`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`,
  `cargo test rtm_promotes_gac_cdol_encoding_and_response_evidence`,
  `cargo test rtm_promotes_dda_internal_authenticate_evidence`,
  `cargo test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T03:53:32Z

- Increment completed: make issuer script parsing direct-child only inside
  host-provided Template `71`/`72` script templates.
- Research note: issuer script sequencing remains a certification-sensitive
  behavior in the engineering notes, so parser evidence should reject nested or
  duplicate script objects instead of recursively accepting APDUs from arbitrary
  constructed TLV subtrees.
- Code impact: host response parsing now accepts script templates only at the
  top level of the host response TLV stream, requires direct `86` command
  children, allows at most one direct `9F18` identifier, and rejects unexpected
  objects inside a script template.
- Evidence updated: issuer-script unit tests, traceability guard, and both RTM
  annexes now prove commandless, nested, duplicate, and misplaced issuer script
  structures are not accepted as executable script commands.
- Verification: `cargo test rejects_nested_or_duplicate_issuer_script_objects`,
  `cargo test parses_arpc_arc_and_issuer_scripts`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T03:48:39Z

- Increment completed: constrain selected-application PDOL extraction to the
  FCI proprietary template before building GPO input data.
- Research note: public EMV references identify tag `9F38` as the PDOL in the
  selected ADF FCI, and public decoded examples place it under the top-level
  `6F` FCI template inside `A5`; accepting an arbitrary flattened `9F38`
  weakens GPO input provenance.
- Code impact: `parse_pdol_from_fci` now requires a single top-level `6F`
  template and only uses direct `9F38` children of `A5`; unwrapped FCI is
  rejected and misplaced PDOL-like data is ignored so GPO construction falls
  back to an empty PDOL.
- Evidence updated: GPO unit, traceability, and both RTM annexes now prove
  valid PDOL extraction and rejection/ignoring of unwrapped or misplaced PDOL
  data.
- Verification: `cargo test extracts_pdol_from_selected_application_fci`,
  `cargo test krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T03:37:54Z

- Increment completed: require PSE/PPSE candidate AIDs to come from directory
  application templates before matching signed profiles.
- Research note: public PSE/PPSE examples describe candidate AIDs as tag `4F`
  entries inside application templates `61`, commonly under FCI issuer
  discretionary data `BF0C`; accepting any flattened `4F` in FCI weakens
  application-selection evidence.
- Code impact: `parse_fci_candidate_aids` now requires a single top-level `6F`
  FCI template and extracts candidates only from `A5/BF0C/61/4F`; valid FCI
  without directory entries still returns an empty list so direct-AID fallback
  remains available.
- Evidence updated: selection unit, traceability, and RTM rows now prove valid
  directory extraction and reject unwrapped or misplaced `4F` tags as
  candidates.
- Verification: `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T03:31:09Z

- Increment completed: require TLV-encoded INTERNAL AUTHENTICATE responses to
  use a single top-level response template before accepting signed dynamic
  application data.
- Research note: public EMV tag references identify response template `77` as
  used for INTERNAL AUTHENTICATE, and the corrected kernel specification says
  TLV-encoded INTERNAL AUTHENTICATE responses carry signed dynamic data under
  tag `9F4B`; accepting an unwrapped `9F4B` would weaken DDA parser evidence.
- Code impact: `parse_internal_authenticate_response` now rejects unwrapped
  signed dynamic data and extra sibling TLVs, then extracts `9F4B` and optional
  `9F4C` only from the sole top-level `77` template.
- Evidence updated: unit, traceability, and RTM rows now include
  `oda::tests::rejects_internal_authenticate_without_response_template`
  alongside DDA signed-dynamic-data verification evidence.
- Verification: `cargo test rejects_internal_authenticate_without_response_template`,
  `cargo test parses_internal_authenticate_response_signed_dynamic_data`,
  `cargo test krn_dda_002_oda_006_requires_signed_dynamic_application_data`,
  `cargo test rtm_promotes_dda_internal_authenticate_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T03:23:25Z

- Increment completed: require READ RECORD bodies to use a single top-level
  record template before storing card data.
- Research note: the corrected kernel specification identifies tag `70` as the
  READ RECORD response record template; accepting unwrapped primitive TLVs would
  let malformed card data populate the transaction store as if it were a valid
  application record.
- Code impact: `parse_read_record_body` now rejects unwrapped primitives and
  extra sibling TLVs, and stores only primitive children of the sole top-level
  `70` record template.
- Evidence updated: unit, traceability, and RTM rows now include
  `record::tests::rejects_unwrapped_or_extra_record_data` alongside the valid
  record-template parser and masked logging evidence.
- Verification: `cargo test rejects_unwrapped_or_extra_record_data`,
  `cargo test krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`,
  `cargo test read_records_retains_ordered_offline_authentication_bodies`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T03:15:38Z

- Increment completed: require a single supported GENERATE AC response
  template before parsing returned cryptogram data.
- Research note: GAC response parsing evidence must prove both accepted
  template `80`/`77` handling and rejection of unsupported top-level shapes;
  otherwise recursive TLV lookup can make malformed or unwrapped responses look
  like profile-permitted format 2 data.
- Code impact: `parse_generate_ac_response` now dispatches only on one
  top-level response template (`80` for format 1, `77` for format 2) and
  rejects unwrapped required tags or extra sibling templates.
- Evidence updated: unit, traceability, and RTM rows now include
  `gac::tests::rejects_generate_ac_without_single_supported_response_template`
  alongside the valid format 1/2 parsing evidence.
- Verification: `cargo test rejects_generate_ac_without_single_supported_response_template`,
  `cargo test gac_parsing_uses_card_returned_cryptogram_for_online_handoff`,
  `cargo test rtm_promotes_gac_cdol_encoding_and_response_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T03:07:56Z

- Increment completed: make EXTERNAL AUTHENTICATE status handling explicitly
  TVR-mediated.
- Research note: the status-word policy skeleton says EXTERNAL AUTHENTICATE
  failures should set the issuer authentication failed TVR bit if attempted,
  rather than collapse into a generic argument error.
- Code impact: the shared status classifier now returns
  `ContinueWithTvr(TVR_B5_ISSUER_AUTHENTICATION_FAILED)` for failed EXTERNAL
  AUTHENTICATE responses, and issuer-authentication runtime handling consumes
  that classifier result before persisting TVR/TSI evidence.
- Evidence updated: unit and traceability tests now require failed EXTERNAL
  AUTHENTICATE status words to follow the issuer-authentication-failed TVR path
  instead of a generic argument error.
- Verification: `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T03:00:54Z

- Increment completed: add a reproducible ABI conformance statement artifact.
- Research note: the ABI conformance JSON is already exposed through FFI, but
  submission packaging is stronger when the exact JSON is checked in, generated
  by a stable command, and cross-checked against the ABI entrypoint.
- Code impact: no transaction behavior changed; the new example emits the same
  canonical JSON as `krn_get_conformance_statement_json`.
- Evidence updated: `abi_conformance_statement.json` is generated by
  `krn_abi_conformance_statement`, covered by the lab manifest and build
  provenance, and open-issues wording keeps the signed lab template pending.
- Verification: `cargo run --quiet --example krn_abi_conformance_statement |
  diff -u docs/abi_conformance_statement.json -`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T02:54:56Z

- Increment completed: add a reproducible pre-lab quality gate manifest.
- Research note: repository-controlled quality gates should be explicit and
  regenerable, but they must not be confused with formal coverage, integration,
  static-analysis, or fuzzing reports accepted for certification submission.
- Code impact: no transaction behavior changed; `prelab_quality_gates_json`
  emits the local gate list and identifies CERT-OPEN-009/010 as still open.
- Evidence updated: `prelab_quality_gates.json` is generated by
  `krn_prelab_quality_gates`, covered by the lab manifest and build provenance,
  and open-issues wording keeps formal report attachments pending.
- Verification: `cargo run --quiet --example krn_prelab_quality_gates | diff
  -u docs/prelab_quality_gates.json -`, `cargo test`, `cargo test --examples`,
  `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and
  `git diff --check` passed.

## 2026-05-22T02:49:53Z

- Increment completed: add a standalone pre-lab APDU trace-pack generator.
- Research note: certification evidence should be reproducible outside the test
  harness; a checked-in fixture is stronger when a maintainer can regenerate it
  with a stable command and compare the exact bytes.
- Code impact: no runtime behavior changed; `krn_prelab_trace_pack` reuses the
  same `ReplayScript`, production log policy, ABI version, and profile version
  as the checked-in fixture.
- Evidence updated: the lab manifest names the generator command, provenance
  coverage includes `examples/krn_prelab_trace_pack.rs`, and the generator
  output compares cleanly against `docs/prelab_apdu_trace_pack.jsonl`.
- Verification: `cargo run --quiet --example krn_prelab_trace_pack | diff -u
  docs/prelab_apdu_trace_pack.jsonl -`, `cargo test`, `cargo test --examples`,
  `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and
  `git diff --check` passed.

## 2026-05-22T02:42:44Z

- Increment completed: add a deterministic pre-lab APDU trace fixture.
- Research note: the lab trace-pack blocker should remain open until all
  lab/test-tool cases are attached, but the repository can still control a
  masked replay fixture that proves the JSONL trace-pack shape, identity
  binding, and PAN suppression behavior.
- Code impact: no runtime behavior changed; traceability coverage now
  regenerates the pre-lab fixture from `ReplayScript` and compares it
  byte-for-byte with the checked-in JSONL.
- Evidence updated: `prelab_apdu_trace_pack.jsonl` is covered by the lab
  manifest, build provenance inputs, and open-issues wording that keeps
  CERT-OPEN-012 open for the full lab trace pack.
- Verification: `cargo test`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T02:36:45Z

- Increment completed: add a controlled certification open-issues register.
- Research note: `docs/eng_notes.md` requires a formal open-issues register so
  external certification blockers are tracked explicitly instead of being
  inferred from scattered manifest caveats.
- Code impact: no runtime behavior changed; traceability coverage now requires
  the register to enumerate external approval, profile, CAPK, ODA vector,
  contactless, device, PCI/PED, security, report, conformance, and APDU-trace
  blockers.
- Evidence updated: the lab manifest now includes the open-issues register as a
  controlled artifact and build provenance covers the new register.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:30:50Z

- Increment completed: bound device and declaration claims in the lab manifest.
- Research note: the draft manifest should not imply certified readers or full
  EMV specification conformance while device evidence, licensed review, scheme
  validation, and laboratory approval remain external.
- Code impact: no runtime behavior changed; traceability guards now reject
  device and declaration overclaims in the lab manifest.
- Evidence updated: the lab manifest now identifies contactless readers as
  pending device/L1 evidence and frames EMV/C-8 alignment as intended behavior
  subject to licensed review and lab approval; engineering notes now match the
  current attachment boundary.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T02:27:19Z

- Increment completed: bound lab-manifest certification scope claims.
- Research note: a draft submission manifest should distinguish in-scope
  pre-certification hardening from actual EMV Level 2, C-8, or PCI evidence
  approval while lab reports, signed profiles, and integration statements remain
  unattached.
- Code impact: no runtime behavior changed; traceability tests now reject
  approval-sounding `Yes` scope claims in the lab manifest.
- Evidence updated: the lab manifest now says contact and C-8 are in scope for
  pre-certification hardening and that final claims require lab execution,
  signed approval evidence, lab-supplied profile data, and PED integration
  evidence.
- Verification: `cargo test`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

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

## 2026-05-22T07:23:51Z

- Increment completed: reject malformed generic replay response TLVs instead
  of silently downgrading them to unparsed response traces.
- Research note: replay traces are certification evidence; status-only
  responses can be represented without TLV fields, but nonempty response
  bodies in generic TLV contexts must parse deterministically or fail closed.
- Code impact: `mask_apdu_response` now propagates TLV parse errors for
  nonempty generic response data while retaining status-only response support.
- Evidence updated: KRN-FSM-003 RTM rows cite the malformed-response replay
  trace regression.
- Verification: `cargo test generic_response_trace_rejects_malformed_tlv_payloads`,
  `cargo test rtm_promotes_fsm_annex_replay_and_error_transition_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T07:28:18Z

- Increment completed: include the legacy RTM compatibility copy in the
  pre-lab build-provenance gate.
- Research note: the active specification and ABI conformance statement treat
  both RTM CSVs as controlled annexes, so reproducible provenance must hash both
  the current RTM and the compatibility copy.
- Code impact: `prelab_quality_gates_json()` now emits a build-provenance
  command that includes `docs/requirements-traceability-matrix.csv`, and the
  checked-in manifest was regenerated to match.
- Evidence updated: traceability coverage now requires the compatibility RTM in
  the lab manifest, provenance input set, required artifact list, and pre-lab
  gate command.
- Verification: `cargo test lab_manifest_and_provenance_cover_reproducible_build_artifacts`,
  `cargo test prelab_quality_gates_are_reproducible_and_do_not_close_external_reports`,
  `cargo run --quiet --example krn_prelab_quality_gates`, the exact
  `cargo run --quiet --example krn_build_manifest -- ...` pre-lab provenance
  command, `cargo test`, `cargo test --examples`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T07:34:52Z

- Increment completed: prevent structural ODA fixtures from being promoted to
  certification vectors by changing only `vector_class`.
- Research note: ODA certification vectors are external lab evidence, so a
  repository fixture that describes itself as parser/evidence plumbing must not
  pass certification-mode validation after metadata relabeling.
- Code impact: certification-mode ODA vector validation now rejects fixture
  language in addition to placeholders, dummy material, and fictitious data.
- Evidence updated: ODA unit and traceability tests now use a separate
  certification-shaped positive annex and assert that the checked-in structural
  fixture remains rejected when relabeled.
- Verification: `cargo test validates_complete_vector_syntax_and_rejects_placeholders`,
  `cargo test certification_vector_coverage_is_method_specific`,
  `cargo test krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T07:44:36Z

- Increment completed: refresh the public standards watch with EMVCo
  Contactless Kernel 8 approval-process signals.
- Research note: public EMVCo materials distinguish full contactless device,
  standalone Contactless Kernel 8, and approved-kernel integration submission
  paths, with implementation conformance statements, laboratory test reports,
  and Letters of Approval remaining external evidence.
- Code impact: no kernel code changed; the standards annex now records the
  public approval-path boundary that must be resolved before closing
  `CERT-OPEN-005`.
- Evidence updated: traceability coverage now requires the standards watch to
  name the approval paths, ICS evidence, laboratory reports, and LoA boundary.
- Verification: `cargo test certification_open_issues_register_tracks_external_blockers`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T07:49:42Z

- Increment completed: make the pre-lab APDU trace pack self-scoping.
- Research note: pre-lab traces are useful reproducibility evidence but must
  identify their case scope and preserve the `CERT-OPEN-012` full lab trace-pack
  boundary inside the generated artifact.
- Code impact: `krn_prelab_trace_pack` now emits a leading
  `trace-pack-metadata` JSONL record with a stable trace-pack ID, case ID,
  repository-controlled fixture scope, and `does_not_close` marker.
- Evidence updated: the checked-in pre-lab trace pack and lab manifest now
  include trace-pack metadata, and traceability coverage verifies that metadata
  before checking masking and replay content.
- Verification: `cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -`,
  `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features` passed.

## 2026-05-22T07:58:18Z

- Increment completed: fail closed on contradictory C-8 outcome instruction
  tuples before they reach Level 3 callbacks.
- Research note: C-8 approval remains external, but repository-controlled
  outcome plumbing can still enforce internal consistency for restart,
  try-again, alternate-interface, and empty-UI encodings.
- Code impact: `ContactlessOutcome::new` now rejects invalid combinations
  such as alternate-interface outcomes without an alternate interface,
  restart-required outcomes without a start signal, try-again outcomes without
  Try Again UI status, and non-empty UI fields attached to `UiStatus::None`.
- Evidence updated: current and compatibility RTM annexes cite the new Rust
  model and FFI rejection tests for C-8/contactless outcome rows.
- Verification: `cargo test outcome_model_rejects_inconsistent_c8_instruction_tuples`,
  `cargo test ffi_rejects_inconsistent_contactless_outcome_tuples`,
  `cargo test rtm_promotes_c8_kernel_outcome_evidence`,
  `cargo test rtm_promotes_contactless_entry_outcome_limit_and_cdcvm_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:10:36Z

- Increment completed: reject structurally invalid CAPK public-key
  components during signed profile loading instead of deferring rejection until
  ODA use.
- Research note: CAPK authority remains external (`CERT-OPEN-003`), but the
  repository-controlled loader can still reject degenerate or unbounded RSA
  public key material before it enters a certification profile set.
- Code impact: CAPK loading now bounds RSA modulus/exponent sizes, rejects
  zero-prefixed or dummy modulus data, and requires a bounded odd public
  exponent greater than one before checksum validation accepts the key record.
- Evidence updated: current and compatibility RTM annexes cite the new CAPK
  component rejection test for CAPK integrity, profile-shape, and configuration
  schema rows.
- Verification: `cargo test rejects_invalid_capk_public_key_components`,
  `cargo test loads_profile_annex_when_signature_is_verified`,
  `cargo test rtm_promotes_signed_profile_and_capk_validation_evidence`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:19:02Z

- Increment completed: lock missing-SDAD CDA evidence for first GENERATE AC
  runtime handoff.
- Research note: lab-supplied CDA cryptographic vectors remain external
  certification evidence, but the repository runtime can still prove that a
  CDA-selected transaction with a template-80 first GENERATE AC response that
  omits signed dynamic application data records CDA failure in TVR and carries
  that TVR into online authorization data.
- Code impact: first GENERATE AC now names the CDA verification decision, and
  the FFI runtime regression covers a CDA-selected online handoff where `9F4B`
  is absent and `B1_CDA_FAILED` is preserved without setting the DDA-failure
  bit.
- Evidence updated: current and compatibility RTM annexes cite the missing-SDAD
  runtime regression for `KRN-ODA-007`, `KRN-ODA-008`, and `KRN-GAC1-005`.
- Verification: `cargo test runtime_cda_missing_signed_dynamic_data_sets_tvr_for_online_handoff`,
  `cargo test rtm_promotes_oda_capk_tvr_cda_evidence`,
  `cargo test rtm_promotes_gac_cdol_encoding_and_response_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:27:34Z

- Increment completed: enforce a host-response-wide issuer script command cap
  instead of limiting only each individual Template 71/72 object.
- Research note: lab issuer-script case packs remain external certification
  evidence, but repository-controlled parsing can still fail closed on bounded
  script structure before any APDU command reaches the card.
- Code impact: `collect_scripts` now counts parsed script APDUs across the
  complete host response and rejects cumulative overflow with
  `KRN_ERR_LENGTH_OVERFLOW`; the regression proves that splitting commands
  across multiple valid templates cannot bypass `MAX_SCRIPT_COMMANDS`.
- Evidence updated: current and compatibility RTM annexes cite the cumulative
  overflow regression for `KRN-SCR-001`.
- Verification: `cargo test rejects_cumulative_issuer_script_command_overflow`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:34:00Z

- Increment completed: make the CVM List parser's rule-count bound explicit
  and traceable.
- Research note: lab CVM cases remain external certification evidence, but the
  repository-controlled parser can still prove that an oversized CVM List is
  rejected before evaluator work scales past the configured rule cap.
- Code impact: CVM List amount-header and rule-stride sizes now use named
  constants, and `parse_cvm_list` has a regression proving more than
  `MAX_CVM_RULES` entries fails with `KRN_ERR_LENGTH_OVERFLOW`.
- Evidence updated: current and compatibility RTM annexes cite the CVM
  overflow regression for `KRN-CVM-001`.
- Verification: `cargo test rejects_cvm_lists_above_rule_limit`,
  `cargo test rtm_promotes_cvm_outcome_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:40:20Z

- Increment completed: make the DOL parser's entry-count bound explicit and
  traceable.
- Research note: external DOL/APDU certification packs remain lab-controlled
  evidence, but repository-controlled parsing can still prove oversized DOL
  definitions fail closed before PDOL/CDOL/DDOL construction work scales past
  the configured entry cap.
- Code impact: `parse_dol` now has a regression proving more than
  `MAX_DOL_ENTRIES` valid tag-length pairs fails with
  `KRN_ERR_LENGTH_OVERFLOW`.
- Evidence updated: current and compatibility RTM annexes cite the oversized
  DOL-entry regression for `KRN-DOL-001`.
- Verification: `cargo test rejects_dol_lists_above_entry_limit`,
  `cargo test rtm_promotes_dol_construction_policy_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:43:33Z

- Increment completed: make TLV parser depth and node-count bounds explicit
  and traceable.
- Research note: invalid nested-template and parser resource-limit cases are
  repository-controllable even while external scheme/lab TLV vector packs remain
  certification evidence blockers.
- Code impact: `parse_many` now has regressions proving more than
  `MAX_TLV_NODES` parsed objects fails with `KRN_ERR_LENGTH_OVERFLOW` and
  nesting deeper than `MAX_TLV_DEPTH` fails closed as malformed TLV structure.
- Evidence updated: current and compatibility RTM annexes cite both TLV
  resource-limit regressions for `KRN-TLV-003`.
- Verification: `cargo test rejects_tlv_node_limit_overflow`,
  `cargo test rejects_tlv_depth_limit_overflow`,
  `cargo test rtm_promotes_tlv_catalogue_and_dol_classification_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:46:59Z

- Increment completed: make AFL entry and READ RECORD locator bounds
  explicit and traceable.
- Research note: scheme/lab GPO and READ RECORD packs remain external
  certification evidence, but repository-controlled AFL expansion can prove
  malformed or oversized record plans fail closed before APDU generation.
- Code impact: AFL parsing now has a regression proving more than
  `MAX_AFL_ENTRIES` fails with `KRN_ERR_LENGTH_OVERFLOW`, and record planning
  has a regression proving more than `MAX_RECORD_LOCATORS` fails before READ
  RECORD APDUs are generated.
- Evidence updated: current and compatibility RTM annexes cite both AFL
  resource-limit regressions for `KRN-RR-001`.
- Verification: `cargo test rejects_afl_lists_above_entry_limit`,
  `cargo test rejects_record_plans_above_locator_limit`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:53:05Z

- Increment completed: make PSE/PPSE candidate-list bounds explicit and
  traceable.
- Research note: lab selection cases remain external certification evidence,
  but repository-controlled FCI directory parsing can still prove oversized
  candidate lists fail closed before profile matching and SELECT response
  continuation work.
- Code impact: PSE/PPSE FCI directory parsing now has a regression proving
  more than `MAX_CANDIDATE_AIDS` unique ADF names fails with
  `KRN_ERR_LENGTH_OVERFLOW` before profile matching.
- Evidence updated: current and compatibility RTM annexes cite the
  candidate-list overflow regression for `KRN-SEL-001` and `KRN-SEL-002`.
- Verification: `cargo test rejects_candidate_aid_lists_above_limit`,
  `cargo test rtm_promotes_runtime_apdu_selection_status_policy_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T08:57:56Z

- Increment completed: make certification-profile JSON parser depth and node
  bounds explicit and traceable.
- Research note: external profile approval remains a certification blocker, but
  repository-controlled profile loading can still prove oversized or deeply
  nested JSON fails closed before schema interpretation or CAPK/profile use.
- Code impact: profile loading now has regressions proving nesting beyond
  `MAX_JSON_DEPTH` and parsed values beyond `MAX_JSON_NODES` fail with
  `KRN_ERR_LENGTH_OVERFLOW`.
- Evidence updated: current and compatibility RTM annexes cite both JSON parser
  resource-limit regressions for `KRN-CFG-002`.
- Verification: `cargo test rejects_profile_json_depth_limit_overflow`,
  `cargo test rejects_profile_json_node_limit_overflow`,
  `cargo test rtm_promotes_cfg_schema_and_terminal_param_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:03:36Z

- Increment completed: make replay and trace evidence resource bounds
  explicit and traceable.
- Research note: external lab trace packs remain certification evidence, but
  repository-controlled replay generation can prove oversized APDU payloads,
  replay scripts, and masked TLV field sets fail closed before becoming
  certification-debug artifacts.
- Code impact: replay script construction now rejects more than
  `MAX_REPLAY_STEPS`, replay exchange construction rejects command or response
  data above `MAX_REPLAY_APDU_BYTES`, and masked TLV stream extraction rejects
  more than `MAX_TRACE_FIELDS`.
- Evidence updated: current and compatibility RTM annexes cite the replay
  resource-limit regressions for `KRN-FSM-003` and the trace-field overflow
  regression for `KRN-LOG-003`.
- Verification: `cargo test replay_rejects_step_count_overflow`,
  `cargo test replay_rejects_apdu_payloads_above_max_bytes`,
  `cargo test mask_tlv_stream_rejects_trace_field_overflow`,
  `cargo test rtm_promotes_fsm_annex_replay_and_error_transition_evidence`,
  `cargo test rtm_promotes_logging_policy_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:10:32Z

- Increment completed: make Level 3 host-response ABI input bounds explicit
  and traceable.
- Research note: external issuer/host response case packs remain certification
  evidence, but repository-controlled ABI handling can still prove empty and
  oversized host response payloads fail closed before parsing or state
  mutation.
- Code impact: `krn_apply_host_response` now has a regression proving empty
  and larger-than-`MAX_HOST_RESPONSE_LEN` payloads return
  `KRN_ERR_LENGTH_OVERFLOW` before host-response parsing.
- Evidence updated: current and compatibility RTM annexes cite the
  host-response ABI input-bound regression for `KRN-ONL-002`.
- Verification: `cargo test apply_host_response_rejects_empty_or_oversize_payload`,
  `cargo test rtm_promotes_online_boundary_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:17:41Z

- Increment completed: make Level 3 online authorization package output
  bounds explicit and traceable.
- Research note: issuer/acquirer host integration and scheme case packs remain
  external certification evidence, but the kernel-owned handoff encoder can
  still prove oversized TLV packages fail closed before Level 3 receives them.
- Code impact: `encode_online_authorization_package` now has a regression
  proving larger-than-`MAX_ONLINE_AUTH_DATA_LEN` TLV output returns
  `LengthOverflow` before emitting the handoff buffer.
- Evidence updated: current and compatibility RTM annexes cite the online
  authorization package output-bound regression for `KRN-ONL-001`.
- Verification: `cargo test online_authorization_package_rejects_tlv_output_above_limit`,
  `cargo test rtm_promotes_online_boundary_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:22:08Z

- Increment completed: make SDA static authentication tag-list bounds
  explicit and traceable.
- Research note: lab ODA vector packs remain external certification evidence,
  but repository-controlled SDA input assembly can prove oversized
  `9F4A` tag lists fail closed before static authentication data is built.
- Code impact: `build_static_authentication_data` now has a regression proving
  more than `MAX_STATIC_AUTH_TAG_LIST_TAGS` primitive tags returns
  `LengthOverflow`.
- Evidence updated: current and compatibility RTM annexes cite the static
  authentication tag-list overflow regression for `KRN-ODA-005`.
- Verification: `cargo test rejects_static_authentication_tag_lists_above_limit`,
  `cargo test rtm_promotes_oda_capk_tvr_cda_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:27:26Z

- Increment completed: make APDU transport follow-up chain bounds explicit
  and traceable.
- Research note: full lab APDU trace packs remain external certification
  evidence, but repository-controlled APDU transport can prove repeated
  `61xx`/`6Cxx` follow-ups fail closed instead of looping indefinitely.
- Code impact: `transmit_apdu_with_followups` now has a regression proving
  more than `MAX_APDU_FOLLOWUPS` chained follow-ups returns
  `LengthOverflow`.
- Evidence updated: current and compatibility RTM annexes cite the APDU
  follow-up chain overflow regression for `KRN-APDU-003` and `KRN-APDU-010`.
- Verification: `cargo test transmit_apdu_followups_rejects_chains_above_limit`,
  `cargo test rtm_promotes_apdu_status_word_evidence`,
  `cargo test rtm_promotes_runtime_apdu_selection_status_policy_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:31:55Z

- Increment completed: make build-provenance manifest resource bounds
  explicit and traceable.
- Research note: EMV Level 2 approval and signed LoA remain external
  certification evidence, but repository-controlled lab-package provenance can
  prove empty and oversized artifact manifests fail closed before becoming
  submission evidence.
- Code impact: `build_provenance_manifest` now has a regression proving empty
  artifact sets and more than `MAX_PROVENANCE_ARTIFACTS` inputs return
  `LengthOverflow`.
- Evidence updated: current and compatibility RTM annexes cite the provenance
  resource-limit regression and lab-manifest provenance coverage for
  `KRN-CERT-001`.
- Verification: `cargo test provenance_manifest_rejects_resource_limits`,
  `cargo test rtm_external_lab_gates_are_explicit`,
  `cargo test lab_manifest_and_provenance_cover_reproducible_build_artifacts`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:36:53Z

- Increment completed: make ODA public-key material resource bounds explicit
  and traceable.
- Research note: lab-supplied SDA/DDA/CDA vector packs remain external
  certification evidence, but repository-controlled ODA recovery can prove
  oversized issuer/ICC public-key material fails closed before certificate
  recovery or RSA exponentiation.
- Code impact: ODA now has a regression proving issuer public-key remainders
  above `MAX_ODA_REMAINDER_BYTES` and RSA moduli above
  `MAX_ODA_RSA_MODULUS_BYTES` return `InvalidProfile`.
- Evidence updated: current and compatibility RTM annexes cite the public-key
  material resource-limit regression for `KRN-ODA-003` and `KRN-ODA-004`.
- Verification: `cargo test rejects_public_key_material_above_resource_limits`,
  `cargo test rtm_promotes_oda_capk_tvr_cda_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:41:42Z

- Increment completed: make per-command issuer-script APDU length bounds
  explicit and traceable.
- Research note: full host/lab issuer-script trace packs remain external
  certification evidence, but repository-controlled script parsing can prove a
  single Template 71/72 command above the configured APDU ceiling fails closed
  before execution.
- Code impact: issuer-script parsing now classifies APDU command values above
  `MAX_SCRIPT_COMMAND_LEN` as `LengthOverflow`, with a regression covering a
  long-form TLV script command over the ceiling.
- Evidence updated: current and compatibility RTM annexes cite the per-command
  issuer-script length-limit regression for `KRN-SCR-001`.
- Verification: `cargo test rejects_issuer_script_commands_above_length_limit`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:45:59Z

- Increment completed: make SDA static-authentication aggregate data bounds
  explicit and traceable.
- Research note: lab-supplied SDA vector packs remain external certification
  evidence, but repository-controlled SDA data assembly can prove AFL record
  bodies and optional static tag-list contributions cannot exceed the bounded
  authentication-data buffer.
- Code impact: ODA now has a regression proving static authentication data
  above `MAX_ODA_AUTHENTICATION_DATA_BYTES` returns `LengthOverflow` before
  signature verification.
- Evidence updated: current and compatibility RTM annexes cite the aggregate
  static-authentication data ceiling regression for `KRN-ODA-005`.
- Verification: `cargo test rejects_static_authentication_data_above_aggregate_limit`,
  `cargo test rtm_promotes_oda_capk_tvr_cda_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:49:47Z

- Increment completed: make performance counter overflow handling explicit
  and traceable.
- Research note: formal performance reports remain external certification
  evidence, but repository-controlled timing evidence can prove ODA crypto, TLV,
  and APDU timing accumulators fail closed instead of wrapping impossible
  microsecond totals.
- Code impact: performance accumulation now has a regression proving per-stage
  counter overflow, aggregate `kernel_only_micros` overflow, and target
  evaluation overflow all return `LengthOverflow`.
- Evidence updated: current and compatibility RTM annexes cite the performance
  counter overflow regression for `KRN-PERF-001`.
- Verification: `cargo test rejects_performance_counter_overflow`,
  `cargo test rtm_promotes_performance_profile_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:54:50Z

- Increment completed: make contactless relay-resistance APDU and response
  resource bounds explicit and traceable.
- Research note: the licensed C-8 relay-resistance profile package remains
  external certification evidence, but repository-controlled profile validation
  can prove oversized relay-resistance command APDUs and success responses fail
  closed before runtime contactless processing.
- Code impact: C-8 relay-resistance profile validation now has a regression
  proving inputs above `MAX_RELAY_RESISTANCE_APDU_LEN` and
  `MAX_RELAY_RESISTANCE_RESPONSE_LEN` return `InvalidProfile`.
- Evidence updated: current and compatibility RTM annexes cite the
  relay-resistance resource-limit regression for `KRN-CLESS-005`.
- Verification: `cargo test rejects_relay_resistance_profiles_above_resource_limits`,
  `cargo test krn_cless_005_relay_resistance_is_profile_required_and_traced`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T09:59:06Z

- Increment completed: make contactless outcome record resource bounds
  explicit and traceable.
- Research note: full C-8 outcome trace packs remain external certification
  evidence, but repository-controlled outcome construction can prove both data
  record and discretionary data payloads are bounded before callback exposure.
- Code impact: the C-8 outcome model now has a regression proving
  `MAX_C8_DATA_RECORD_LEN` and `MAX_C8_DISCRETIONARY_DATA_LEN` are enforced
  with `LengthOverflow`.
- Evidence updated: current and compatibility RTM annexes cite the contactless
  outcome record-bound regression for `KRN-CLESS-002`, `KRN-C8-001`, and
  `KRN-C8-002`.
- Verification: `cargo test outcome_model_bounds_records_and_alternate_interface_instruction`,
  `cargo test rtm_promotes_contactless_entry_outcome_limit_and_cdcvm_evidence`,
  `cargo test rtm_promotes_c8_kernel_outcome_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T10:04:14Z

- Increment completed: make contactless relay-resistance minimum profile
  fields explicit and traceable.
- Research note: licensed relay-resistance profile data remains external C-8
  certification evidence, but repository-controlled profile validation can
  prove incomplete command APDUs, incomplete success responses, and zero timing
  windows fail closed before runtime use.
- Code impact: C-8 relay-resistance profile validation now has a regression
  proving command APDUs shorter than 4 bytes, success responses shorter than 2
  bytes, and `max_round_trip_ms = 0` return `InvalidProfile`.
- Evidence updated: current and compatibility RTM annexes cite the incomplete
  relay-resistance profile regression for `KRN-CLESS-005`.
- Verification: `cargo test rejects_incomplete_relay_resistance_profiles`,
  `cargo test krn_cless_005_relay_resistance_is_profile_required_and_traced`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T10:12:09Z

- Increment completed: make TRM random-selection sample bounds executable
  and traceable.
- Research note: public EMVCo contactless materials still require licensed C-8
  reconciliation for contactless claims, but this repo-controlled TRM slice
  focuses on the local EMV/profile rule that random-selection parameters must
  be certified and interpreted in the documented basis-point domain.
- Code impact: TRM evaluation now rejects supplied random-selection samples
  above `9999` basis points with `InvalidProfile` instead of silently treating
  them as not selected.
- Evidence updated: current and compatibility RTM annexes cite the random
  sample bound regression for `KRN-TRM-002`.
- Verification: `cargo test rejects_out_of_range_random_selection_sample`,
  `cargo test rtm_promotes_trm_floor_random_and_tsi_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T10:18:09Z

- Increment completed: make short APDU payload bounds explicit and
  traceable.
- Research note: EMV L2 approval evaluates kernel behavior against the EMV
  specifications, so repository-controlled APDU construction evidence should
  prove command builders respect the short APDU one-byte `Lc` domain instead
  of relying on implicit encoder failures.
- Code impact: APDU construction now exposes `MAX_SHORT_APDU_DATA_LEN` and
  rejects oversized command data for raw command encoding, INTERNAL
  AUTHENTICATE, EXTERNAL AUTHENTICATE, and GENERATE AC with `LengthOverflow`.
- Evidence updated: current and compatibility RTM annexes cite the short APDU
  payload-bound regression for `KRN-APDU-001`.
- Verification: `cargo test rejects_command_payloads_above_short_apdu_lc_limit`,
  `cargo test rtm_promotes_apdu_command_construction_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T10:22:28Z

- Increment completed: make direct SELECT AID length bounds explicit and
  traceable.
- Research note: direct AID selection is part of the certified application
  selection path, so repository-controlled APDU construction should reject ADF
  names outside the same 5-16 byte AID domain enforced by profile and directory
  candidate parsing.
- Code impact: APDU construction now exposes shared `MIN_AID_LEN` and
  `MAX_AID_LEN` constants, uses them in both direct SELECT AID construction and
  selection candidate parsing, and rejects too-short direct AID inputs with
  `InvalidArgument`.
- Evidence updated: current and compatibility RTM annexes cite the SELECT AID
  length-domain regression for `KRN-APDU-001`.
- Verification: `cargo test rejects_select_aids_outside_emv_length_domain`,
  `cargo test rtm_promotes_apdu_command_construction_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T10:28:02Z

- Increment completed: make GPO tag `83` PDOL length encoding
  certification-grade at the short-APDU boundary.
- Research note: `docs/spec.md` requires the kernel to build PDOL and send GPO
  after application selection, while the corrected engineering baseline states
  GPO command data is `83 || L || PDOL_values`; repository-controlled evidence
  should therefore prove `L` is BER-TLV encoded rather than a raw byte for
  values above 127 bytes.
- Code impact: GPO construction now encodes tag `83` lengths in BER short form
  for `0..=127` bytes and `0x81 <len>` long form for `128..=252` bytes, and
  exposes the short-APDU PDOL-value ceiling as `MAX_GPO_PDOL_VALUE_LEN`.
- Evidence updated: current and compatibility RTM annexes cite the long-form
  GPO tag `83` boundary regression and PDOL ceiling regression for
  `KRN-APDU-001` and `KRN-DOL-001`.
- Verification: `cargo test builds_gpo_tag_83_with_ber_long_form_length_at_boundary`,
  `cargo test rejects_gpo_pdol_values_above_short_apdu_template_capacity`,
  `cargo test rtm_promotes_apdu_command_construction_evidence`,
  `cargo test rtm_promotes_dol_construction_policy_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check`
  passed.

## 2026-05-22T10:34:43Z

- Increment completed: require GPO template `80` responses to carry both AIP
  and AFL before the kernel accepts them as valid GPO output.
- Research note: `KRN-GPO-002` requires GPO parsing to extract AIP and AFL or
  fail with an explicit missing-mandatory-tag outcome; accepting a two-byte
  template `80` body created an internal contradiction between runtime behavior
  and the repository-controlled certification baseline.
- Code impact: template `80` parsing now rejects AIP-only bodies with
  `MissingMandatoryTag` and always parses the remaining bytes as AFL, preserving
  valid template `80` coverage with an AIP-plus-AFL fixture.
- Evidence updated: current and compatibility RTM annexes now cite
  `gpo::tests::parses_gpo_template_80_with_aip_and_afl` as valid template `80`
  evidence, while GPO missing-mandatory regressions prove AIP-only template `80`
  bodies fail closed.
- Verification: `cargo test parses_gpo_template_80_with_aip_and_afl`,
  `cargo test rejects_gpo_without_mandatory_aip_afl`,
  `cargo test rtm_promotes_gpo_and_read_record_evidence`,
  `cargo test krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T10:41:14Z

- Increment completed: fail closed on malformed dynamic-authentication data in
  GENERATE AC format 2 responses.
- Research note: CDA evidence depends on treating `9F4B` as signed dynamic
  application data before CDA verification, and `9F4C` as an ICC dynamic number
  only when it is actually present. Accepting undersized signatures or empty
  dynamic-number TLVs lets malformed authentication material flow into card
  data and later ODA/CDA phases.
- Code impact: `parse_generate_ac_response` now rejects format 2 responses with
  a present-but-too-short `9F4B` using `InvalidProfile` and rejects empty `9F4C`
  using `ParseError`, while preserving valid format 2 parsing and existing CDA
  verification paths.
- Evidence updated: current and compatibility RTM annexes cite
  `gac::tests::rejects_malformed_dynamic_authentication_data_in_gac_response`
  for `KRN-GAC-004`, `KRN-GAC1-004`, `KRN-GAC1-005`, and `KRN-ODA-008`.
- Verification: `cargo test rejects_malformed_dynamic_authentication_data_in_gac_response`,
  `cargo test parses_generate_ac_format_2_template_77`,
  `cargo test rtm_promotes_gac_cdol_encoding_and_response_evidence`,
  `cargo test rtm_promotes_oda_capk_tvr_cda_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T10:47:07Z

- Increment completed: reject nested issuer script templates instead of
  silently treating malformed host script data as absent.
- Research note: `KRN-SCR-001` requires issuer script template structure to be
  validated. A host response that wraps `71` or `72` under another TLV must not
  parse successfully and drop the script, because that can skip issuer script
  execution while preserving an apparently successful host-response parse.
- Code impact: the host-response structural rejection pass now rejects nested
  issuer script templates (`71` and `72`) in the same recursive pass that
  already rejects nested authorization response code and issuer authentication
  objects.
- Evidence updated: `issuer::tests::rejects_nested_or_duplicate_issuer_script_objects`
  now proves nested pre-final and post-final script templates fail closed, and
  existing RTM guards keep that evidence attached to `KRN-SCR-001`.
- Verification: `cargo test rejects_nested_or_duplicate_issuer_script_objects`,
  `cargo test rtm_promotes_issuer_script_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:02:04Z

- Increment completed: preserve issuer-script warning continuation semantics
  even when the active profile marks the script command INS as critical.
- Research note: public EMV Book 3 excerpts describe issuer-script warning
  status words (`62xx` and `63xx`) as continuation conditions. The kernel
  should still record SW1/SW2 and set script-processing evidence bits, but it
  must not turn those warnings into a critical abort before later commands in
  the same script are attempted.
- Code impact: issuer-script status classification now distinguishes warning
  continuation from non-critical error continuation. Critical script commands
  still fail closed on error statuses, while `62xx`/`63xx` warning statuses
  continue through the ordered script command list.
- Evidence updated: `ffi::tests::critical_issuer_script_warning_continues_and_reports_results`
  proves warning results for critical post-final script commands are captured,
  the second command is still transmitted, TVR/TSI are persisted, and the FSM
  reaches final outcome instead of `SE`. The state-machine annex and both RTM
  CSVs cite the warning-continuation behavior.
- Verification: `cargo test critical_issuer_script_warning_continues_and_reports_results`,
  `cargo test verify_and_script_status_words_keep_their_own_meaning`,
  `cargo test rtm_promotes_issuer_script_evidence`,
  `cargo test validates_machine_readable_state_annex`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:11:03Z

- Increment completed: honor CVM condition code `0x03` by checking whether the
  terminal supports the candidate CVM method before selecting the rule.
- Research note: public CVM condition-code references describe condition
  `0x03` as terminal support for the candidate CVM, so rule matching must use
  the CVM method's own capability instead of skipping the rule or treating the
  condition as globally true.
- Code impact: `condition_matches` now delegates condition `0x03` to
  `terminal_supports_method`, which uses the existing offline PIN, online PIN,
  signature, and contactless interface context without widening the ABI.
- Evidence updated: `cvm::tests::terminal_support_condition_matches_candidate_cvm_capability`
  proves online PIN and signature rules guarded by condition `0x03` follow the
  candidate capability, and both RTM CSVs cite it for `KRN-CVM-001` and
  `KRN-CVMCAP-001`.
- Verification: `cargo test terminal_support_condition_matches_candidate_cvm_capability`,
  `cargo test rtm_promotes_cvm_outcome_evidence`,
  `cargo test rtm_promotes_cvm_pin_capability_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:18:58Z

- Increment completed: implement CVM transaction-type condition codes `0x01`,
  `0x02`, `0x04`, and `0x05` for unattended cash, non-cash, manual cash, and
  purchase-with-cashback rule selection.
- Research note: public EMV CVM condition-code references identify these
  transaction predicates as separate branches from amount and terminal-support
  predicates, so the evaluator must not treat them as unsupported conditions.
- Code impact: `CvmContext` now carries a `CvmTransactionType` derived from the
  existing runtime transaction type and terminal type inputs; the C ABI remains
  unchanged.
- Evidence updated: `cvm::tests::transaction_type_conditions_select_only_matching_rules`
  proves the evaluator selects only matching transaction-condition rules, while
  `ffi::tests::cvm_transaction_type_uses_terminal_and_transaction_tags` proves
  the runtime maps existing transaction parameters into those CVM predicates.
  Both RTM CSVs cite the new evidence under `KRN-CVM-001`.
- Verification: `cargo test transaction_type_conditions_select_only_matching_rules`,
  `cargo test cvm_transaction_type_uses_terminal_and_transaction_tags`,
  `cargo test rtm_promotes_cvm_outcome_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:27:28Z

- Increment completed: persist the EMV TVR unrecognized-CVM bit when a matching
  CVM rule uses an unknown method code.
- Research note: public EMV TVR/CVM references identify unrecognized CVM as a
  distinct byte-3 TVR condition. Continuing to a later successful CVM must not
  erase that evidence from the transaction TVR.
- Code impact: `CvmOutcome::Selected` now carries an optional TVR bit so CVM
  evaluation can report non-fatal unrecognized-CVM evidence while still
  selecting a later rule; `run_cvm_processing` persists that bit into TVR/tag
  `95` before storing CVM Results.
- Evidence updated: `cvm::tests::unrecognized_cvm_sets_tvr_even_when_next_rule_succeeds`
  covers both continued success and terminal failure for unknown CVM codes, and
  `ffi::tests::cvm_processing_persists_unrecognized_tvr_on_later_success`
  proves the runtime persists `B3_UNRECOGNIZED_CVM` alongside successful online
  PIN evidence. Both RTM CSVs cite the new tests under `KRN-CVM-002`.
- Verification: `cargo test unrecognized_cvm_sets_tvr_even_when_next_rule_succeeds`,
  `cargo test cvm_processing_persists_unrecognized_tvr_on_later_success`,
  `cargo test rtm_promotes_cvm_outcome_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:34:45Z

- Increment completed: preserve specific PIN-CVM TVR evidence when PIN CVMs
  cannot execute.
- Research note: public TVR references identify separate byte-3 bits for PIN
  pad unavailable and PIN required but not entered. Collapsing those paths into
  generic cardholder-verification failure weakens the TAA evidence model.
- Code impact: CVM evaluation now reports `B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING`
  when an offline PIN rule matches but no offline PIN facility is available,
  and `B3_PIN_NOT_ENTERED` when the facility is available but no PED-owned PIN
  handle is supplied. Continue-on-failure preserves the specific PIN TVR bit
  for a later successful CVM.
- Evidence updated: `cvm::tests::pin_cvm_unavailable_sets_specific_tvr_bits`
  covers direct evaluator failures for both PIN cases, and
  `ffi::tests::cvm_processing_persists_missing_pin_pad_tvr_on_later_success`
  proves runtime tag `95` preserves PIN-pad evidence alongside a later online
  PIN success. Both RTM CSVs cite the evidence under `KRN-CVM-002`.
- Verification: `cargo test pin_cvm_unavailable_sets_specific_tvr_bits`,
  `cargo test cvm_processing_persists_missing_pin_pad_tvr_on_later_success`,
  `cargo test continue_on_failure_skips_to_next_matching_cvm_rule`,
  `cargo test rtm_promotes_cvm_outcome_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:42:06Z

- Increment completed: separate offline PIN facility capability from
  PED-owned offline PIN handles in the stable FFI surface.
- Code impact: added an additive `krn_set_offline_pin_capability` ABI setter
  while preserving the existing `krn_set_cvm_capabilities` signature. Runtime
  CVM processing now treats offline PIN as supported when either the declared
  facility flag is set or a method-specific PED handle is present.
- Evidence updated: `ffi::tests::offline_pin_capability_is_separate_from_ped_handle`
  proves the new setter is boolean-validated and call-order safe with the
  existing CVM capability setter. `ffi::tests::cvm_processing_persists_pin_not_entered_tvr_when_handle_missing`
  proves a terminal with offline PIN capability but no entered PIN preserves
  `B3_PIN_NOT_ENTERED` in tag `95` while a later online PIN succeeds. Both RTM
  CSVs cite the evidence under `KRN-CVMCAP-001` and `KRN-CVM-002`.
- Verification: `cargo fmt`,
  `cargo test offline_pin_capability_is_separate_from_ped_handle`,
  `cargo test cvm_processing_persists_pin_not_entered_tvr_when_handle_missing`,
  `cargo test rtm_promotes_cvm_outcome_evidence`, and
  `cargo test rtm_promotes_cvm_pin_capability_evidence`, `cargo fmt --check`,
  `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T11:53:49Z

- Increment completed: resolve APDU transport follow-ups across core runtime
  commands instead of only SELECT, internal-authenticate, scripts, and final
  GENERATE AC.
- Code impact: READ RECORD, GPO, first GENERATE AC, and EXTERNAL AUTHENTICATE
  now use the bounded `transmit_apdu_with_followups` path, so `61xx` GET
  RESPONSE and `6Cxx` Le retry handling occurs before command-specific parser
  and status-word logic. The `krn_run_transaction` API comment now reflects
  the current callback-driven runner instead of the old future-runner caveat.
- Evidence updated: `ffi::tests::runtime_core_flow_resolves_gpo_record_and_gac_followups`
  proves a full transaction resolves GPO GET RESPONSE, READ RECORD GET
  RESPONSE, and GENERATE AC Le retry follow-ups before reaching online handoff.
  `ffi::tests::issuer_authentication_resolves_get_response_followup` proves
  EXTERNAL AUTHENTICATE GET RESPONSE handling reaches issuer-script processing
  without setting issuer-authentication-failed TVR evidence. Both RTM CSVs cite
  the new tests under APDU status/follow-up and issuer-authentication rows.
- Verification: `cargo fmt`,
  `cargo test runtime_core_flow_resolves_gpo_record_and_gac_followups`,
  `cargo test issuer_authentication_resolves_get_response_followup`,
  `cargo test rtm_promotes_apdu_status_word_evidence`,
  `cargo test rtm_promotes_runtime_apdu_selection_status_policy_evidence`, and
  `cargo test rtm_promotes_issuer_authentication_and_final_gac_evidence`
  passed. `cargo fmt --check`, `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` also
  passed.

## 2026-05-22T19:26:34Z

- Increment completed: add explicit masked host-response TLV stream evidence
  to the repository-controlled pre-lab trace pack.
- Research note: APDU replay suppression proves command payload custody, but
  issuer host-response data enters through the Level 3 boundary. The pre-lab
  fixture now carries a distinct TLV-stream record proving tag-level masking
  for issuer authentication data and issuer script data without treating it as
  card APDU replay.
- Code impact: added `TlvStreamTrace` and `mask_tlv_stream_trace` to the trace
  layer, reused the existing masked-field JSON emitter for APDU and TLV-stream
  evidence, and taught `krn_prelab_trace_pack` to emit one host-response stream
  for the issuer-authentication/script case.
- Evidence updated: `docs/prelab_apdu_trace_pack.jsonl` now includes
  `expected_tlv_stream_count` per scenario and one `tlv-stream` line for tag
  `91`, template `71`, tag `9F18`, and tag `86`. The traceability test checks
  those suppression reasons and rejects raw issuer-authentication bytes,
  issuer-script command APDU bytes, and issuer-script identifier bytes. The lab
  manifest now calls out the masked host-response TLV evidence while leaving
  full lab/test-tool traces open.
- Verification: `cargo fmt`,
  `cargo test trace::tests::production_suppresses_issuer_script_command_data`,
  `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`,
  `cargo test --example krn_prelab_trace_pack`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T12:02:44Z

- Increment completed: broaden the repository-controlled pre-lab APDU trace
  fixture without claiming it closes the full lab trace-pack requirement.
- Code impact: `examples/krn_prelab_trace_pack.rs` now emits a deterministic
  three-case masked JSONL fixture covering the existing PAN/GENERATE AC
  masking case, issuer-authentication/script status evidence, and APDU
  follow-up status evidence for `61xx` GET RESPONSE and `6Cxx` Le retry paths.
- Evidence updated: `docs/prelab_apdu_trace_pack.jsonl` now carries the three
  case IDs while retaining `does_not_close = CERT-OPEN-012`. The lab manifest
  describes the broader local fixture but keeps full lab/test-tool traces open.
  Both RTM CSVs cite `prelab_apdu_trace_pack_is_replayable_masked_and_scoped`
  under deterministic replay, trace identity, and production logging evidence.
- Verification: `cargo fmt`,
  `cargo test prelab_apdu_trace_pack_is_replayable_masked_and_scoped`,
  `cargo test rtm_promotes_fsm_annex_replay_and_error_transition_evidence`,
  `cargo test rtm_promotes_logging_policy_evidence`,
  `cargo test rtm_promotes_deployment_profile_update_evidence`, and
  `cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -`
  passed. `cargo fmt --check`, `cargo test`, `cargo test --examples`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` also
  passed.

## 2026-05-22T19:35:02Z

- Increment completed: harden reproducible build provenance so artifact names
  are canonical repository-relative paths.
- Research note: the lab submission manifest is part of the evidence chain, so
  its artifact names must be unambiguous before a lab or reviewer compares
  hashes. Accepting absolute paths, parent traversal, current-directory
  segments, or doubled separators would make the same file set appear under
  multiple names and weaken reproducibility.
- Code impact: `build_provenance_manifest` now rejects absolute artifact names,
  `.` or `..` path segments, empty path segments, and existing invalid
  characters before digesting artifacts. The manifest text now states that
  build provenance uses controlled relative artifact names.
- Evidence updated: `provenance_manifest_rejects_ambiguous_artifact_names`
  covers the rejected path forms, both RTM CSV annexes cite it under
  `KRN-CERT-001`, and the traceability tests require that citation plus the
  manifest wording.
- Verification: `cargo fmt`,
  `cargo test provenance_manifest_rejects_ambiguous_artifact_names`,
  `cargo test lab_manifest_and_provenance_cover_reproducible_build_artifacts`,
  `cargo test rtm_external_lab_gates_are_explicit`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T19:42:33Z

- Increment completed: reject all-`FF` unpredictable numbers from the platform
  RNG callback in addition to all-zero and repeated outputs.
- Research note: the unpredictable number feeds DOL construction and online
  cryptogram requests. A callback that returns a sentinel all-`FF` value is a
  weak platform failure mode, not usable transaction entropy, so the kernel now
  fails closed with the same stable RNG error path used for all-zero and
  repeated outputs.
- Code impact: `request_unpredictable_number` rejects all-`FF` four-byte
  outputs before storing tag `9F37`. The FFI traceability test now exercises
  all-zero, all-`FF`, repeated, and accepted callback outputs through
  `krn_run_transaction`.
- Evidence updated: both RTM CSV annexes now define `KRN-RNG-002` as rejecting
  all-zero, all-`FF`, or repeated unpredictable numbers, and
  `rtm_promotes_rng_callback_evidence` enforces that wording.
- Verification: `cargo fmt`,
  `cargo test krn_rng_001_002_rejects_zero_and_repeated_unpredictable_numbers`,
  `cargo test rtm_promotes_rng_callback_evidence`, `cargo test`,
  `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T19:51:31Z

- Increment completed: reject inconsistent signed-profile CDA controls before
  runtime transaction processing.
- Research note: CDA request control is profile-defined. A certification-shaped
  profile that claims CDA support without an encoding, or carries an encoding
  while disabling CDA, is ambiguous and should fail at profile load rather than
  degrade to runtime inference.
- Code impact: `parse_aid` now requires `cda_supported` to match the presence
  of `cda_request_encoding`; inconsistent pairs return `InvalidProfile`.
  Existing profile fixtures were updated to keep tests focused on their target
  concerns.
- Evidence updated: `rejects_inconsistent_cda_profile_controls` covers missing
  and stale CDA controls,
  `krn_gac_010_cda_request_is_profile_defined_or_unsupported` now expects loader
  rejection for missing encoding, and both RTM CSVs cite the new config evidence
  under `KRN-GAC-009` and `KRN-GAC-010`.
- Verification: `cargo fmt`,
  `cargo test rejects_inconsistent_cda_profile_controls`,
  `cargo test krn_gac_010_cda_request_is_profile_defined_or_unsupported`,
  `cargo test rtm_promotes_legacy_gac_cda_control_evidence`,
  `cargo test rejects_example_profile_in_certification_or_production_mode`,
  `cargo test capk_lookup_requires_verified_integrity_and_unexpired_key`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T20:00:23Z

- Increment completed: extend the masked pre-lab decode tool to parse GENERATE
  AC responses through Hyperion's own GAC parser.
- Research note: the open-source reference review identifies tool-first EMV
  trace triage as a useful pattern to adapt without importing external code.
  This change applies that pattern to returned cryptogram evidence while keeping
  cryptograms, issuer application data, ICC dynamic numbers, and signed dynamic
  application data suppressed by default.
- Code impact: `krn_emv_decode` now accepts `gac` /
  `generate-ac-response`, reports response format, CID classification, and
  value lengths, and maps malformed unwrapped response data through stable
  kernel error names.
- Evidence updated: `gac_response_output_parses_without_exposing_values`,
  `gac_response_output_rejects_unwrapped_response_data`, and
  `cli_routes_gac_mode` cover the new decode path. Both RTM CSVs cite the
  masked decode evidence under `KRN-GAC-004` and `KRN-GAC1-004`, and
  `rtm_promotes_gac_cdol_encoding_and_response_evidence` now guards those
  citations. The open-source adaptation backlog now names GENERATE AC response
  decoding as covered by the decode tool.
- Verification: `cargo fmt`,
  `cargo test --example krn_emv_decode gac_response_output_parses_without_exposing_values`,
  `cargo test --example krn_emv_decode gac_response_output_rejects_unwrapped_response_data`,
  `cargo test --example krn_emv_decode cli_routes_gac_mode`,
  `cargo test rtm_promotes_gac_cdol_encoding_and_response_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.

## 2026-05-22T20:10:50Z

- Increment completed: retain every eligible card ADF name that matches a
  partial signed-profile AID during PSE/PPSE candidate matching.
- Research note: public standards drift was rechecked against official EMVCo
  and PCI SSC sources before selecting this slice; the standards-watch annex
  already guards the current public C-8 and PCI PTS boundary. The runtime gap
  addressed here is repository-controlled: partial-selection matching must not
  silently drop card applications that share the same certified profile prefix.
- Code impact: `match_profile_candidates` now rejects duplicate card candidate
  inputs before profile matching, emits one `SelectionCandidate` per matching
  card ADF/profile pair, and preserves deterministic ordering through the
  existing candidate sorter. The final SELECT AID remains the full card ADF
  name while the signed profile AID continues to identify the certified rule
  set.
- Evidence updated:
  `partial_selection_retains_all_matching_card_adf_names` covers multi-ADF
  partial matches, `rejects_duplicate_card_candidates_before_profile_matching`
  covers defensive duplicate rejection, and
  `krn_sel_001_002_003_parses_candidates_and_matches_signed_profiles` now
  checks the traceability-level multi-candidate case. Both RTM CSVs cite the new
  selection evidence under `KRN-SEL-001` and `KRN-SEL-002`.
- Verification: `cargo fmt`,
  `cargo test partial_selection_retains_all_matching_card_adf_names`,
  `cargo test rejects_duplicate_card_candidates_before_profile_matching`,
  `cargo test krn_sel_001_002_003_parses_candidates_and_matches_signed_profiles`,
  `cargo test rtm_promotes_runtime_apdu_selection_status_policy_evidence`,
  `cargo test`, `cargo test --examples`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `git diff --check` passed.
