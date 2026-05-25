# Hyperion Certification Freeze Manifest

- Kernel version: 0.1.0
- ABI version: 2
- Checked on: 2026-05-23
- Scope: submitted-build hash slots for certification freeze and lab package assembly
- Source of truth: `docs/lab_submission_manifest.md` and `docs/certification_open_issues.md`
- Boundary: this manifest does not close any `CERT-OPEN-*` issue.

## Freeze Policy
- Every submitted artifact must have a SHA-256 digest before certification-facing review.
- The submitted binary, signed profiles, CAPKs, vectors, RTM, reports, traces, and approval package must name the same product scope.
- A changed artifact hash requires a new freeze review and supersedes the prior package by recorded reason.
- The freeze manifest is a binding template only and cannot close external certification blockers by itself.

## Required Freeze Artifacts
| ID | Title | Kind | Binds Open Issues | Required Metadata | Evidence Source | Required Hash | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| kernel_binary_hash | Submitted kernel binary | build artifact | CERT-OPEN-001, CERT-OPEN-006, CERT-OPEN-009, CERT-OPEN-011, CERT-OPEN-012 | target_triple, build_profile, cargo_version, rustc_version, abi_version | release build pipeline artifact digest accepted for the lab submission | SHA-256 pending | pending external certification freeze |
| config_bundle_hash | Signed runtime configuration bundle | signed configuration | CERT-OPEN-002, CERT-OPEN-005, CERT-OPEN-009, CERT-OPEN-012 | profile_version, signature_status, rollback_counter, retrieval_date | signed configuration package digest tied to the submitted binary | SHA-256 pending | pending external certification freeze |
| capk_bundle_hash | Scheme/acquirer-approved CAPK bundle | public key material | CERT-OPEN-003, CERT-OPEN-004, CERT-OPEN-009 | capk_source, retrieval_date, expiry_set, checksum_set, approval_reference | accepted CAPK package digest with signed provenance | SHA-256 pending | pending external certification freeze |
| scheme_profile_hash | Scheme/acquirer-approved profile bundle | scheme profile | CERT-OPEN-002, CERT-OPEN-005, CERT-OPEN-009, CERT-OPEN-012 | authority, scheme_set, aid_set, kernel_mapping, profile_signature | accepted scheme profile package digest with profile authority evidence | SHA-256 pending | pending external certification freeze |
| test_vector_hash | Lab-supplied ODA and APDU test-vector bundle | test vectors | CERT-OPEN-004, CERT-OPEN-009, CERT-OPEN-012 | vector_class, tool_version, method_coverage, expected_outputs, bundle_authority | recognized-lab vector and trace-pack digest | SHA-256 pending | pending external certification freeze |
| trace_pack_hash | Full masked APDU and outcome trace pack | trace pack | CERT-OPEN-009, CERT-OPEN-012 | trace_pack_hash, test_tool_version, lab_case_ids, profile_hash, submitted_binary_hash | recognized-lab or accepted test-tool masked trace-pack digest | SHA-256 pending | pending external certification freeze |
| traceability_matrix_hash | Final RTM and lab/tool crosswalk | traceability | CERT-OPEN-001, CERT-OPEN-009, CERT-OPEN-011, CERT-OPEN-012 | rtm_version, test_tool_package, lab_case_ids, deviation_list, reviewer | final RTM digest after lab test-case ID reconciliation | SHA-256 pending | pending external certification freeze |
| coverage_report_hash | Accepted 100% coverage report package | quality report | CERT-OPEN-009 | source_commit, coverage_tool_version, coverage_enforced, target_triple, feature_set | accepted coverage report and metadata package digest | SHA-256 pending | pending external certification freeze |
| static_fuzz_report_hash | Accepted static-analysis and fuzzing report package | quality report | CERT-OPEN-010 | tool_versions, commands, sanitizer_set, corpus_hashes, run_budget, finding_dispositions | accepted static-analysis and fuzzing report package digest | SHA-256 pending | pending external certification freeze |
| approval_package_hash | Signed approval and conformance package | approval artifact | CERT-OPEN-001, CERT-OPEN-011 | signer, signature_date, template_version, claimed_scope, approval_reference | recognized authority signed approval package digest | SHA-256 pending | pending external certification freeze |
