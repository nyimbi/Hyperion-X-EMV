# Hyperion Integration Report Evidence Plan

- Kernel version: 0.1.0
- ABI version: 2
- Checked on: 2026-05-24
- Scope: full integration report and masked APDU trace-pack evidence plan
- Boundary: this plan does not close `CERT-OPEN-009` or `CERT-OPEN-012`; pending external coverage, full EMV integration, Level 3/acquirer, and full trace-pack reports are still required.

## Required Metadata
| Field | Requirement |
| --- | --- |
| submitted_binary_hash | SHA-256 of the exact kernel binary used for the integration run |
| profile_bundle_hash | SHA-256 of the signed profile and configuration bundle under test |
| capk_bundle_hash | SHA-256 of the approved CAPK bundle under test |
| test_tool_version | recognized lab, scheme, acquirer, or submission-owner test-tool package version |
| lab_case_id | accepted lab or test-tool case identifier mapped to repository RTM rows |
| acquirer_case_id | Level 3 or acquirer case identifier where the accepted test plan requires it |
| level3_bulletin_set | Level 3, acquirer, and public-bulletin reconciliation notes selected for the submitted scope |
| trace_pack_hash | SHA-256 of the full masked APDU trace pack tied to case ordering and submitted build identity |
| expected_outcome | expected cryptogram type, TVR/TSI, SW1/SW2, issuer-script result, and final outcome |
| actual_outcome | observed cryptogram type, TVR/TSI, SW1/SW2, issuer-script result, and final outcome |
| deviation_disposition | accepted deviation, remediation, retest evidence, or rejection for every mismatch |

## Evidence Requirements
| ID | Area | Open Issues | Authority | Required Attachment | Required Metadata | Repository Support | Acceptance Gate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| INTEGRATION-TEST-SCOPE | accepted test-plan scope | CERT-OPEN-009, CERT-OPEN-012 | recognized laboratory, scheme, acquirer, or submission owner | test-plan scope statement naming L2, L3/acquirer, contact, contactless, and excluded case families | test_tool_version, lab_case_id, acquirer_case_id, level3_bulletin_set, interface_scope | docs/requirements_traceability.csv, docs/certification_open_issues.md, docs/public_standards_watch.json | test scope must match the submitted kernel, device, profile, interface, and public/licensed bulletin reconciliation set |
| INTEGRATION-L2-EXECUTION | EMV Level 2 execution report | CERT-OPEN-009 | recognized laboratory, scheme, or accepted submission owner | complete L2 execution report with pass/fail results, environment, tool version, and deviation list | submitted_binary_hash, profile_bundle_hash, capk_bundle_hash, test_tool_version, lab_case_id | cargo test, cargo test --examples, docs/prelab_quality_gates.json | every applicable L2 case must be executed or formally excluded with authority-approved rationale |
| INTEGRATION-L3-ACQUIRER | Level 3 and acquirer reconciliation | CERT-OPEN-009, CERT-OPEN-012 | acquirer, processor, scheme, or Level 3 test authority | Level 3/acquirer bulletin reconciliation and host-message outcome report for the accepted test plan | acquirer_case_id, level3_bulletin_set, test_tool_version, expected_outcome, actual_outcome | docs/public_standards_watch.json, examples/krn_basic_pos.rs, examples/krn_basic_softpos.rs, src/gac.rs | L3/acquirer results must agree with host handoff data, authorization response handling, and final outcome traces |
| INTEGRATION-TRACE-COVERAGE | full masked APDU trace coverage | CERT-OPEN-012 | recognized laboratory, scheme, acquirer, or accepted test-tool owner | full masked APDU trace pack for every applicable case in accepted execution order | trace_pack_hash, lab_case_id, acquirer_case_id, submitted_binary_hash, profile_bundle_hash | docs/prelab_apdu_trace_pack.jsonl, src/trace.rs, examples/krn_prelab_trace_pack.rs | trace pack must be replayable, masked, complete for the claimed cases, and bound to the submitted binary/profile identity |
| INTEGRATION-OUTCOME-MAPPING | case outcome and transaction evidence | CERT-OPEN-009, CERT-OPEN-012 | laboratory, scheme, acquirer, or submission owner | case-level expected-versus-actual outcome matrix covering TVR, TSI, CID, SW1/SW2, issuer scripts, and final outcome | lab_case_id, expected_outcome, actual_outcome, deviation_disposition, trace_pack_hash | docs/bitmap_catalogue.csv, src/cid.rs, src/issuer.rs, src/sw.rs | every mismatch must have a recorded disposition, remediation, retest, or accepted exclusion |
| INTEGRATION-DEVIATION-DISPOSITION | deviation and retest governance | CERT-OPEN-009, CERT-OPEN-012 | laboratory, scheme, acquirer, or submission owner | deviation register with owner, severity, remediation, retest evidence, residual-risk acceptance, and supersession history | lab_case_id, acquirer_case_id, deviation_disposition, submitted_binary_hash, trace_pack_hash | docs/certification_evidence_intake.json, docs/certification_freeze_manifest.json, docs/certification_report_pack.json | no unresolved unacceptable deviation may remain before a certification-facing release is submitted |
| INTEGRATION-BUILD-BINDING | submitted-build and report binding | CERT-OPEN-009, CERT-OPEN-012 | laboratory, acquirer, and submission owner | hash bundle tying integration report, trace pack, RTM, device evidence, profiles, CAPKs, and binary together | submitted_binary_hash, profile_bundle_hash, capk_bundle_hash, trace_pack_hash, test_tool_version | docs/certification_freeze_manifest.json, examples/krn_build_manifest.rs, docs/certification_device_evidence_plan.json | report hashes must agree with freeze-manifest hashes and the device/profile scope under submission |
