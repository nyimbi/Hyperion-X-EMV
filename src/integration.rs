//! Integration-report and lab trace-pack evidence plan generation.
//!
//! The generated plan is an attachment-control surface for `CERT-OPEN-009`
//! and `CERT-OPEN-012`. It records the report metadata, test-case mapping,
//! trace coverage, Level 3/acquirer reconciliation, and submitted-build binding
//! that must exist before a full integration report or APDU trace pack can be
//! reviewed as certification-facing evidence.

use core::fmt::Write;

pub struct IntegrationReportRequirement {
    pub id: &'static str,
    pub area: &'static str,
    pub open_issues: &'static [&'static str],
    pub authority: &'static str,
    pub required_attachment: &'static str,
    pub required_metadata: &'static [&'static str],
    pub repository_support: &'static [&'static str],
    pub acceptance_gate: &'static str,
}

pub struct IntegrationReportMetadata {
    pub field: &'static str,
    pub requirement: &'static str,
}

const INTEGRATION_REPORT_METADATA: &[IntegrationReportMetadata] = &[
    IntegrationReportMetadata {
        field: "submitted_binary_hash",
        requirement: "SHA-256 of the exact kernel binary used for the integration run",
    },
    IntegrationReportMetadata {
        field: "profile_bundle_hash",
        requirement: "SHA-256 of the signed profile and configuration bundle under test",
    },
    IntegrationReportMetadata {
        field: "capk_bundle_hash",
        requirement: "SHA-256 of the approved CAPK bundle under test",
    },
    IntegrationReportMetadata {
        field: "test_tool_version",
        requirement: "recognized lab, scheme, acquirer, or submission-owner test-tool package version",
    },
    IntegrationReportMetadata {
        field: "lab_case_id",
        requirement: "accepted lab or test-tool case identifier mapped to repository RTM rows",
    },
    IntegrationReportMetadata {
        field: "acquirer_case_id",
        requirement: "Level 3 or acquirer case identifier where the accepted test plan requires it",
    },
    IntegrationReportMetadata {
        field: "level3_bulletin_set",
        requirement: "Level 3, acquirer, and public-bulletin reconciliation notes selected for the submitted scope",
    },
    IntegrationReportMetadata {
        field: "trace_pack_hash",
        requirement: "SHA-256 of the full masked APDU trace pack tied to case ordering and submitted build identity",
    },
    IntegrationReportMetadata {
        field: "expected_outcome",
        requirement: "expected cryptogram type, TVR/TSI, SW1/SW2, issuer-script result, and final outcome",
    },
    IntegrationReportMetadata {
        field: "actual_outcome",
        requirement: "observed cryptogram type, TVR/TSI, SW1/SW2, issuer-script result, and final outcome",
    },
    IntegrationReportMetadata {
        field: "deviation_disposition",
        requirement: "accepted deviation, remediation, retest evidence, or rejection for every mismatch",
    },
];

const INTEGRATION_REPORT_REQUIREMENTS: &[IntegrationReportRequirement] = &[
    IntegrationReportRequirement {
        id: "INTEGRATION-TEST-SCOPE",
        area: "accepted test-plan scope",
        open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
        authority: "recognized laboratory, scheme, acquirer, or submission owner",
        required_attachment:
            "test-plan scope statement naming L2, L3/acquirer, contact, contactless, and excluded case families",
        required_metadata: &[
            "test_tool_version",
            "lab_case_id",
            "acquirer_case_id",
            "level3_bulletin_set",
            "interface_scope",
        ],
        repository_support: &[
            "docs/requirements_traceability.csv",
            "docs/certification_open_issues.md",
            "docs/public_standards_watch.json",
        ],
        acceptance_gate:
            "test scope must match the submitted kernel, device, profile, interface, and public/licensed bulletin reconciliation set",
    },
    IntegrationReportRequirement {
        id: "INTEGRATION-L2-EXECUTION",
        area: "EMV Level 2 execution report",
        open_issues: &["CERT-OPEN-009"],
        authority: "recognized laboratory, scheme, or accepted submission owner",
        required_attachment:
            "complete L2 execution report with pass/fail results, environment, tool version, and deviation list",
        required_metadata: &[
            "submitted_binary_hash",
            "profile_bundle_hash",
            "capk_bundle_hash",
            "test_tool_version",
            "lab_case_id",
        ],
        repository_support: &[
            "cargo test",
            "cargo test --examples",
            "docs/prelab_quality_gates.json",
        ],
        acceptance_gate:
            "every applicable L2 case must be executed or formally excluded with authority-approved rationale",
    },
    IntegrationReportRequirement {
        id: "INTEGRATION-L3-ACQUIRER",
        area: "Level 3 and acquirer reconciliation",
        open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
        authority: "acquirer, processor, scheme, or Level 3 test authority",
        required_attachment:
            "Level 3/acquirer bulletin reconciliation and host-message outcome report for the accepted test plan",
        required_metadata: &[
            "acquirer_case_id",
            "level3_bulletin_set",
            "test_tool_version",
            "expected_outcome",
            "actual_outcome",
        ],
        repository_support: &[
            "docs/public_standards_watch.json",
            "examples/krn_basic_pos.rs",
            "examples/krn_basic_softpos.rs",
            "src/gac.rs",
        ],
        acceptance_gate:
            "L3/acquirer results must agree with host handoff data, authorization response handling, and final outcome traces",
    },
    IntegrationReportRequirement {
        id: "INTEGRATION-TRACE-COVERAGE",
        area: "full masked APDU trace coverage",
        open_issues: &["CERT-OPEN-012"],
        authority: "recognized laboratory, scheme, acquirer, or accepted test-tool owner",
        required_attachment:
            "full masked APDU trace pack for every applicable case in accepted execution order",
        required_metadata: &[
            "trace_pack_hash",
            "lab_case_id",
            "acquirer_case_id",
            "submitted_binary_hash",
            "profile_bundle_hash",
        ],
        repository_support: &[
            "docs/prelab_apdu_trace_pack.jsonl",
            "src/trace.rs",
            "examples/krn_prelab_trace_pack.rs",
        ],
        acceptance_gate:
            "trace pack must be replayable, masked, complete for the claimed cases, and bound to the submitted binary/profile identity",
    },
    IntegrationReportRequirement {
        id: "INTEGRATION-OUTCOME-MAPPING",
        area: "case outcome and transaction evidence",
        open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
        authority: "laboratory, scheme, acquirer, or submission owner",
        required_attachment:
            "case-level expected-versus-actual outcome matrix covering TVR, TSI, CID, SW1/SW2, issuer scripts, and final outcome",
        required_metadata: &[
            "lab_case_id",
            "expected_outcome",
            "actual_outcome",
            "deviation_disposition",
            "trace_pack_hash",
        ],
        repository_support: &[
            "docs/bitmap_catalogue.csv",
            "src/cid.rs",
            "src/issuer.rs",
            "src/sw.rs",
        ],
        acceptance_gate:
            "every mismatch must have a recorded disposition, remediation, retest, or accepted exclusion",
    },
    IntegrationReportRequirement {
        id: "INTEGRATION-DEVIATION-DISPOSITION",
        area: "deviation and retest governance",
        open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
        authority: "laboratory, scheme, acquirer, or submission owner",
        required_attachment:
            "deviation register with owner, severity, remediation, retest evidence, residual-risk acceptance, and supersession history",
        required_metadata: &[
            "lab_case_id",
            "acquirer_case_id",
            "deviation_disposition",
            "submitted_binary_hash",
            "trace_pack_hash",
        ],
        repository_support: &[
            "docs/certification_evidence_intake.json",
            "docs/certification_freeze_manifest.json",
            "docs/certification_report_pack.json",
        ],
        acceptance_gate:
            "no unresolved unacceptable deviation may remain before a certification-facing release is submitted",
    },
    IntegrationReportRequirement {
        id: "INTEGRATION-BUILD-BINDING",
        area: "submitted-build and report binding",
        open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
        authority: "laboratory, acquirer, and submission owner",
        required_attachment:
            "hash bundle tying integration report, trace pack, RTM, device evidence, profiles, CAPKs, and binary together",
        required_metadata: &[
            "submitted_binary_hash",
            "profile_bundle_hash",
            "capk_bundle_hash",
            "trace_pack_hash",
            "test_tool_version",
        ],
        repository_support: &[
            "docs/certification_freeze_manifest.json",
            "examples/krn_build_manifest.rs",
            "docs/certification_device_evidence_plan.json",
        ],
        acceptance_gate:
            "report hashes must agree with freeze-manifest hashes and the device/profile scope under submission",
    },
];

pub fn certification_integration_report_plan_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-integration-report-plan");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "checked_on", "2026-05-24");
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "full integration report and masked APDU trace-pack evidence plan",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_array_values(&mut out, &["CERT-OPEN-009", "CERT-OPEN-012"]);
    out.push_str("],\"required_metadata\":[");
    for (idx, metadata) in INTEGRATION_REPORT_METADATA.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "field", metadata.field);
        out.push(',');
        push_json_str(&mut out, "requirement", metadata.requirement);
        out.push('}');
    }
    out.push_str("],\"requirements\":[");
    for (idx, requirement) in INTEGRATION_REPORT_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_requirement_json(&mut out, requirement);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_integration_report_plan_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Integration Report Evidence Plan");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-24");
    let _ = writeln!(
        out,
        "- Scope: full integration report and masked APDU trace-pack evidence plan"
    );
    let _ = writeln!(
        out,
        "- Boundary: this plan does not close `CERT-OPEN-009` or `CERT-OPEN-012`; pending external coverage, full EMV integration, Level 3/acquirer, and full trace-pack reports are still required."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Metadata");
    let _ = writeln!(out, "| Field | Requirement |");
    let _ = writeln!(out, "| --- | --- |");
    for metadata in INTEGRATION_REPORT_METADATA {
        let _ = writeln!(out, "| {} | {} |", metadata.field, metadata.requirement);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence Requirements");
    let _ = writeln!(
        out,
        "| ID | Area | Open Issues | Authority | Required Attachment | Required Metadata | Repository Support | Acceptance Gate |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for requirement in INTEGRATION_REPORT_REQUIREMENTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            requirement.id,
            requirement.area,
            requirement.open_issues.join(", "),
            requirement.authority,
            requirement.required_attachment,
            requirement.required_metadata.join(", "),
            requirement.repository_support.join(", "),
            requirement.acceptance_gate,
        );
    }
    out
}

fn push_requirement_json(out: &mut String, requirement: &IntegrationReportRequirement) {
    out.push('{');
    push_json_str(out, "id", requirement.id);
    out.push(',');
    push_json_str(out, "area", requirement.area);
    out.push_str(",\"open_issues\":[");
    push_json_array_values(out, requirement.open_issues);
    out.push_str("],");
    push_json_str(out, "authority", requirement.authority);
    out.push(',');
    push_json_str(out, "required_attachment", requirement.required_attachment);
    out.push_str(",\"required_metadata\":[");
    push_json_array_values(out, requirement.required_metadata);
    out.push_str("],\"repository_support\":[");
    push_json_array_values(out, requirement.repository_support);
    out.push_str("],");
    push_json_str(out, "acceptance_gate", requirement.acceptance_gate);
    out.push('}');
}

fn push_json_array_values(out: &mut String, values: &[&str]) {
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(out, value);
    }
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    out.push_str(&value.to_string());
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for byte in value.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                out.push_str("\\u00");
                out.push(hex_nibble(byte >> 4));
                out.push(hex_nibble(byte & 0x0f));
            }
        }
    }
    out.push('"');
}

fn hex_nibble(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[usize::from(value & 0x0f)] as char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_report_plan_tracks_full_report_and_trace_boundaries() {
        let json = certification_integration_report_plan_json(2);
        let markdown = certification_integration_report_plan_markdown(2);

        assert!(json.contains("\"type\":\"certification-integration-report-plan\""));
        assert!(json.contains("\"INTEGRATION-TEST-SCOPE\""));
        assert!(json.contains("\"INTEGRATION-L2-EXECUTION\""));
        assert!(json.contains("\"INTEGRATION-L3-ACQUIRER\""));
        assert!(json.contains("\"INTEGRATION-TRACE-COVERAGE\""));
        assert!(json.contains("\"INTEGRATION-OUTCOME-MAPPING\""));
        assert!(json.contains("\"INTEGRATION-DEVIATION-DISPOSITION\""));
        assert!(json.contains("\"INTEGRATION-BUILD-BINDING\""));
        assert!(json.contains("\"CERT-OPEN-009\""));
        assert!(json.contains("\"CERT-OPEN-012\""));
        assert!(json.contains("\"trace_pack_hash\""));
        assert!(json.contains("\"level3_bulletin_set\""));
        assert!(json.contains("does_not_close"));
        assert!(!json.contains("\"certified\":true"));
        assert!(markdown.contains("# Hyperion Integration Report Evidence Plan"));
        assert!(markdown.contains("pending external coverage, full EMV integration"));
    }

    #[test]
    fn json_string_escape_helper_covers_control_and_non_ascii_bytes() {
        let mut out = String::new();
        push_json_string(
            &mut out,
            "quote\" slash\\ line\ncarriage\rtab\t high\x1f byte\u{00ff}",
        );
        assert_eq!(
            out,
            "\"quote\\\" slash\\\\ line\\ncarriage\\rtab\\t high\\u001f byte\\u00c3\\u00bf\""
        );
    }
}
