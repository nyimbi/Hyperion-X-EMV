//! Certification freeze manifest generation.
//!
//! The manifest generated here is a template for binding a submitted kernel
//! build to the exact external evidence package reviewed by a lab, scheme,
//! acquirer, device vendor, or security assessor. It deliberately records
//! pending hash slots and does not claim certification closure.

use core::fmt::Write;

pub struct FreezeArtifactRequirement {
    pub id: &'static str,
    pub title: &'static str,
    pub artifact_kind: &'static str,
    pub binds_open_issues: &'static [&'static str],
    pub required_metadata: &'static [&'static str],
    pub evidence_source: &'static str,
}

const FREEZE_ARTIFACTS: &[FreezeArtifactRequirement] = &[
    FreezeArtifactRequirement {
        id: "kernel_binary_hash",
        title: "Submitted kernel binary",
        artifact_kind: "build artifact",
        binds_open_issues: &[
            "CERT-OPEN-001",
            "CERT-OPEN-006",
            "CERT-OPEN-009",
            "CERT-OPEN-011",
            "CERT-OPEN-012",
        ],
        required_metadata: &[
            "target_triple",
            "build_profile",
            "cargo_version",
            "rustc_version",
            "abi_version",
        ],
        evidence_source: "release build pipeline artifact digest accepted for the lab submission",
    },
    FreezeArtifactRequirement {
        id: "config_bundle_hash",
        title: "Signed runtime configuration bundle",
        artifact_kind: "signed configuration",
        binds_open_issues: &[
            "CERT-OPEN-002",
            "CERT-OPEN-005",
            "CERT-OPEN-009",
            "CERT-OPEN-012",
        ],
        required_metadata: &[
            "profile_version",
            "signature_status",
            "rollback_counter",
            "retrieval_date",
        ],
        evidence_source: "signed configuration package digest tied to the submitted binary",
    },
    FreezeArtifactRequirement {
        id: "capk_bundle_hash",
        title: "Scheme/acquirer-approved CAPK bundle",
        artifact_kind: "public key material",
        binds_open_issues: &["CERT-OPEN-003", "CERT-OPEN-004", "CERT-OPEN-009"],
        required_metadata: &[
            "capk_source",
            "retrieval_date",
            "expiry_set",
            "checksum_set",
            "approval_reference",
        ],
        evidence_source: "accepted CAPK package digest with signed provenance",
    },
    FreezeArtifactRequirement {
        id: "scheme_profile_hash",
        title: "Scheme/acquirer-approved profile bundle",
        artifact_kind: "scheme profile",
        binds_open_issues: &[
            "CERT-OPEN-002",
            "CERT-OPEN-005",
            "CERT-OPEN-009",
            "CERT-OPEN-012",
        ],
        required_metadata: &[
            "authority",
            "scheme_set",
            "aid_set",
            "kernel_mapping",
            "profile_signature",
        ],
        evidence_source: "accepted scheme profile package digest with profile authority evidence",
    },
    FreezeArtifactRequirement {
        id: "test_vector_hash",
        title: "Lab-supplied ODA and APDU test-vector bundle",
        artifact_kind: "test vectors",
        binds_open_issues: &["CERT-OPEN-004", "CERT-OPEN-009", "CERT-OPEN-012"],
        required_metadata: &[
            "vector_class",
            "tool_version",
            "method_coverage",
            "expected_outputs",
            "bundle_authority",
        ],
        evidence_source: "recognized-lab vector and trace-pack digest",
    },
    FreezeArtifactRequirement {
        id: "traceability_matrix_hash",
        title: "Final RTM and lab/tool crosswalk",
        artifact_kind: "traceability",
        binds_open_issues: &[
            "CERT-OPEN-001",
            "CERT-OPEN-009",
            "CERT-OPEN-011",
            "CERT-OPEN-012",
        ],
        required_metadata: &[
            "rtm_version",
            "test_tool_package",
            "lab_case_ids",
            "deviation_list",
            "reviewer",
        ],
        evidence_source: "final RTM digest after lab test-case ID reconciliation",
    },
    FreezeArtifactRequirement {
        id: "coverage_report_hash",
        title: "Accepted 100% coverage report package",
        artifact_kind: "quality report",
        binds_open_issues: &["CERT-OPEN-009"],
        required_metadata: &[
            "source_commit",
            "coverage_tool_version",
            "coverage_enforced",
            "target_triple",
            "feature_set",
        ],
        evidence_source: "accepted coverage report and metadata package digest",
    },
    FreezeArtifactRequirement {
        id: "static_fuzz_report_hash",
        title: "Accepted static-analysis and fuzzing report package",
        artifact_kind: "quality report",
        binds_open_issues: &["CERT-OPEN-010"],
        required_metadata: &[
            "tool_versions",
            "commands",
            "sanitizer_set",
            "corpus_hashes",
            "run_budget",
            "finding_dispositions",
        ],
        evidence_source: "accepted static-analysis and fuzzing report package digest",
    },
    FreezeArtifactRequirement {
        id: "approval_package_hash",
        title: "Signed approval and conformance package",
        artifact_kind: "approval artifact",
        binds_open_issues: &["CERT-OPEN-001", "CERT-OPEN-011"],
        required_metadata: &[
            "signer",
            "signature_date",
            "template_version",
            "claimed_scope",
            "approval_reference",
        ],
        evidence_source: "recognized authority signed approval package digest",
    },
];

pub fn certification_freeze_manifest_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-freeze-manifest-template");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "checked_on", "2026-05-23");
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "submitted-build hash slots for certification freeze and lab package assembly",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "source_of_truth",
        "docs/lab_submission_manifest.md and docs/certification_open_issues.md",
    );
    out.push_str(",\"does_not_close\":[");
    for (idx, issue) in [
        "CERT-OPEN-001",
        "CERT-OPEN-002",
        "CERT-OPEN-003",
        "CERT-OPEN-004",
        "CERT-OPEN-005",
        "CERT-OPEN-006",
        "CERT-OPEN-007",
        "CERT-OPEN-008",
        "CERT-OPEN-009",
        "CERT-OPEN-010",
        "CERT-OPEN-011",
        "CERT-OPEN-012",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, issue);
    }
    out.push_str("],\"freeze_policy\":[");
    for (idx, policy) in [
        "every submitted artifact must have a SHA-256 digest before certification-facing review",
        "the submitted binary, signed profiles, CAPKs, vectors, RTM, reports, traces, and approval package must name the same product scope",
        "a changed artifact hash requires a new freeze review and supersedes the prior package by recorded reason",
        "the freeze manifest is a binding template only and cannot close external certification blockers by itself",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, policy);
    }
    out.push_str("],\"required_artifacts\":[");
    for (idx, artifact) in FREEZE_ARTIFACTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_freeze_artifact_json(&mut out, artifact);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_freeze_manifest_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Freeze Manifest");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-23");
    let _ = writeln!(
        out,
        "- Scope: submitted-build hash slots for certification freeze and lab package assembly"
    );
    let _ = writeln!(
        out,
        "- Source of truth: `docs/lab_submission_manifest.md` and `docs/certification_open_issues.md`"
    );
    let _ = writeln!(
        out,
        "- Boundary: this manifest does not close any `CERT-OPEN-*` issue."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Freeze Policy");
    for policy in [
        "Every submitted artifact must have a SHA-256 digest before certification-facing review.",
        "The submitted binary, signed profiles, CAPKs, vectors, RTM, reports, traces, and approval package must name the same product scope.",
        "A changed artifact hash requires a new freeze review and supersedes the prior package by recorded reason.",
        "The freeze manifest is a binding template only and cannot close external certification blockers by itself.",
    ] {
        let _ = writeln!(out, "- {policy}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Freeze Artifacts");
    let _ = writeln!(
        out,
        "| ID | Title | Kind | Binds Open Issues | Required Metadata | Evidence Source | Required Hash | Status |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for artifact in FREEZE_ARTIFACTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | SHA-256 pending | pending external certification freeze |",
            artifact.id,
            artifact.title,
            artifact.artifact_kind,
            artifact.binds_open_issues.join(", "),
            artifact.required_metadata.join(", "),
            artifact.evidence_source,
        );
    }
    out
}

fn push_freeze_artifact_json(out: &mut String, artifact: &FreezeArtifactRequirement) {
    out.push('{');
    push_json_str(out, "id", artifact.id);
    out.push(',');
    push_json_str(out, "title", artifact.title);
    out.push(',');
    push_json_str(out, "artifact_kind", artifact.artifact_kind);
    out.push_str(",\"binds_open_issues\":[");
    push_json_array_values(out, artifact.binds_open_issues);
    out.push_str("],\"required_metadata\":[");
    push_json_array_values(out, artifact.required_metadata);
    out.push_str("],");
    push_json_str(out, "evidence_source", artifact.evidence_source);
    out.push(',');
    push_json_str(out, "required_hash", "SHA-256 pending");
    out.push(',');
    push_json_str(out, "status", "pending external certification freeze");
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
    fn freeze_manifest_tracks_hash_slots_without_certification_claims() {
        let json = certification_freeze_manifest_json(2);
        let markdown = certification_freeze_manifest_markdown(2);

        assert!(json.contains("\"type\":\"certification-freeze-manifest-template\""));
        assert!(json.contains("\"kernel_binary_hash\""));
        assert!(json.contains("\"coverage_report_hash\""));
        assert!(json.contains("\"approval_package_hash\""));
        assert!(json.contains("\"required_hash\":\"SHA-256 pending\""));
        assert!(json.contains("\"CERT-OPEN-012\""));
        assert!(json.contains("does_not_close"));
        assert!(!json.contains("\"certified\":true"));
        assert!(markdown.contains("# Hyperion Certification Freeze Manifest"));
        assert!(markdown.contains("pending external certification freeze"));
        assert!(markdown.contains("does not close any `CERT-OPEN-*` issue"));
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
