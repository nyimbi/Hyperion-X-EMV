//! Format-specific authority artifact adapters.
//!
//! These adapters cover common certification exchange shapes that can be parsed
//! without proprietary SDKs. They do not claim to understand every lab/vendor
//! export. Unknown proprietary formats should still be mapped through an
//! explicit `hyperion-integration-manifest.json` reviewed by the submitter.

use core::fmt::Write;
use std::str;

use crate::integration_import::CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION;
use crate::provenance::{sha256, to_hex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityArtifactFormat {
    CapkCsv,
    LabApduJsonl,
    C8OutcomeCsv,
    Level3ReconciliationCsv,
    SignedConformanceJson,
    StaticFuzzReportJson,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityAdapterOutput {
    pub format: AuthorityArtifactFormat,
    pub status: &'static str,
    pub artifact_count: usize,
    pub integration_manifest_json: String,
    pub findings: Vec<String>,
}

pub fn adapt_authority_artifact(
    format: AuthorityArtifactFormat,
    authority: &str,
    source_path: &str,
    bytes: &[u8],
) -> AuthorityAdapterOutput {
    let mut findings = Vec::new();
    let artifact_count = match format {
        AuthorityArtifactFormat::CapkCsv => validate_csv(
            bytes,
            &["rid", "index", "modulus", "exponent", "checksum"],
            &mut findings,
        ),
        AuthorityArtifactFormat::LabApduJsonl => {
            validate_jsonl(bytes, &["case", "apdu"], &mut findings)
        }
        AuthorityArtifactFormat::C8OutcomeCsv => {
            validate_csv(bytes, &["case", "outcome"], &mut findings)
        }
        AuthorityArtifactFormat::Level3ReconciliationCsv => {
            validate_csv(bytes, &["case", "expected", "actual"], &mut findings)
        }
        AuthorityArtifactFormat::SignedConformanceJson => {
            validate_json_object(bytes, &["signature", "scope"], &mut findings)
        }
        AuthorityArtifactFormat::StaticFuzzReportJson => {
            validate_json_object(bytes, &["tool", "findings"], &mut findings)
        }
    };
    let status = if findings.is_empty() {
        "manifest_ready_unreviewed"
    } else {
        "rejected"
    };
    AuthorityAdapterOutput {
        format,
        status,
        artifact_count,
        integration_manifest_json: integration_manifest_json(format, authority, source_path, bytes),
        findings,
    }
}

fn integration_manifest_json(
    format: AuthorityArtifactFormat,
    authority: &str,
    source_path: &str,
    bytes: &[u8],
) -> String {
    let profile = format_profile(format);
    let mut out = String::new();
    out.push('{');
    push_json_str(
        &mut out,
        "schema_version",
        CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
    );
    out.push(',');
    push_json_str(
        &mut out,
        "manifest_id",
        &format!("{}.{}", sanitize(authority), profile.artifact_id),
    );
    out.push(',');
    push_json_str(&mut out, "authority", authority);
    out.push_str(",\"artifacts\":[{");
    push_json_str(&mut out, "path", source_path);
    out.push(',');
    push_json_str(&mut out, "adapter_id", profile.adapter_id);
    out.push(',');
    push_json_str(&mut out, "artifact_id", profile.artifact_id);
    out.push(',');
    push_json_str(&mut out, "artifact_kind", profile.artifact_kind);
    out.push_str(",\"binds_open_issues\":[");
    for (idx, issue) in profile.open_issues.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, issue);
    }
    out.push(']');
    if let Some(bundle_field) = profile.bundle_field {
        out.push(',');
        push_json_str(&mut out, "bundle_field", bundle_field);
    }
    if let Some(freeze_id) = profile.freeze_artifact_id {
        out.push(',');
        push_json_str(&mut out, "freeze_artifact_id", freeze_id);
    }
    out.push(',');
    push_json_str(&mut out, "expected_sha256_hex", &to_hex(&sha256(bytes)));
    out.push_str(",\"metadata\":[");
    for (idx, metadata) in profile.metadata.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, metadata);
    }
    out.push_str("]}]}\n");
    out
}

struct FormatProfile {
    adapter_id: &'static str,
    artifact_id: &'static str,
    artifact_kind: &'static str,
    open_issues: &'static [&'static str],
    bundle_field: Option<&'static str>,
    freeze_artifact_id: Option<&'static str>,
    metadata: &'static [&'static str],
}

fn format_profile(format: AuthorityArtifactFormat) -> FormatProfile {
    match format {
        AuthorityArtifactFormat::CapkCsv => FormatProfile {
            adapter_id: "CAPK",
            artifact_id: "capk_bundle_csv",
            artifact_kind: "public key material",
            open_issues: &["CERT-OPEN-003", "CERT-OPEN-004"],
            bundle_field: Some("payload.capk_set"),
            freeze_artifact_id: Some("capk_bundle_hash"),
            metadata: &["authority", "retrieval_date", "checksum_set", "expiry_set"],
        },
        AuthorityArtifactFormat::LabApduJsonl => FormatProfile {
            adapter_id: "LAB-TRACE",
            artifact_id: "lab_apdu_trace_pack_jsonl",
            artifact_kind: "trace pack",
            open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
            bundle_field: None,
            freeze_artifact_id: Some("trace_pack_hash"),
            metadata: &["test_tool_version", "lab_case_ids", "masking_policy"],
        },
        AuthorityArtifactFormat::C8OutcomeCsv => FormatProfile {
            adapter_id: "VECTOR",
            artifact_id: "c8_outcome_export_csv",
            artifact_kind: "test vectors",
            open_issues: &["CERT-OPEN-004", "CERT-OPEN-009"],
            bundle_field: Some("payload.vector_bundle_json"),
            freeze_artifact_id: Some("test_vector_hash"),
            metadata: &["kernel", "tool_version", "outcome_set"],
        },
        AuthorityArtifactFormat::Level3ReconciliationCsv => FormatProfile {
            adapter_id: "REPORT",
            artifact_id: "level3_reconciliation_csv",
            artifact_kind: "quality report",
            open_issues: &["CERT-OPEN-009"],
            bundle_field: None,
            freeze_artifact_id: Some("approval_package_hash"),
            metadata: &["acquirer", "case_ids", "deviation_disposition"],
        },
        AuthorityArtifactFormat::SignedConformanceJson => FormatProfile {
            adapter_id: "REPORT",
            artifact_id: "signed_conformance_template_json",
            artifact_kind: "approval artifact",
            open_issues: &["CERT-OPEN-011"],
            bundle_field: None,
            freeze_artifact_id: Some("approval_package_hash"),
            metadata: &["signer", "signature_date", "template_version"],
        },
        AuthorityArtifactFormat::StaticFuzzReportJson => FormatProfile {
            adapter_id: "REPORT",
            artifact_id: "static_fuzz_report_json",
            artifact_kind: "quality report",
            open_issues: &["CERT-OPEN-010"],
            bundle_field: None,
            freeze_artifact_id: Some("static_fuzz_report_hash"),
            metadata: &["tool_versions", "commands", "finding_dispositions"],
        },
    }
}

fn validate_csv(bytes: &[u8], required_headers: &[&str], findings: &mut Vec<String>) -> usize {
    let text = match str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            findings.push("csv-not-utf8".to_string());
            return 0;
        }
    };
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines.next().unwrap_or_default().to_ascii_lowercase();
    for required in required_headers {
        if !header.split(',').any(|field| field.trim() == *required) {
            findings.push(format!("missing-header:{required}"));
        }
    }
    let count = lines.count();
    if count == 0 {
        findings.push("no-data-rows".to_string());
    }
    count
}

fn validate_jsonl(bytes: &[u8], required_tokens: &[&str], findings: &mut Vec<String>) -> usize {
    let text = match str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            findings.push("jsonl-not-utf8".to_string());
            return 0;
        }
    };
    let mut count = 0;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        count += 1;
        let lowered = line.to_ascii_lowercase();
        if !line.trim_start().starts_with('{') || !line.trim_end().ends_with('}') {
            findings.push("jsonl-line-not-object".to_string());
        }
        for token in required_tokens {
            if !lowered.contains(token) {
                findings.push(format!("missing-token:{token}"));
            }
        }
    }
    if count == 0 {
        findings.push("no-jsonl-records".to_string());
    }
    count
}

fn validate_json_object(
    bytes: &[u8],
    required_tokens: &[&str],
    findings: &mut Vec<String>,
) -> usize {
    let text = match str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            findings.push("json-not-utf8".to_string());
            return 0;
        }
    };
    let trimmed = text.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        findings.push("json-not-object".to_string());
    }
    let lowered = trimmed.to_ascii_lowercase();
    for token in required_tokens {
        if !lowered.contains(token) {
            findings.push(format!("missing-token:{token}"));
        }
    }
    usize::from(findings.is_empty())
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_string(out, key);
    out.push(':');
    push_json_string(out, value);
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
                let _ = write!(out, "{:02x}", byte);
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_adapters_emit_manifest_for_supported_formats() {
        let cases = [
            (
                AuthorityArtifactFormat::CapkCsv,
                "rid,index,modulus,exponent,checksum\nA000000003,01,AA,03,BB\n",
                "capk_bundle_hash",
            ),
            (
                AuthorityArtifactFormat::LabApduJsonl,
                "{\"case\":\"C1\",\"apdu\":\"00A40400\"}\n",
                "trace_pack_hash",
            ),
            (
                AuthorityArtifactFormat::C8OutcomeCsv,
                "case,outcome\nC8-1,approved\n",
                "test_vector_hash",
            ),
            (
                AuthorityArtifactFormat::Level3ReconciliationCsv,
                "case,expected,actual\nL3-1,approved,approved\n",
                "approval_package_hash",
            ),
            (
                AuthorityArtifactFormat::SignedConformanceJson,
                "{\"signature\":\"sig\",\"scope\":\"c8\"}",
                "approval_package_hash",
            ),
            (
                AuthorityArtifactFormat::StaticFuzzReportJson,
                "{\"tool\":\"cargo-fuzz\",\"findings\":[]}",
                "static_fuzz_report_hash",
            ),
        ];
        for (format, payload, freeze_slot) in cases {
            let output =
                adapt_authority_artifact(format, "Lab A", "reports/input.json", payload.as_bytes());
            assert_eq!(output.status, "manifest_ready_unreviewed");
            assert!(output.artifact_count > 0);
            assert!(output.integration_manifest_json.contains(freeze_slot));
            assert!(output
                .integration_manifest_json
                .contains("expected_sha256_hex"));
        }
    }

    #[test]
    fn authority_adapters_reject_malformed_inputs_and_escape_manifest_text() {
        let output = adapt_authority_artifact(
            AuthorityArtifactFormat::CapkCsv,
            "Lab \"A\"",
            "capk/bad.csv",
            b"rid,index\n",
        );
        assert_eq!(output.status, "rejected");
        assert!(output
            .findings
            .iter()
            .any(|finding| finding == "missing-header:modulus"));
        assert!(output.integration_manifest_json.contains("Lab \\\"A\\\""));
        let jsonl = adapt_authority_artifact(
            AuthorityArtifactFormat::LabApduJsonl,
            "Lab",
            "lab/trace.jsonl",
            b"not json",
        );
        assert!(jsonl
            .findings
            .contains(&"jsonl-line-not-object".to_string()));
        let non_utf8 = adapt_authority_artifact(
            AuthorityArtifactFormat::StaticFuzzReportJson,
            "Lab",
            "reports/fuzz.json",
            &[0xff],
        );
        assert!(non_utf8.findings.contains(&"json-not-utf8".to_string()));
    }

    #[test]
    fn authority_adapters_cover_encoding_empty_and_json_edge_findings() {
        let csv = adapt_authority_artifact(
            AuthorityArtifactFormat::CapkCsv,
            "Lab",
            "capk/non-utf8.csv",
            &[0xff],
        );
        assert!(csv.findings.contains(&"csv-not-utf8".to_string()));

        let jsonl_non_utf8 = adapt_authority_artifact(
            AuthorityArtifactFormat::LabApduJsonl,
            "Lab",
            "lab/non-utf8.jsonl",
            &[0xff],
        );
        assert!(jsonl_non_utf8
            .findings
            .contains(&"jsonl-not-utf8".to_string()));

        let jsonl_empty = adapt_authority_artifact(
            AuthorityArtifactFormat::LabApduJsonl,
            "Lab",
            "lab/empty.jsonl",
            b"\n",
        );
        assert!(jsonl_empty
            .findings
            .contains(&"no-jsonl-records".to_string()));

        let json_shape = adapt_authority_artifact(
            AuthorityArtifactFormat::SignedConformanceJson,
            "Lab",
            "lab/template.json",
            b"[]",
        );
        assert!(json_shape.findings.contains(&"json-not-object".to_string()));
        assert!(json_shape
            .findings
            .contains(&"missing-token:signature".to_string()));

        let escaped = adapt_authority_artifact(
            AuthorityArtifactFormat::SignedConformanceJson,
            "Lab\n\t\r\u{00ff}",
            "lab/template\\x.json",
            b"{\"signature\":\"sig\",\"template_version\":1}",
        );
        assert!(escaped.integration_manifest_json.contains("\\n"));
        assert!(escaped.integration_manifest_json.contains("\\t"));
        assert!(escaped.integration_manifest_json.contains("\\r"));
        assert!(escaped.integration_manifest_json.contains("\\\\x"));
        assert!(escaped.integration_manifest_json.contains("\\u00c3\\u00bf"));
    }
}
