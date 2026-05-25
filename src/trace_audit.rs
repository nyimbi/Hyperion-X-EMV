//! APDU trace-pack auditing for `CERT-OPEN-012`.
//!
//! Repository-generated trace fixtures are useful only if they remain complete,
//! replay-shaped, masked, and clearly scoped as pre-lab evidence. This module
//! audits JSONL trace packs without treating them as accepted laboratory trace
//! evidence.

use core::fmt::Write;
use std::fs;
use std::io;
use std::path::Path;

use crate::provenance::{sha256, to_hex};

pub const DEFAULT_PRELAB_TRACE_PACK_PATH: &str = "docs/prelab_apdu_trace_pack.jsonl";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracePackCaseAudit {
    pub case_id: String,
    pub metadata_seen: bool,
    pub scenario_seen: bool,
    pub trace_identity_seen: bool,
    pub expected_step_count: Option<u64>,
    pub command_count: u64,
    pub response_count: u64,
    pub expected_tlv_stream_count: Option<u64>,
    pub tlv_stream_count: u64,
    pub findings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracePackAudit {
    pub path: String,
    pub status: &'static str,
    pub boundary: &'static str,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub line_count: u64,
    pub cases: Vec<TracePackCaseAudit>,
    pub findings: Vec<String>,
}

pub fn audit_trace_pack(path: &Path) -> io::Result<TracePackAudit> {
    if !path.is_file() {
        return Ok(TracePackAudit {
            path: path.display().to_string(),
            status: "missing_or_malformed",
            boundary: trace_audit_boundary(),
            size_bytes: 0,
            sha256: None,
            line_count: 0,
            cases: Vec::new(),
            findings: vec![format!("missing trace pack file: {}", path.display())],
        });
    }

    let bytes = fs::read(path)?;
    let text = String::from_utf8(bytes.clone()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "trace pack must be UTF-8 JSONL")
    })?;
    let mut findings = Vec::new();
    let mut cases = Vec::new();
    let mut current_case: Option<usize> = None;
    let mut line_count = 0;

    for (index, raw_line) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        line_count += 1;

        validate_sensitive_trace_line(line_no, line, &mut findings);

        if line.contains("\"type\":\"trace-pack-metadata\"") {
            match json_string_value(line, "case_id") {
                Some(case_id) => {
                    if cases
                        .iter()
                        .any(|case: &TracePackCaseAudit| case.case_id == case_id)
                    {
                        findings.push(format!("line {line_no}: duplicate case_id `{case_id}`"));
                    }
                    let mut case = TracePackCaseAudit {
                        case_id,
                        metadata_seen: true,
                        scenario_seen: false,
                        trace_identity_seen: false,
                        expected_step_count: None,
                        command_count: 0,
                        response_count: 0,
                        expected_tlv_stream_count: None,
                        tlv_stream_count: 0,
                        findings: Vec::new(),
                    };
                    if json_string_value(line, "does_not_close").as_deref() != Some("CERT-OPEN-012")
                    {
                        case.findings
                            .push("metadata does_not_close must be CERT-OPEN-012".to_string());
                    }
                    if json_string_value(line, "scope").as_deref()
                        != Some("repository-controlled pre-lab fixture")
                    {
                        case.findings.push(
                            "metadata scope must be repository-controlled pre-lab fixture"
                                .to_string(),
                        );
                    }
                    cases.push(case);
                    current_case = Some(cases.len() - 1);
                }
                None => findings.push(format!("line {line_no}: metadata missing case_id")),
            }
        } else if line.contains("\"type\":\"trace-scenario\"") {
            match json_string_value(line, "case_id") {
                Some(case_id) => {
                    let case_index = find_or_create_case(&mut cases, &case_id);
                    let case = &mut cases[case_index];
                    case.scenario_seen = true;
                    case.expected_step_count = json_u64_value(line, "expected_step_count");
                    case.expected_tlv_stream_count =
                        json_u64_value(line, "expected_tlv_stream_count");
                    if case.expected_step_count.is_none() {
                        case.findings
                            .push("scenario missing expected_step_count".to_string());
                    }
                    if case.expected_tlv_stream_count.is_none() {
                        case.findings
                            .push("scenario missing expected_tlv_stream_count".to_string());
                    }
                    if !line.contains("\"masking_assertions\"")
                        || !line.contains("full-apdu-disabled")
                    {
                        case.findings.push(
                            "scenario masking_assertions must include full-apdu-disabled"
                                .to_string(),
                        );
                    }
                    current_case = Some(case_index);
                }
                None => findings.push(format!("line {line_no}: scenario missing case_id")),
            }
        } else if line.contains("\"type\":\"trace-identity\"") {
            match current_case {
                Some(case_index) => {
                    cases[case_index].trace_identity_seen = true;
                    if !line.contains("\"log_build_mode\":\"production\"") {
                        cases[case_index].findings.push(
                            "trace identity must declare production log_build_mode".to_string(),
                        );
                    }
                    if !line.contains("\"support_authorization_verified\":false") {
                        cases[case_index].findings.push(
                            "trace identity must declare support_authorization_verified=false"
                                .to_string(),
                        );
                    }
                }
                None => findings.push(format!(
                    "line {line_no}: trace identity appeared before case metadata"
                )),
            }
        } else if line.contains("\"direction\":\"command\"") {
            match current_case {
                Some(case_index) => {
                    cases[case_index].command_count += 1;
                    if !line.contains("\"reason\":\"full-apdu-disabled\"") {
                        cases[case_index].findings.push(format!(
                            "line {line_no}: command APDU data is not suppressed"
                        ));
                    }
                }
                None => findings.push(format!(
                    "line {line_no}: command trace appeared before case metadata"
                )),
            }
        } else if line.contains("\"direction\":\"response\"") {
            match current_case {
                Some(case_index) => {
                    cases[case_index].response_count += 1;
                    if !line.contains("\"data\":{\"type\":\"suppressed\"") {
                        cases[case_index]
                            .findings
                            .push(format!("line {line_no}: response APDU body is not masked"));
                    }
                }
                None => findings.push(format!(
                    "line {line_no}: response trace appeared before case metadata"
                )),
            }
        } else if line.contains("\"type\":\"tlv-stream\"") {
            match current_case {
                Some(case_index) => cases[case_index].tlv_stream_count += 1,
                None => findings.push(format!(
                    "line {line_no}: TLV stream appeared before case metadata"
                )),
            }
        } else {
            findings.push(format!("line {line_no}: unknown trace-pack JSONL record"));
        }
    }

    validate_trace_cases(&mut cases);
    if cases.is_empty() {
        findings.push("trace pack contains no cases".to_string());
    }

    let has_case_findings = cases.iter().any(|case| !case.findings.is_empty());
    let status = if cases.is_empty() {
        "missing_or_malformed"
    } else if findings.is_empty() && !has_case_findings {
        "prelab_fixture_reviewable"
    } else {
        "incomplete"
    };

    Ok(TracePackAudit {
        path: path.display().to_string(),
        status,
        boundary: trace_audit_boundary(),
        size_bytes: bytes.len() as u64,
        sha256: Some(to_hex(&sha256(&bytes))),
        line_count,
        cases,
        findings,
    })
}

pub fn trace_pack_is_prelab_reviewable(audit: &TracePackAudit) -> bool {
    audit.status == "prelab_fixture_reviewable"
}

pub fn trace_pack_audit_json(abi_version: u32, audit: &TracePackAudit) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "trace-pack-audit");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "trace_pack_path", &audit.path);
    out.push(',');
    push_json_str(&mut out, "status", audit.status);
    out.push(',');
    push_json_str(&mut out, "boundary", audit.boundary);
    out.push(',');
    push_json_number(&mut out, "size_bytes", audit.size_bytes);
    out.push(',');
    out.push_str("\"sha256\":");
    if let Some(hash) = &audit.sha256 {
        push_json_string(&mut out, hash);
    } else {
        out.push_str("null");
    }
    out.push(',');
    push_json_number(&mut out, "line_count", audit.line_count);
    out.push_str(",\"cases\":[");
    for (idx, case) in audit.cases.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_case_json(&mut out, case);
    }
    out.push_str("],\"findings\":[");
    for (idx, finding) in audit.findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, finding);
    }
    out.push_str("]}\n");
    out
}

pub fn trace_pack_audit_markdown(abi_version: u32, audit: &TracePackAudit) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Trace Pack Audit");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Trace pack path: `{}`", audit.path);
    let _ = writeln!(out, "- Status: `{}`", audit.status);
    let _ = writeln!(out, "- Boundary: {}", audit.boundary);
    let _ = writeln!(out, "- Size bytes: {}", audit.size_bytes);
    let _ = writeln!(
        out,
        "- SHA-256: `{}`",
        audit.sha256.as_deref().unwrap_or("n/a")
    );
    let _ = writeln!(out, "- Line count: {}", audit.line_count);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Cases");
    let _ = writeln!(
        out,
        "| Case | Metadata | Scenario | Identity | Commands | Responses | TLV Streams | Findings |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | ---: | ---: | ---: | --- |");
    for case in &audit.cases {
        let findings = if case.findings.is_empty() {
            "none".to_string()
        } else {
            case.findings.join("; ")
        };
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} / {} | {} / {} | {} / {} | {} |",
            case.case_id,
            case.metadata_seen,
            case.scenario_seen,
            case.trace_identity_seen,
            case.command_count,
            optional_number(case.expected_step_count),
            case.response_count,
            optional_number(case.expected_step_count),
            case.tlv_stream_count,
            optional_number(case.expected_tlv_stream_count),
            findings
        );
    }
    if !audit.findings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Findings");
        for finding in &audit.findings {
            let _ = writeln!(out, "- {finding}");
        }
    }
    out
}

fn trace_audit_boundary() -> &'static str {
    "trace-pack audit only; full lab/test-tool trace acceptance is still required before CERT-OPEN-012 can close"
}

fn find_or_create_case(cases: &mut Vec<TracePackCaseAudit>, case_id: &str) -> usize {
    if let Some(index) = cases.iter().position(|case| case.case_id == case_id) {
        return index;
    }
    cases.push(TracePackCaseAudit {
        case_id: case_id.to_string(),
        metadata_seen: false,
        scenario_seen: false,
        trace_identity_seen: false,
        expected_step_count: None,
        command_count: 0,
        response_count: 0,
        expected_tlv_stream_count: None,
        tlv_stream_count: 0,
        findings: vec!["scenario appeared before metadata".to_string()],
    });
    cases.len() - 1
}

fn validate_trace_cases(cases: &mut [TracePackCaseAudit]) {
    for case in cases {
        if !case.metadata_seen {
            case.findings
                .push("missing trace-pack metadata".to_string());
        }
        if !case.scenario_seen {
            case.findings.push("missing trace scenario".to_string());
        }
        if !case.trace_identity_seen {
            case.findings.push("missing trace identity".to_string());
        }
        if let Some(expected) = case.expected_step_count {
            if case.command_count != expected {
                case.findings.push(format!(
                    "command count {} does not match expected_step_count {}",
                    case.command_count, expected
                ));
            }
            if case.response_count != expected {
                case.findings.push(format!(
                    "response count {} does not match expected_step_count {}",
                    case.response_count, expected
                ));
            }
        }
        if case.command_count == 0 {
            case.findings
                .push("case contains no command trace records".to_string());
        }
        if case.response_count == 0 {
            case.findings
                .push("case contains no response trace records".to_string());
        }
        if let Some(expected) = case.expected_tlv_stream_count {
            if case.tlv_stream_count != expected {
                case.findings.push(format!(
                    "TLV stream count {} does not match expected_tlv_stream_count {}",
                    case.tlv_stream_count, expected
                ));
            }
        }
    }
}

fn validate_sensitive_trace_line(line_no: usize, line: &str, findings: &mut Vec<String>) {
    for (tag, reason) in [
        ("\"tag\":\"57\"", "\"reason\":\"track2\""),
        ("\"tag\":\"9f26\"", "\"reason\":\"transaction-cryptogram\""),
        ("\"tag\":\"9f10\"", "\"reason\":\"issuer-application-data\""),
        (
            "\"tag\":\"9f4b\"",
            "\"reason\":\"signed-dynamic-application-data\"",
        ),
        ("\"tag\":\"9f4c\"", "\"reason\":\"icc-dynamic-number\""),
        (
            "\"tag\":\"91\"",
            "\"reason\":\"issuer-authentication-data\"",
        ),
        (
            "\"tag\":\"9f18\"",
            "\"reason\":\"issuer-script-identifier\"",
        ),
        (
            "\"tag\":\"86\"",
            "\"reason\":\"issuer-script-command-data\"",
        ),
    ] {
        if line.contains(tag) && !line.contains(reason) {
            findings.push(format!(
                "line {line_no}: sensitive {tag} value must be suppressed as {reason}"
            ));
        }
    }

    let lowercase = line.to_ascii_lowercase();
    for forbidden in [
        "123456789012345",
        "123456789012d251",
        "25122012345678",
        "010203",
        "a1a2a3a4a5a6a7a8",
        "1122334455667788",
        "00da000001aa",
        "deadbeef",
        "1112131415161718",
        "aabbcc",
    ] {
        if lowercase.contains(forbidden) {
            findings.push(format!(
                "line {line_no}: forbidden raw sensitive fixture value `{forbidden}` is present"
            ));
        }
    }
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| value.to_string())
}

fn json_string_value(input: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let start = input.find(&marker)? + marker.len();
    let rest = &input[start..];
    let mut out = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn json_u64_value(input: &str, key: &str) -> Option<u64> {
    let marker = format!("\"{key}\":");
    let start = input.find(&marker)? + marker.len();
    let rest = input[start..].trim_start();
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse().ok()
}

fn push_case_json(out: &mut String, case: &TracePackCaseAudit) {
    out.push('{');
    push_json_str(out, "case_id", &case.case_id);
    out.push(',');
    push_json_bool(out, "metadata_seen", case.metadata_seen);
    out.push(',');
    push_json_bool(out, "scenario_seen", case.scenario_seen);
    out.push(',');
    push_json_bool(out, "trace_identity_seen", case.trace_identity_seen);
    out.push_str(",\"expected_step_count\":");
    push_optional_number(out, case.expected_step_count);
    out.push(',');
    push_json_number(out, "command_count", case.command_count);
    out.push(',');
    push_json_number(out, "response_count", case.response_count);
    out.push_str(",\"expected_tlv_stream_count\":");
    push_optional_number(out, case.expected_tlv_stream_count);
    out.push(',');
    push_json_number(out, "tlv_stream_count", case.tlv_stream_count);
    out.push_str(",\"findings\":[");
    for (idx, finding) in case.findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(out, finding);
    }
    out.push_str("]}");
}

fn push_optional_number(out: &mut String, value: Option<u64>) {
    if let Some(value) = value {
        let _ = write!(out, "{value}");
    } else {
        out.push_str("null");
    }
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_string(out, key);
    out.push(':');
    push_json_string(out, value);
}

fn push_json_bool(out: &mut String, key: &str, value: bool) {
    push_json_string(out, key);
    out.push(':');
    out.push_str(if value { "true" } else { "false" });
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_string(out, key);
    out.push(':');
    let _ = write!(out, "{value}");
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use std::process;

    #[test]
    fn missing_trace_pack_reports_missing_without_error() {
        let path = temp_path("missing");
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }

        let audit = audit_trace_pack(&path).unwrap();

        assert_eq!(audit.status, "missing_or_malformed");
        assert!(!trace_pack_is_prelab_reviewable(&audit));
        assert!(audit.findings[0].contains("missing trace pack file"));
    }

    #[test]
    fn complete_prelab_trace_pack_is_reviewable() {
        let path = temp_path("reviewable");
        fs::write(&path, valid_trace_pack()).unwrap();

        let audit = audit_trace_pack(&path).unwrap();
        let json = trace_pack_audit_json(2, &audit);
        let markdown = trace_pack_audit_markdown(2, &audit);

        assert_eq!(audit.status, "prelab_fixture_reviewable");
        assert!(trace_pack_is_prelab_reviewable(&audit));
        assert_eq!(audit.cases.len(), 1);
        assert!(json.contains("\"type\":\"trace-pack-audit\""));
        assert!(json.contains("\"status\":\"prelab_fixture_reviewable\""));
        assert!(markdown.contains("# Hyperion Trace Pack Audit"));
        assert!(markdown.contains("CERT-OPEN-012"));

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn raw_sensitive_values_make_trace_pack_incomplete() {
        let path = temp_path("raw-sensitive");
        fs::write(
            &path,
            valid_trace_pack().replace(
                "\"reason\":\"transaction-cryptogram\"",
                "\"type\":\"hex\",\"value\":\"1122334455667788\"",
            ),
        )
        .unwrap();

        let audit = audit_trace_pack(&path).unwrap();

        assert_eq!(audit.status, "incomplete");
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("transaction-cryptogram")));
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("1122334455667788")));

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn step_count_mismatches_make_trace_pack_incomplete() {
        let path = temp_path("step-mismatch");
        fs::write(
            &path,
            valid_trace_pack().replace("\"expected_step_count\":1", "\"expected_step_count\":2"),
        )
        .unwrap();

        let audit = audit_trace_pack(&path).unwrap();

        assert_eq!(audit.status, "incomplete");
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding.contains("command count 1")));
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding.contains("response count 1")));

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn malformed_trace_pack_records_all_structure_failures() {
        let path = temp_path("malformed-structure");
        fs::write(
            &path,
            concat!(
                "\n",
                "{\"type\":\"trace-pack-metadata\",\"case_id\":\"bad.case\",\"scope\":\"wrong\",\"does_not_close\":\"WRONG\"}\n",
                "{\"type\":\"trace-pack-metadata\",\"case_id\":\"bad.case\",\"scope\":\"wrong\",\"does_not_close\":\"WRONG\"}\n",
                "{\"type\":\"trace-scenario\",\"case_id\":\"bad.case\",\"masking_assertions\":[]}\n",
                "{\"type\":\"trace-identity\",\"log_build_mode\":\"debug\",\"support_authorization_verified\":true}\n",
                "{\"sequence\":0,\"direction\":\"command\",\"data\":{\"type\":\"raw\"}}\n",
                "{\"sequence\":1,\"direction\":\"response\",\"data\":{\"type\":\"raw\"}}\n",
                "{\"type\":\"tlv-stream\"}\n",
                "{\"type\":\"unknown\"}\n"
            ),
        )
        .unwrap();

        let audit = audit_trace_pack(&path).unwrap();
        let json = trace_pack_audit_json(2, &audit);
        let markdown = trace_pack_audit_markdown(2, &audit);

        assert_eq!(audit.status, "incomplete");
        assert_eq!(audit.line_count, 8);
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("duplicate case_id")));
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("unknown trace-pack JSONL record")));
        let case_findings = &audit.cases[0].findings;
        for expected in [
            "metadata does_not_close must be CERT-OPEN-012",
            "metadata scope must be repository-controlled pre-lab fixture",
            "scenario missing expected_step_count",
            "scenario missing expected_tlv_stream_count",
            "scenario masking_assertions must include full-apdu-disabled",
            "trace identity must declare production log_build_mode",
            "trace identity must declare support_authorization_verified=false",
        ] {
            assert!(
                case_findings.iter().any(|finding| finding == expected),
                "missing {expected}"
            );
        }
        assert!(case_findings
            .iter()
            .any(|finding| finding.contains("command APDU data")));
        assert!(case_findings
            .iter()
            .any(|finding| finding.contains("response APDU body")));
        assert!(json.contains("\"expected_step_count\":null"));
        assert!(markdown.contains("## Findings"));

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn out_of_order_trace_records_create_incomplete_case() {
        let path = temp_path("out-of-order");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"trace-scenario\",\"case_id\":\"late.metadata\",\"expected_step_count\":0,\"expected_tlv_stream_count\":1,\"masking_assertions\":[\"full-apdu-disabled\"]}\n",
                "{\"type\":\"tlv-stream\"}\n"
            ),
        )
        .unwrap();

        let audit = audit_trace_pack(&path).unwrap();

        assert_eq!(audit.status, "incomplete");
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding == "scenario appeared before metadata"));
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding == "missing trace-pack metadata"));
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding == "missing trace identity"));
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding == "case contains no command trace records"));
        assert!(audit.cases[0]
            .findings
            .iter()
            .any(|finding| finding == "case contains no response trace records"));

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn non_utf8_and_empty_trace_pack_are_rejected() {
        let non_utf8 = temp_path("non-utf8");
        fs::write(&non_utf8, [0xff, 0xfe]).unwrap();
        let err = audit_trace_pack(&non_utf8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(&non_utf8).unwrap();

        let empty = temp_path("empty");
        fs::write(&empty, b"\n\n").unwrap();
        let audit = audit_trace_pack(&empty).unwrap();
        assert_eq!(audit.status, "missing_or_malformed");
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding == "trace pack contains no cases"));
        fs::remove_file(&empty).unwrap();
    }

    #[test]
    fn sensitive_trace_line_rejects_all_masking_regressions() {
        for (idx, (tag, raw)) in [
            ("57", "123456789012345"),
            ("9f26", "a1a2a3a4a5a6a7a8"),
            ("9f10", "010203"),
            ("9f4b", "deadbeef"),
            ("9f4c", "aabbcc"),
            ("91", "1112131415161718"),
            ("9f18", "25122012345678"),
            ("86", "00da000001aa"),
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_path(&format!("sensitive-{idx}"));
            fs::write(
                &path,
                format!(
                    "{{\"type\":\"trace-pack-metadata\",\"case_id\":\"sensitive.{idx}\",\"scope\":\"repository-controlled pre-lab fixture\",\"does_not_close\":\"CERT-OPEN-012\"}}\n{{\"type\":\"trace-scenario\",\"case_id\":\"sensitive.{idx}\",\"expected_step_count\":1,\"expected_tlv_stream_count\":0,\"masking_assertions\":[\"full-apdu-disabled\"]}}\n{{\"type\":\"trace-identity\",\"log_build_mode\":\"production\",\"support_authorization_verified\":false}}\n{{\"sequence\":0,\"direction\":\"command\",\"data\":{{\"type\":\"suppressed\",\"reason\":\"full-apdu-disabled\"}}}}\n{{\"sequence\":1,\"direction\":\"response\",\"data\":{{\"type\":\"suppressed\"}},\"fields\":[{{\"tag\":\"{tag}\",\"value\":\"{raw}\"}}]}}\n"
                ),
            )
            .unwrap();
            let audit = audit_trace_pack(&path).unwrap();
            assert_eq!(audit.status, "incomplete");
            assert!(audit.findings.iter().any(|finding| finding.contains(tag)));
            assert!(audit.findings.iter().any(|finding| finding.contains(raw)));
            fs::remove_file(&path).unwrap();
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        env::temp_dir().join(format!("hyperion-trace-audit-{label}-{}", process::id()))
    }

    fn valid_trace_pack() -> String {
        concat!(
            "{\"type\":\"trace-pack-metadata\",\"trace_pack_id\":\"PRELAB-MASKED-APDU-001\",\"scope\":\"repository-controlled pre-lab fixture\",\"case_id\":\"prelab.test\",\"does_not_close\":\"CERT-OPEN-012\"}\n",
            "{\"type\":\"trace-scenario\",\"case_id\":\"prelab.test\",\"expected_step_count\":1,\"expected_fsm_events\":[\"GacArqc\"],\"expected_fsm_actions\":[\"BuildHostRequest\"],\"expected_status_actions\":[],\"expected_command_flow\":[\"generate-ac\"],\"expected_response_shapes\":[\"gac-template-77\"],\"expected_terminal_outcome\":\"online-authorization-request\",\"expected_tlv_stream_count\":0,\"masking_assertions\":[\"full-apdu-disabled\",\"transaction-cryptogram-suppressed\"]}\n",
            "{\"type\":\"trace-identity\",\"kernel_name\":\"hyperion-emv\",\"kernel_version\":\"0.1.0\",\"abi_version\":2,\"profile_version\":2,\"profile_sha256\":\"abcdef\",\"log_build_mode\":\"production\",\"support_authorization_verified\":false}\n",
            "{\"sequence\":0,\"direction\":\"command\",\"context\":\"generic\",\"cla\":\"80\",\"ins\":\"ae\",\"p1\":\"80\",\"p2\":\"00\",\"data\":{\"type\":\"suppressed\",\"reason\":\"full-apdu-disabled\"},\"fields\":[]}\n",
            "{\"sequence\":1,\"direction\":\"response\",\"context\":\"generate-ac-response\",\"sw\":\"9000\",\"data\":{\"type\":\"suppressed\",\"reason\":\"tag-masked\"},\"fields\":[{\"tag\":\"9f26\",\"value\":{\"type\":\"suppressed\",\"reason\":\"transaction-cryptogram\"}}]}\n",
        )
        .to_string()
    }
}
