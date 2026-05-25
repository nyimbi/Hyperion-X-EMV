//! Coverage report package auditing for `CERT-OPEN-009`.
//!
//! The coverage workflow can generate local repository evidence, but that
//! evidence is not self-approving. This module checks whether the staged
//! coverage package has the files and metadata needed for review, and keeps the
//! boundary explicit: accepted external report review is still required before
//! `CERT-OPEN-009` can close.

use core::fmt::Write;
use std::fs;
use std::io;
use std::path::Path;

use crate::provenance::{sha256, to_hex};

pub const DEFAULT_COVERAGE_ROOT: &str = "target/coverage";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageMetadata {
    pub metadata_type: String,
    pub source_commit: String,
    pub cargo_version: String,
    pub rustc_version: String,
    pub target_triple: String,
    pub coverage_tool_version: String,
    pub workspace: bool,
    pub all_targets: bool,
    pub all_features: bool,
    pub line_coverage_threshold: u64,
    pub coverage_enforced: bool,
    pub html_report: String,
    pub readme: String,
    pub open_issue: String,
    pub does_not_close: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageAuditFile {
    pub path: &'static str,
    pub status: &'static str,
    pub size_bytes: u64,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoveragePackageAudit {
    pub root: String,
    pub status: &'static str,
    pub boundary: &'static str,
    pub metadata_status: &'static str,
    pub metadata: Option<CoverageMetadata>,
    pub files: Vec<CoverageAuditFile>,
    pub findings: Vec<String>,
}

pub fn audit_coverage_package(root: &Path) -> io::Result<CoveragePackageAudit> {
    let metadata_path = root.join("metadata.json");
    let readme_path = root.join("README.txt");
    let html_index_path = root.join("html").join("index.html");
    let files = vec![
        audit_coverage_file("metadata.json", &metadata_path)?,
        audit_coverage_file("README.txt", &readme_path)?,
        audit_coverage_file("html/index.html", &html_index_path)?,
    ];

    let mut findings = Vec::new();
    for file in &files {
        if file.status != "present" {
            findings.push(format!(
                "missing required coverage package file: {}",
                file.path
            ));
        }
    }

    let (metadata_status, metadata) = if metadata_path.is_file() {
        let text = fs::read_to_string(&metadata_path)?;
        match parse_coverage_metadata(&text) {
            Ok(metadata) => ("parsed", Some(metadata)),
            Err(err) => {
                findings.push(err);
                ("malformed", None)
            }
        }
    } else {
        ("missing", None)
    };

    if let Some(metadata) = &metadata {
        validate_coverage_metadata(metadata, &mut findings);
    }

    let status = classify_coverage_package(metadata.as_ref(), &findings);
    Ok(CoveragePackageAudit {
        root: root.display().to_string(),
        status,
        boundary: "coverage package audit only; accepted external report review is still required before CERT-OPEN-009 can close",
        metadata_status,
        metadata,
        files,
        findings,
    })
}

pub fn coverage_package_is_reviewable(audit: &CoveragePackageAudit) -> bool {
    matches!(
        audit.status,
        "measurement_only_unreviewed" | "certification_candidate_unreviewed"
    )
}

pub fn coverage_package_is_certification_candidate(audit: &CoveragePackageAudit) -> bool {
    audit.status == "certification_candidate_unreviewed"
}

pub fn coverage_package_audit_json(abi_version: u32, audit: &CoveragePackageAudit) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "coverage-package-audit");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "coverage_root", &audit.root);
    out.push(',');
    push_json_str(&mut out, "status", audit.status);
    out.push(',');
    push_json_str(&mut out, "boundary", audit.boundary);
    out.push(',');
    push_json_str(&mut out, "metadata_status", audit.metadata_status);
    out.push_str(",\"metadata\":");
    if let Some(metadata) = &audit.metadata {
        push_metadata_json(&mut out, metadata);
    } else {
        out.push_str("null");
    }
    out.push_str(",\"files\":[");
    for (index, file) in audit.files.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_file_json(&mut out, file);
    }
    out.push_str("],\"findings\":[");
    for (index, finding) in audit.findings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(&mut out, finding);
    }
    out.push_str("]}\n");
    out
}

pub fn coverage_package_audit_markdown(abi_version: u32, audit: &CoveragePackageAudit) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Coverage Package Audit");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Coverage root: `{}`", audit.root);
    let _ = writeln!(out, "- Status: `{}`", audit.status);
    let _ = writeln!(out, "- Boundary: {}", audit.boundary);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Files");
    let _ = writeln!(out, "| Path | Status | Size | SHA-256 |");
    let _ = writeln!(out, "| --- | --- | ---: | --- |");
    for file in &audit.files {
        let hash = file.sha256.as_deref().unwrap_or("n/a");
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | `{}` |",
            file.path, file.status, file.size_bytes, hash
        );
    }

    if let Some(metadata) = &audit.metadata {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Metadata");
        let _ = writeln!(out, "- Source commit: `{}`", metadata.source_commit);
        let _ = writeln!(out, "- Cargo: `{}`", metadata.cargo_version);
        let _ = writeln!(out, "- Rustc: `{}`", metadata.rustc_version);
        let _ = writeln!(out, "- Target triple: `{}`", metadata.target_triple);
        let _ = writeln!(out, "- Coverage tool: `{}`", metadata.coverage_tool_version);
        let _ = writeln!(
            out,
            "- Scope: workspace={}, all_targets={}, all_features={}",
            metadata.workspace, metadata.all_targets, metadata.all_features
        );
        let _ = writeln!(
            out,
            "- Threshold: {}% line coverage",
            metadata.line_coverage_threshold
        );
        let _ = writeln!(out, "- Enforcement mode: {}", metadata.coverage_enforced);
        let _ = writeln!(out, "- Open issue: `{}`", metadata.open_issue);
        let _ = writeln!(out, "- Does not close: `{}`", metadata.does_not_close);
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

fn audit_coverage_file(path: &'static str, full_path: &Path) -> io::Result<CoverageAuditFile> {
    if !full_path.is_file() {
        return Ok(CoverageAuditFile {
            path,
            status: "missing",
            size_bytes: 0,
            sha256: None,
        });
    }
    let bytes = fs::read(full_path)?;
    Ok(CoverageAuditFile {
        path,
        status: "present",
        size_bytes: bytes.len() as u64,
        sha256: Some(to_hex(&sha256(&bytes))),
    })
}

fn classify_coverage_package(
    metadata: Option<&CoverageMetadata>,
    findings: &[String],
) -> &'static str {
    let Some(metadata) = metadata else {
        return "missing_or_malformed";
    };
    if !findings.is_empty() {
        return "incomplete";
    }
    if metadata.coverage_enforced && metadata.line_coverage_threshold == 100 {
        "certification_candidate_unreviewed"
    } else {
        "measurement_only_unreviewed"
    }
}

fn validate_coverage_metadata(metadata: &CoverageMetadata, findings: &mut Vec<String>) {
    if metadata.metadata_type != "hyperion-coverage-report-metadata" {
        findings.push("metadata type must be hyperion-coverage-report-metadata".to_string());
    }
    if metadata.source_commit.is_empty() || metadata.source_commit == "unknown" {
        findings.push("metadata source_commit must name the submitted source commit".to_string());
    }
    if !metadata.workspace {
        findings.push("metadata workspace must be true".to_string());
    }
    if !metadata.all_targets {
        findings.push("metadata all_targets must be true".to_string());
    }
    if !metadata.all_features {
        findings.push("metadata all_features must be true".to_string());
    }
    if metadata.line_coverage_threshold != 100 {
        findings.push("metadata line_coverage_threshold must be 100".to_string());
    }
    if metadata.html_report != "target/coverage/html" {
        findings.push("metadata html_report must be target/coverage/html".to_string());
    }
    if metadata.readme != "target/coverage/README.txt" {
        findings.push("metadata readme must be target/coverage/README.txt".to_string());
    }
    if metadata.open_issue != "CERT-OPEN-009" {
        findings.push("metadata open_issue must be CERT-OPEN-009".to_string());
    }
    if metadata.does_not_close != "CERT-OPEN-009" {
        findings.push("metadata does_not_close must be CERT-OPEN-009".to_string());
    }
}

fn parse_coverage_metadata(input: &str) -> Result<CoverageMetadata, String> {
    Ok(CoverageMetadata {
        metadata_type: required_string(input, "type")?,
        source_commit: required_string(input, "source_commit")?,
        cargo_version: required_string(input, "cargo_version")?,
        rustc_version: required_string(input, "rustc_version")?,
        target_triple: required_string(input, "target_triple")?,
        coverage_tool_version: required_string(input, "coverage_tool_version")?,
        workspace: required_bool(input, "workspace")?,
        all_targets: required_bool(input, "all_targets")?,
        all_features: required_bool(input, "all_features")?,
        line_coverage_threshold: required_u64(input, "line_coverage_threshold")?,
        coverage_enforced: required_bool(input, "coverage_enforced")?,
        html_report: required_string(input, "html_report")?,
        readme: required_string(input, "readme")?,
        open_issue: required_string(input, "open_issue")?,
        does_not_close: required_string(input, "does_not_close")?,
    })
}

fn required_string(input: &str, key: &str) -> Result<String, String> {
    json_string_value(input, key).ok_or_else(|| format!("metadata field `{key}` is missing"))
}

fn required_bool(input: &str, key: &str) -> Result<bool, String> {
    json_bool_value(input, key).ok_or_else(|| format!("metadata field `{key}` is missing"))
}

fn required_u64(input: &str, key: &str) -> Result<u64, String> {
    json_u64_value(input, key).ok_or_else(|| format!("metadata field `{key}` is missing"))
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

fn json_bool_value(input: &str, key: &str) -> Option<bool> {
    let rest = json_field_tail(input, key)?;
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_u64_value(input: &str, key: &str) -> Option<u64> {
    let rest = json_field_tail(input, key)?;
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse().ok()
}

fn json_field_tail<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":");
    let start = input.find(&marker)? + marker.len();
    Some(input[start..].trim_start())
}

fn push_metadata_json(out: &mut String, metadata: &CoverageMetadata) {
    out.push('{');
    push_json_str(out, "type", &metadata.metadata_type);
    out.push(',');
    push_json_str(out, "source_commit", &metadata.source_commit);
    out.push(',');
    push_json_str(out, "cargo_version", &metadata.cargo_version);
    out.push(',');
    push_json_str(out, "rustc_version", &metadata.rustc_version);
    out.push(',');
    push_json_str(out, "target_triple", &metadata.target_triple);
    out.push(',');
    push_json_str(
        out,
        "coverage_tool_version",
        &metadata.coverage_tool_version,
    );
    out.push(',');
    push_json_bool(out, "workspace", metadata.workspace);
    out.push(',');
    push_json_bool(out, "all_targets", metadata.all_targets);
    out.push(',');
    push_json_bool(out, "all_features", metadata.all_features);
    out.push(',');
    push_json_number(
        out,
        "line_coverage_threshold",
        metadata.line_coverage_threshold,
    );
    out.push(',');
    push_json_bool(out, "coverage_enforced", metadata.coverage_enforced);
    out.push(',');
    push_json_str(out, "html_report", &metadata.html_report);
    out.push(',');
    push_json_str(out, "readme", &metadata.readme);
    out.push(',');
    push_json_str(out, "open_issue", &metadata.open_issue);
    out.push(',');
    push_json_str(out, "does_not_close", &metadata.does_not_close);
    out.push('}');
}

fn push_file_json(out: &mut String, file: &CoverageAuditFile) {
    out.push('{');
    push_json_str(out, "path", file.path);
    out.push(',');
    push_json_str(out, "status", file.status);
    out.push(',');
    push_json_number(out, "size_bytes", file.size_bytes);
    out.push_str(",\"sha256\":");
    if let Some(hash) = &file.sha256 {
        push_json_string(out, hash);
    } else {
        out.push_str("null");
    }
    out.push('}');
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
    fn missing_coverage_package_reports_missing_or_malformed_without_error() {
        let root = temp_root("missing");
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }

        let audit = audit_coverage_package(&root).unwrap();

        assert_eq!(audit.status, "missing_or_malformed");
        assert_eq!(audit.metadata_status, "missing");
        assert!(!coverage_package_is_reviewable(&audit));
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("metadata.json")));
    }

    #[test]
    fn measurement_coverage_package_is_reviewable_but_not_certification_candidate() {
        let root = temp_root("measurement");
        write_coverage_package(&root, false, 100).unwrap();

        let audit = audit_coverage_package(&root).unwrap();
        let json = coverage_package_audit_json(2, &audit);
        let markdown = coverage_package_audit_markdown(2, &audit);

        assert_eq!(audit.status, "measurement_only_unreviewed");
        assert!(coverage_package_is_reviewable(&audit));
        assert!(!coverage_package_is_certification_candidate(&audit));
        assert!(json.contains("\"type\":\"coverage-package-audit\""));
        assert!(json.contains("\"status\":\"measurement_only_unreviewed\""));
        assert!(json.contains("\"coverage_enforced\":false"));
        assert!(json.contains("\"does_not_close\":\"CERT-OPEN-009\""));
        assert!(markdown.contains("# Hyperion Coverage Package Audit"));
        assert!(markdown.contains("CERT-OPEN-009"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn enforcing_coverage_package_is_certification_candidate_but_not_approval() {
        let root = temp_root("enforced");
        write_coverage_package(&root, true, 100).unwrap();

        let audit = audit_coverage_package(&root).unwrap();

        assert_eq!(audit.status, "certification_candidate_unreviewed");
        assert!(coverage_package_is_reviewable(&audit));
        assert!(coverage_package_is_certification_candidate(&audit));
        assert_eq!(
            audit.boundary,
            "coverage package audit only; accepted external report review is still required before CERT-OPEN-009 can close"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn malformed_or_non_100_package_is_incomplete() {
        let root = temp_root("incomplete");
        write_coverage_package(&root, true, 99).unwrap();

        let audit = audit_coverage_package(&root).unwrap();

        assert_eq!(audit.status, "incomplete");
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding == "metadata line_coverage_threshold must be 100"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wrong_metadata_type_is_incomplete() {
        let root = temp_root("wrong-type");
        write_coverage_package(&root, true, 100).unwrap();
        let metadata_path = root.join("metadata.json");
        let metadata = fs::read_to_string(&metadata_path).unwrap();
        fs::write(
            &metadata_path,
            metadata.replace(
                "hyperion-coverage-report-metadata",
                "external-coverage-report",
            ),
        )
        .unwrap();

        let audit = audit_coverage_package(&root).unwrap();

        assert_eq!(audit.status, "incomplete");
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding == "metadata type must be hyperion-coverage-report-metadata"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn malformed_metadata_and_missing_files_report_all_blockers() {
        let root = temp_root("malformed-missing-files");
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("metadata.json"), b"{not json}").unwrap();

        let audit = audit_coverage_package(&root).unwrap();
        let json = coverage_package_audit_json(2, &audit);
        let markdown = coverage_package_audit_markdown(2, &audit);

        assert_eq!(audit.status, "missing_or_malformed");
        assert_eq!(audit.metadata_status, "malformed");
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("README.txt")));
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("html/index.html")));
        assert!(audit
            .findings
            .iter()
            .any(|finding| finding.contains("metadata field `type` is missing")));
        assert!(json.contains("\"metadata\":null"));
        assert!(json.contains("\"sha256\":null"));
        assert!(markdown.contains("## Findings"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn metadata_validator_reports_each_required_boolean_and_path_field() {
        let root = temp_root("bad-fields");
        write_coverage_package(&root, false, 100).unwrap();
        fs::write(
            root.join("metadata.json"),
            "{\"type\":\"hyperion-coverage-report-metadata\",\"source_commit\":\"unknown\",\"cargo_version\":\"cargo 1\",\"rustc_version\":\"rustc 1\",\"target_triple\":\"target\",\"coverage_tool_version\":\"tool\",\"workspace\":false,\"all_targets\":false,\"all_features\":false,\"line_coverage_threshold\":0,\"coverage_enforced\":false,\"html_report\":\"wrong/html\",\"readme\":\"wrong/README.txt\",\"open_issue\":\"WRONG\",\"does_not_close\":\"WRONG\"}",
        )
        .unwrap();

        let audit = audit_coverage_package(&root).unwrap();

        assert_eq!(audit.status, "incomplete");
        for expected in [
            "metadata source_commit must name the submitted source commit",
            "metadata workspace must be true",
            "metadata all_targets must be true",
            "metadata all_features must be true",
            "metadata line_coverage_threshold must be 100",
            "metadata html_report must be target/coverage/html",
            "metadata readme must be target/coverage/README.txt",
            "metadata open_issue must be CERT-OPEN-009",
            "metadata does_not_close must be CERT-OPEN-009",
        ] {
            assert!(
                audit.findings.iter().any(|finding| finding == expected),
                "missing {expected}"
            );
        }

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn audit_json_escapes_findings_and_metadata_values() {
        let audit = CoveragePackageAudit {
            root: "target/coverage\nroot".to_string(),
            status: "incomplete",
            boundary: "coverage boundary",
            metadata_status: "parsed",
            metadata: Some(CoverageMetadata {
                metadata_type: "hyperion-coverage-report-metadata".to_string(),
                source_commit: "abc\\def\"ghi".to_string(),
                cargo_version: "cargo\t1".to_string(),
                rustc_version: "rustc\r1".to_string(),
                target_triple: "target".to_string(),
                coverage_tool_version: "tool".to_string(),
                workspace: true,
                all_targets: true,
                all_features: true,
                line_coverage_threshold: 100,
                coverage_enforced: true,
                html_report: "target/coverage/html".to_string(),
                readme: "target/coverage/README.txt".to_string(),
                open_issue: "CERT-OPEN-009".to_string(),
                does_not_close: "CERT-OPEN-009".to_string(),
            }),
            files: vec![CoverageAuditFile {
                path: "metadata.json",
                status: "present",
                size_bytes: 1,
                sha256: Some("hash".to_string()),
            }],
            findings: vec!["quote \" slash \\ newline\n tab\t".to_string()],
        };

        let json = coverage_package_audit_json(2, &audit);

        assert!(json.contains("target/coverage\\nroot"));
        assert!(json.contains("abc\\\\def\\\"ghi"));
        assert!(json.contains("cargo\\t1"));
        assert!(json.contains("rustc\\r1"));
        assert!(json.contains("quote \\\" slash \\\\ newline\\n tab\\t"));
    }

    #[test]
    fn metadata_parsers_cover_escaped_unterminated_and_invalid_scalar_values() {
        assert_eq!(
            json_string_value(r#"{"field":"a\"b"}"#, "field"),
            Some("a\"b".to_string())
        );
        assert_eq!(
            json_string_value(r#"{"field":"unterminated"#, "field"),
            None
        );
        assert_eq!(json_bool_value(r#"{"flag":null}"#, "flag"), None);
        assert_eq!(json_u64_value(r#"{"count":null}"#, "count"), None);

        let mut out = String::new();
        let control = format!("control{}", char::from(0x1f));
        push_json_string(&mut out, &control);
        assert_eq!(out, "\"control\\u001f\"");
    }

    #[test]
    fn coverage_package_writer_replaces_existing_tree() {
        let root = temp_root("rewrite");
        write_coverage_package(&root, false, 99).unwrap();
        fs::write(root.join("stale.txt"), b"stale").unwrap();
        write_coverage_package(&root, true, 100).unwrap();

        assert!(!root.join("stale.txt").exists());
        let audit = audit_coverage_package(&root).unwrap();
        assert_eq!(audit.status, "certification_candidate_unreviewed");

        fs::remove_dir_all(&root).unwrap();
    }

    fn temp_root(label: &str) -> PathBuf {
        env::temp_dir().join(format!("hyperion-coverage-audit-{label}-{}", process::id()))
    }

    fn write_coverage_package(root: &Path, enforced: bool, threshold: u64) -> io::Result<()> {
        if root.exists() {
            fs::remove_dir_all(root)?;
        }
        fs::create_dir_all(root.join("html"))?;
        fs::write(
            root.join("README.txt"),
            b"Hyperion-X-EMV 100% coverage report staging directory.",
        )?;
        fs::write(root.join("html/index.html"), b"<html>coverage</html>")?;
        fs::write(
            root.join("metadata.json"),
            format!(
                "{{\"type\":\"hyperion-coverage-report-metadata\",\"source_commit\":\"abcdef0\",\"cargo_version\":\"cargo 1.70.0\",\"rustc_version\":\"rustc 1.70.0\",\"target_triple\":\"x86_64-unknown-linux-gnu\",\"coverage_tool_version\":\"cargo-llvm-cov 0.6.0\",\"workspace\":true,\"all_targets\":true,\"all_features\":true,\"line_coverage_threshold\":{threshold},\"coverage_enforced\":{enforced},\"html_report\":\"target/coverage/html\",\"readme\":\"target/coverage/README.txt\",\"open_issue\":\"CERT-OPEN-009\",\"does_not_close\":\"CERT-OPEN-009\"}}"
            ),
        )?;
        Ok(())
    }
}
