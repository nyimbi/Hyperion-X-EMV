//! Certification artifact importer and adapter registry.
//!
//! The importer is intentionally format-agnostic at the file boundary: real lab,
//! scheme, device, CAPK, vector, and report packages arrive in different
//! authority-specific formats. This module classifies those files into stable
//! Hyperion intake lanes, rejects unsafe containers, records deterministic
//! hashes, and leaves final semantic acceptance to the relevant authority gate.

use core::fmt::Write;
use std::fs;
use std::io;
use std::path::Path;

use crate::provenance::{sha256, to_hex};

pub const DEFAULT_CERTIFICATION_ARTIFACT_IMPORT_ROOT: &str = "target/hyperion-cert-artifact-import";
pub const MAX_IMPORTED_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_IMPORTED_ARTIFACTS_PER_ADAPTER: usize = 256;
const MAX_NORMALIZED_PATH_BYTES: usize = 240;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactAdapterSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub input_dir: &'static str,
    pub normalized_slot: &'static str,
    pub open_issues: &'static [&'static str],
    pub accepted_extensions: &'static [&'static str],
    pub required_metadata: &'static [&'static str],
    pub security_policy: &'static str,
}

pub const ARTIFACT_ADAPTER_SPECS: &[ArtifactAdapterSpec] = &[
    ArtifactAdapterSpec {
        id: "LAB-APPROVAL",
        title: "Lab and approval artifacts",
        input_dir: "lab",
        normalized_slot: "CERT-OPEN-001",
        open_issues: &["CERT-OPEN-001", "CERT-OPEN-011"],
        accepted_extensions: &["csv", "json", "md", "pdf", "txt", "xml"],
        required_metadata: &[
            "authority",
            "approval_reference",
            "claimed_interface",
            "submitted_binary_hash",
            "profile_hash",
        ],
        security_policy: "accept public approval, report, and conformance records only; private signing material is rejected",
    },
    ArtifactAdapterSpec {
        id: "SCHEME-PROFILE",
        title: "Scheme and acquirer profile data",
        input_dir: "scheme",
        normalized_slot: "CERT-OPEN-002",
        open_issues: &["CERT-OPEN-002", "CERT-OPEN-005", "CERT-OPEN-012"],
        accepted_extensions: &["csv", "json", "md", "txt", "xml"],
        required_metadata: &[
            "scheme",
            "authority",
            "retrieval_date",
            "profile_version",
            "signature_status",
        ],
        security_policy: "accept signed or countersigned public profile material; do not import issuer secrets or private keys",
    },
    ArtifactAdapterSpec {
        id: "CAPK",
        title: "CAPK authority data",
        input_dir: "capk",
        normalized_slot: "CERT-OPEN-003",
        open_issues: &["CERT-OPEN-003", "CERT-OPEN-004"],
        accepted_extensions: &["csv", "json", "md", "pem", "txt", "xml"],
        required_metadata: &[
            "rid",
            "key_index",
            "source",
            "retrieval_date",
            "expiry_date",
            "checksum",
        ],
        security_policy: "accept public CAPK provenance and checksum material only; private key containers are rejected",
    },
    ArtifactAdapterSpec {
        id: "VECTOR",
        title: "Lab vector and expected-output data",
        input_dir: "vectors",
        normalized_slot: "CERT-OPEN-004",
        open_issues: &["CERT-OPEN-004", "CERT-OPEN-009", "CERT-OPEN-012"],
        accepted_extensions: &["csv", "json", "md", "txt", "xml"],
        required_metadata: &[
            "vector_class",
            "vector_source",
            "tool_version",
            "method_coverage",
            "expected_outputs",
        ],
        security_policy: "accept complete vector data and expected outcomes; scenario summaries remain advisory until vectors validate",
    },
    ArtifactAdapterSpec {
        id: "DEVICE",
        title: "Device, L1, and PED evidence",
        input_dir: "device",
        normalized_slot: "CERT-OPEN-006",
        open_issues: &["CERT-OPEN-006", "CERT-OPEN-007"],
        accepted_extensions: &["csv", "json", "md", "pdf", "txt", "xml"],
        required_metadata: &[
            "device_model",
            "hardware_revision",
            "firmware_version",
            "l1_reference",
            "pci_pts_reference",
        ],
        security_policy: "accept device, reader, L1, and PED evidence; clear PIN data and private material are never accepted",
    },
    ArtifactAdapterSpec {
        id: "REPORT",
        title: "Coverage, integration, static, fuzz, trace, and security reports",
        input_dir: "reports",
        normalized_slot: "CERT-OPEN-009",
        open_issues: &[
            "CERT-OPEN-008",
            "CERT-OPEN-009",
            "CERT-OPEN-010",
            "CERT-OPEN-012",
        ],
        accepted_extensions: &[
            "csv", "html", "json", "lcov", "md", "pdf", "sarif", "txt", "xml",
        ],
        required_metadata: &[
            "tool_version",
            "command",
            "submitted_binary_hash",
            "profile_hash",
            "finding_disposition",
        ],
        security_policy: "accept masked reports and trace packs; unmasked PAN, PIN, cryptogram, or issuer-script payload evidence must remain external",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedArtifact {
    pub adapter_id: &'static str,
    pub normalized_slot: &'static str,
    pub source_path: String,
    pub normalized_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedArtifact {
    pub adapter_id: &'static str,
    pub source_path: String,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterImport {
    pub spec: &'static ArtifactAdapterSpec,
    pub status: &'static str,
    pub imported: Vec<ImportedArtifact>,
    pub rejected: Vec<RejectedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactImportReport {
    pub root: String,
    pub adapters: Vec<AdapterImport>,
}

pub fn certification_artifact_adapter_specs() -> &'static [ArtifactAdapterSpec] {
    ARTIFACT_ADAPTER_SPECS
}

pub fn import_certification_artifacts(root: &Path) -> io::Result<ArtifactImportReport> {
    let mut adapters = Vec::new();
    for spec in ARTIFACT_ADAPTER_SPECS {
        adapters.push(import_adapter(root, spec)?);
    }
    Ok(ArtifactImportReport {
        root: root.display().to_string(),
        adapters,
    })
}

pub fn certification_artifact_import_plan_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-artifact-import-plan");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "format-agnostic adapters for real lab, scheme, CAPK, vector, device, and report artifacts",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "boundary",
        "hash inventory and intake normalization only; external authorities still decide acceptance",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "integration_manifest",
        "hyperion-integration-manifest.json files may map imported authority artifacts into bundle fields, artifact hash bindings, evidence slots, and release-freeze slots without source changes",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "integration_manifest_schema",
        "hyperion-certification-integration-manifest-1.0",
    );
    out.push_str(",\"adapters\":[");
    for (idx, spec) in ARTIFACT_ADAPTER_SPECS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_adapter_spec_json(&mut out, spec);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_artifact_import_plan_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Artifact Import Plan");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(
        out,
        "- Scope: format-agnostic adapters for real lab, scheme, CAPK, vector, device, and report artifacts"
    );
    let _ = writeln!(
        out,
        "- Boundary: hash inventory and intake normalization only; external authorities still decide acceptance."
    );
    let _ = writeln!(
        out,
        "- Integration manifest: `hyperion-integration-manifest.json` files may map imported authority artifacts into bundle fields, artifact hash bindings, evidence slots, and release-freeze slots without source changes."
    );
    let _ = writeln!(
        out,
        "- Integration manifest schema: `hyperion-certification-integration-manifest-1.0`."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Adapter Lanes");
    let _ = writeln!(
        out,
        "| Adapter | Input Directory | Slot | Open Issues | Accepted Extensions | Required Metadata | Security Policy |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |");
    for spec in ARTIFACT_ADAPTER_SPECS {
        let _ = writeln!(
            out,
            "| {} | `{}` | `{}` | {} | {} | {} | {} |",
            spec.title,
            spec.input_dir,
            spec.normalized_slot,
            spec.open_issues.join(", "),
            spec.accepted_extensions.join(", "),
            spec.required_metadata.join(", "),
            spec.security_policy
        );
    }
    out
}

pub fn certification_artifact_import_report_json(
    abi_version: u32,
    report: &ArtifactImportReport,
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-artifact-import-report");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "root", &report.root);
    out.push(',');
    push_json_str(
        &mut out,
        "boundary",
        "adapter classification and SHA-256 inventory only; it does not close certification open issues",
    );
    out.push_str(",\"adapters\":[");
    for (idx, adapter) in report.adapters.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_adapter_import_json(&mut out, adapter);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_artifact_import_report_markdown(
    abi_version: u32,
    report: &ArtifactImportReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Artifact Import Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Root: `{}`", report.root);
    let _ = writeln!(
        out,
        "- Boundary: adapter classification and SHA-256 inventory only; it does not close certification open issues."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Adapter Results");
    let _ = writeln!(
        out,
        "| Adapter | Status | Imported | Rejected | Required Metadata |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for adapter in &report.adapters {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            adapter.spec.id,
            adapter.status,
            adapter.imported.len(),
            adapter.rejected.len(),
            adapter.spec.required_metadata.join(", ")
        );
    }
    for adapter in &report.adapters {
        if !adapter.imported.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "### {} Imported Files", adapter.spec.id);
            for artifact in &adapter.imported {
                let _ = writeln!(
                    out,
                    "- `{}` -> `{}` ({} bytes, SHA-256 `{}`)",
                    artifact.source_path,
                    artifact.normalized_path,
                    artifact.size_bytes,
                    artifact.sha256
                );
            }
        }
        if !adapter.rejected.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "### {} Rejected Files", adapter.spec.id);
            for rejection in &adapter.rejected {
                let _ = writeln!(out, "- `{}`: {}", rejection.source_path, rejection.reason);
            }
        }
    }
    out
}

fn import_adapter(root: &Path, spec: &'static ArtifactAdapterSpec) -> io::Result<AdapterImport> {
    let input = root.join(spec.input_dir);
    let mut imported = Vec::new();
    let mut rejected = Vec::new();
    if input.is_dir() {
        collect_adapter_files(root, &input, spec, 0, &mut imported, &mut rejected)?;
        imported.sort_by(|left, right| left.normalized_path.cmp(&right.normalized_path));
        rejected.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    }
    let status = adapter_status(&imported, &rejected);
    Ok(AdapterImport {
        spec,
        status,
        imported,
        rejected,
    })
}

fn collect_adapter_files(
    root: &Path,
    dir: &Path,
    spec: &'static ArtifactAdapterSpec,
    depth: usize,
    imported: &mut Vec<ImportedArtifact>,
    rejected: &mut Vec<RejectedArtifact>,
) -> io::Result<()> {
    if depth > 8 {
        rejected.push(RejectedArtifact {
            adapter_id: spec.id,
            source_path: normalize_path(root, dir),
            reason: "directory-depth-limit",
        });
        return Ok(());
    }
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_adapter_files(root, &path, spec, depth + 1, imported, rejected)?;
        } else if file_type.is_file() {
            classify_file(root, &path, spec, imported, rejected)?;
        } else {
            rejected.push(RejectedArtifact {
                adapter_id: spec.id,
                source_path: normalize_path(root, &path),
                reason: "unsupported-file-type",
            });
        }
    }
    Ok(())
}

fn classify_file(
    root: &Path,
    path: &Path,
    spec: &'static ArtifactAdapterSpec,
    imported: &mut Vec<ImportedArtifact>,
    rejected: &mut Vec<RejectedArtifact>,
) -> io::Result<()> {
    let source_path = normalize_path(root, path);
    if source_path.len() > MAX_NORMALIZED_PATH_BYTES {
        rejected.push(RejectedArtifact {
            adapter_id: spec.id,
            source_path,
            reason: "path-too-long",
        });
        return Ok(());
    }
    if imported.len() >= MAX_IMPORTED_ARTIFACTS_PER_ADAPTER {
        rejected.push(RejectedArtifact {
            adapter_id: spec.id,
            source_path,
            reason: "adapter-file-count-limit",
        });
        return Ok(());
    }
    let lower_name = source_path.to_ascii_lowercase();
    if lower_name.contains("private")
        || lower_name.ends_with(".key")
        || lower_name.ends_with(".p12")
        || lower_name.ends_with(".pfx")
    {
        rejected.push(RejectedArtifact {
            adapter_id: spec.id,
            source_path,
            reason: "private-key-material-not-accepted",
        });
        return Ok(());
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !spec
        .accepted_extensions
        .iter()
        .any(|accepted| *accepted == extension)
    {
        rejected.push(RejectedArtifact {
            adapter_id: spec.id,
            source_path,
            reason: "unsupported-extension",
        });
        return Ok(());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_IMPORTED_ARTIFACT_BYTES {
        rejected.push(RejectedArtifact {
            adapter_id: spec.id,
            source_path,
            reason: "file-too-large",
        });
        return Ok(());
    }
    let bytes = fs::read(path)?;
    imported.push(ImportedArtifact {
        adapter_id: spec.id,
        normalized_slot: spec.normalized_slot,
        normalized_path: format!("{}/{}", spec.normalized_slot, source_path),
        source_path,
        size_bytes: bytes.len() as u64,
        sha256: to_hex(&sha256(&bytes)),
    });
    Ok(())
}

fn adapter_status(imported: &[ImportedArtifact], rejected: &[RejectedArtifact]) -> &'static str {
    match (imported.is_empty(), rejected.is_empty()) {
        (true, true) => "missing",
        (true, false) => "rejected_unreviewed",
        (false, true) => "imported_unreviewed",
        (false, false) => "imported_unreviewed_with_rejections",
    }
}

fn normalize_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn push_adapter_spec_json(out: &mut String, spec: &ArtifactAdapterSpec) {
    out.push('{');
    push_json_str(out, "id", spec.id);
    out.push(',');
    push_json_str(out, "title", spec.title);
    out.push(',');
    push_json_str(out, "input_dir", spec.input_dir);
    out.push(',');
    push_json_str(out, "normalized_slot", spec.normalized_slot);
    out.push_str(",\"open_issues\":[");
    push_json_array(out, spec.open_issues);
    out.push_str("],\"accepted_extensions\":[");
    push_json_array(out, spec.accepted_extensions);
    out.push_str("],\"required_metadata\":[");
    push_json_array(out, spec.required_metadata);
    out.push_str("],");
    push_json_str(out, "security_policy", spec.security_policy);
    out.push('}');
}

fn push_adapter_import_json(out: &mut String, adapter: &AdapterImport) {
    out.push('{');
    push_json_str(out, "adapter_id", adapter.spec.id);
    out.push(',');
    push_json_str(out, "title", adapter.spec.title);
    out.push(',');
    push_json_str(out, "status", adapter.status);
    out.push(',');
    push_json_str(out, "input_dir", adapter.spec.input_dir);
    out.push(',');
    push_json_str(out, "normalized_slot", adapter.spec.normalized_slot);
    out.push_str(",\"open_issues\":[");
    push_json_array(out, adapter.spec.open_issues);
    out.push_str("],\"required_metadata\":[");
    push_json_array(out, adapter.spec.required_metadata);
    out.push_str("],\"imported\":[");
    for (idx, artifact) in adapter.imported.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_imported_artifact_json(out, artifact);
    }
    out.push_str("],\"rejected\":[");
    for (idx, rejection) in adapter.rejected.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_rejected_artifact_json(out, rejection);
    }
    out.push_str("]}");
}

fn push_imported_artifact_json(out: &mut String, artifact: &ImportedArtifact) {
    out.push('{');
    push_json_str(out, "adapter_id", artifact.adapter_id);
    out.push(',');
    push_json_str(out, "normalized_slot", artifact.normalized_slot);
    out.push(',');
    push_json_str(out, "source_path", &artifact.source_path);
    out.push(',');
    push_json_str(out, "normalized_path", &artifact.normalized_path);
    out.push(',');
    push_json_number(out, "size_bytes", artifact.size_bytes);
    out.push(',');
    push_json_str(out, "sha256", &artifact.sha256);
    out.push('}');
}

fn push_rejected_artifact_json(out: &mut String, rejection: &RejectedArtifact) {
    out.push('{');
    push_json_str(out, "adapter_id", rejection.adapter_id);
    out.push(',');
    push_json_str(out, "source_path", &rejection.source_path);
    out.push(',');
    push_json_str(out, "reason", rejection.reason);
    out.push('}');
}

fn push_json_array(out: &mut String, values: &[&str]) {
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
    use std::env;
    use std::process;

    #[test]
    fn import_plan_documents_all_real_artifact_lanes_without_closure_claims() {
        let json = certification_artifact_import_plan_json(2);
        let markdown = certification_artifact_import_plan_markdown(2);

        assert!(json.contains("\"type\":\"certification-artifact-import-plan\""));
        assert!(json.contains("\"id\":\"LAB-APPROVAL\""));
        assert!(json.contains("\"id\":\"SCHEME-PROFILE\""));
        assert!(json.contains("\"id\":\"CAPK\""));
        assert!(json.contains("\"id\":\"VECTOR\""));
        assert!(json.contains("\"id\":\"DEVICE\""));
        assert!(json.contains("\"id\":\"REPORT\""));
        assert!(json.contains("external authorities still decide acceptance"));
        assert!(!json.contains("\"certified\":true"));
        assert!(markdown.contains("# Hyperion Certification Artifact Import Plan"));
        assert!(markdown.contains("private signing material is rejected"));
        assert_eq!(certification_artifact_adapter_specs().len(), 6);
    }

    #[test]
    fn import_report_classifies_hashes_and_rejections_by_adapter() {
        let root = env::temp_dir().join(format!("hyperion-artifact-import-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("lab/nested")).unwrap();
        fs::create_dir_all(root.join("scheme")).unwrap();
        fs::create_dir_all(root.join("capk")).unwrap();
        fs::create_dir_all(root.join("vectors")).unwrap();
        fs::create_dir_all(root.join("device")).unwrap();
        fs::create_dir_all(root.join("reports")).unwrap();
        fs::write(root.join("lab/nested/loa.pdf"), b"approval").unwrap();
        fs::write(root.join("scheme/profile.json"), b"scheme").unwrap();
        fs::write(root.join("capk/public.pem"), b"capk").unwrap();
        fs::write(root.join("vectors/oda.xml"), b"vectors").unwrap();
        fs::write(root.join("device/l1.txt"), b"device").unwrap();
        fs::write(root.join("reports/coverage.lcov"), b"coverage").unwrap();
        fs::write(root.join("reports/private-key.p12"), b"secret").unwrap();
        fs::write(root.join("reports/raw.bin"), b"bin").unwrap();

        let report = import_certification_artifacts(&root).unwrap();
        let json = certification_artifact_import_report_json(2, &report);
        let markdown = certification_artifact_import_report_markdown(2, &report);

        assert_eq!(report.adapters.len(), 6);
        assert!(report
            .adapters
            .iter()
            .any(|adapter| adapter.status == "imported_unreviewed_with_rejections"));
        assert!(json.contains("\"type\":\"certification-artifact-import-report\""));
        assert!(json.contains("\"normalized_path\":\"CERT-OPEN-001/lab/nested/loa.pdf\""));
        assert!(json.contains(&to_hex(&sha256(b"approval"))));
        assert!(json.contains("private-key-material-not-accepted"));
        assert!(json.contains("unsupported-extension"));
        assert!(markdown.contains("# Hyperion Certification Artifact Import Report"));
        assert!(markdown.contains("REPORT Rejected Files"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn import_report_covers_resource_limits_and_unusual_file_types() {
        let root = env::temp_dir().join(format!(
            "hyperion-artifact-import-resource-{}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("lab")).unwrap();
        for idx in 0..=MAX_IMPORTED_ARTIFACTS_PER_ADAPTER {
            fs::write(root.join("lab").join(format!("approval-{idx}.pdf")), b"ok").unwrap();
        }
        let large = root.join("scheme/large.json");
        fs::create_dir_all(large.parent().unwrap()).unwrap();
        let large_file = fs::File::create(&large).unwrap();
        large_file.set_len(MAX_IMPORTED_ARTIFACT_BYTES + 1).unwrap();
        let mut deep = root.join("vectors");
        for idx in 0..10 {
            deep = deep.join(format!("d{idx}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("vector.json"), b"vector").unwrap();
        fs::create_dir_all(root.join("device")).unwrap();
        fs::write(root.join("device/private.key"), b"private").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("approval-0.pdf", root.join("lab/link.pdf")).unwrap();
        }

        let report = import_certification_artifacts(&root).unwrap();
        let lab = report
            .adapters
            .iter()
            .find(|adapter| adapter.spec.id == "LAB-APPROVAL")
            .unwrap();
        assert!(lab
            .rejected
            .iter()
            .any(|item| item.reason == "adapter-file-count-limit"));
        #[cfg(unix)]
        assert!(lab
            .rejected
            .iter()
            .any(|item| item.reason == "unsupported-file-type"));
        let scheme = report
            .adapters
            .iter()
            .find(|adapter| adapter.spec.id == "SCHEME-PROFILE")
            .unwrap();
        assert_eq!(scheme.status, "rejected_unreviewed");
        assert!(scheme
            .rejected
            .iter()
            .any(|item| item.reason == "file-too-large"));
        let vector = report
            .adapters
            .iter()
            .find(|adapter| adapter.spec.id == "VECTOR")
            .unwrap();
        assert!(vector
            .rejected
            .iter()
            .any(|item| item.reason == "directory-depth-limit"));
        let device = report
            .adapters
            .iter()
            .find(|adapter| adapter.spec.id == "DEVICE")
            .unwrap();
        assert!(device
            .rejected
            .iter()
            .any(|item| item.reason == "private-key-material-not-accepted"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn import_report_json_escapes_control_and_non_ascii_values() {
        let report = ArtifactImportReport {
            root: "root\n\t\\\"\u{00a9}".to_string(),
            adapters: vec![AdapterImport {
                spec: &ARTIFACT_ADAPTER_SPECS[0],
                status: "imported_unreviewed_with_rejections",
                imported: vec![
                    ImportedArtifact {
                        adapter_id: "LAB-APPROVAL",
                        normalized_slot: "CERT-OPEN-001",
                        source_path: "lab/a.pdf".to_string(),
                        normalized_path: "CERT-OPEN-001/lab/a.pdf".to_string(),
                        size_bytes: 1,
                        sha256: "00".repeat(32),
                    },
                    ImportedArtifact {
                        adapter_id: "LAB-APPROVAL",
                        normalized_slot: "CERT-OPEN-001",
                        source_path: "lab/b.pdf".to_string(),
                        normalized_path: "CERT-OPEN-001/lab/b.pdf".to_string(),
                        size_bytes: 2,
                        sha256: "11".repeat(32),
                    },
                ],
                rejected: vec![RejectedArtifact {
                    adapter_id: "LAB-APPROVAL",
                    source_path: "lab/bad\r.bin".to_string(),
                    reason: "unsupported-extension",
                }],
            }],
        };

        let json = certification_artifact_import_report_json(2, &report);
        assert!(json.contains("root\\n\\t\\\\\\\"\\u00c2\\u00a9"));
        assert!(json.contains("lab/bad\\r.bin"));
        assert!(json.contains("},{\"adapter_id\":\"LAB-APPROVAL\""));
    }

    #[test]
    fn import_report_handles_missing_oversized_and_resource_rejection_paths() {
        let root =
            env::temp_dir().join(format!("hyperion-artifact-import-limits-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("lab")).unwrap();
        let long_name = format!("{}.pdf", "a".repeat(MAX_NORMALIZED_PATH_BYTES));
        fs::write(root.join("lab").join(long_name), b"path").unwrap();
        fs::write(root.join("lab/approval.pdf"), b"ok").unwrap();

        let mut report = import_certification_artifacts(&root).unwrap();
        let lab = report
            .adapters
            .iter()
            .find(|adapter| adapter.spec.id == "LAB-APPROVAL")
            .unwrap();
        assert_eq!(lab.status, "imported_unreviewed_with_rejections");
        assert!(lab
            .rejected
            .iter()
            .any(|item| item.reason == "path-too-long"));

        report
            .adapters
            .retain(|adapter| adapter.spec.id == "VECTOR");
        assert_eq!(report.adapters[0].status, "missing");
        let json = certification_artifact_import_report_json(2, &report);
        assert!(json.contains("\"status\":\"missing\""));

        fs::remove_dir_all(&root).unwrap();
    }
}
