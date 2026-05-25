//! Certification integration import compiler.
//!
//! This module bridges raw external artifacts and the data-driven Hyperion
//! certification surfaces. Real lab, scheme, acquirer, device, CAPK, vector,
//! trace, and report packages can arrive in proprietary or authority-specific
//! formats. The stable boundary here is a strict normalized manifest plus a
//! deterministic hash inventory: adapters may map any real input format into
//! `hyperion-integration-manifest.json`, and the rest of the kernel can bind
//! those artifacts to bundle, evidence, report, and release-freeze surfaces
//! without source changes.

use core::fmt::Write;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::artifact_import::{
    import_certification_artifacts, AdapterImport, ArtifactImportReport, ImportedArtifact,
    RejectedArtifact, ARTIFACT_ADAPTER_SPECS,
};
use crate::cert_bundle::ArtifactHashBinding;
use crate::config::{JsonParser, JsonValue};
use crate::error::{KernelError, KernelResult};

pub const CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION: &str =
    "hyperion-certification-integration-manifest-1.0";
pub const CERTIFICATION_INTEGRATION_MANIFEST_FILE: &str = "hyperion-integration-manifest.json";
pub const MAX_INTEGRATION_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_INTEGRATION_FINDINGS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationIntegrationReport {
    pub root: String,
    pub status: &'static str,
    pub import_report: ArtifactImportReport,
    pub normalized_artifacts: Vec<NormalizedCertificationArtifact>,
    pub bundle_bindings: Vec<ArtifactHashBinding>,
    pub freeze_bindings: Vec<ReleaseFreezeBinding>,
    pub findings: Vec<IntegrationFinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCertificationArtifact {
    pub adapter_id: &'static str,
    pub source_path: String,
    pub normalized_path: String,
    pub artifact_id: String,
    pub artifact_kind: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
    pub binds_open_issues: Vec<String>,
    pub bundle_field: Option<String>,
    pub freeze_artifact_id: Option<String>,
    pub semantic_status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFreezeBinding {
    pub freeze_artifact_id: &'static str,
    pub title: &'static str,
    pub artifact_kind: &'static str,
    pub source_path: Option<String>,
    pub sha256_hex: Option<String>,
    pub status: &'static str,
    pub required_metadata: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationFinding {
    pub severity: &'static str,
    pub source_path: String,
    pub code: &'static str,
    pub message: String,
    pub suggestion: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntegrationManifest {
    source_path: String,
    manifest_id: String,
    authority: String,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestArtifact {
    path: String,
    adapter_id: Option<String>,
    artifact_id: String,
    artifact_kind: String,
    binds_open_issues: Vec<String>,
    bundle_field: Option<String>,
    freeze_artifact_id: Option<String>,
    expected_sha256_hex: Option<String>,
    metadata: Vec<String>,
}

struct FreezeTarget {
    id: &'static str,
    title: &'static str,
    artifact_kind: &'static str,
    required_metadata: &'static [&'static str],
}

const FREEZE_TARGETS: &[FreezeTarget] = &[
    FreezeTarget {
        id: "kernel_binary_hash",
        title: "Submitted kernel binary",
        artifact_kind: "build artifact",
        required_metadata: &[
            "target_triple",
            "build_profile",
            "cargo_version",
            "rustc_version",
            "abi_version",
        ],
    },
    FreezeTarget {
        id: "config_bundle_hash",
        title: "Signed runtime configuration bundle",
        artifact_kind: "signed configuration",
        required_metadata: &[
            "profile_version",
            "signature_status",
            "rollback_counter",
            "retrieval_date",
        ],
    },
    FreezeTarget {
        id: "scheme_profile_hash",
        title: "Scheme/acquirer-approved profile bundle",
        artifact_kind: "scheme profile",
        required_metadata: &[
            "authority",
            "scheme_set",
            "aid_set",
            "kernel_mapping",
            "profile_signature",
        ],
    },
    FreezeTarget {
        id: "capk_bundle_hash",
        title: "Scheme/acquirer-approved CAPK bundle",
        artifact_kind: "public key material",
        required_metadata: &[
            "capk_source",
            "retrieval_date",
            "expiry_set",
            "checksum_set",
            "approval_reference",
        ],
    },
    FreezeTarget {
        id: "test_vector_hash",
        title: "Lab-supplied ODA and APDU test-vector bundle",
        artifact_kind: "test vectors",
        required_metadata: &[
            "vector_class",
            "tool_version",
            "method_coverage",
            "expected_outputs",
            "bundle_authority",
        ],
    },
    FreezeTarget {
        id: "trace_pack_hash",
        title: "Full masked APDU and outcome trace pack",
        artifact_kind: "trace pack",
        required_metadata: &[
            "trace_pack_hash",
            "test_tool_version",
            "lab_case_ids",
            "profile_hash",
            "submitted_binary_hash",
        ],
    },
    FreezeTarget {
        id: "coverage_report_hash",
        title: "Accepted 100% coverage report package",
        artifact_kind: "quality report",
        required_metadata: &[
            "source_commit",
            "coverage_tool_version",
            "coverage_enforced",
            "target_triple",
            "feature_set",
        ],
    },
    FreezeTarget {
        id: "static_fuzz_report_hash",
        title: "Accepted static-analysis and fuzzing report package",
        artifact_kind: "quality report",
        required_metadata: &[
            "tool_versions",
            "commands",
            "sanitizer_set",
            "corpus_hashes",
            "run_budget",
            "finding_dispositions",
        ],
    },
    FreezeTarget {
        id: "approval_package_hash",
        title: "Signed approval and conformance package",
        artifact_kind: "approval artifact",
        required_metadata: &[
            "signer",
            "signature_date",
            "template_version",
            "claimed_scope",
            "approval_reference",
        ],
    },
];

pub fn compile_certification_integration_artifacts(
    root: &Path,
) -> io::Result<CertificationIntegrationReport> {
    let import_report = import_certification_artifacts(root)?;
    let mut findings = Vec::new();
    let manifests = load_integration_manifests(root, &mut findings)?;
    let mut normalized_artifacts = Vec::new();
    for adapter in &import_report.adapters {
        for artifact in &adapter.imported {
            normalized_artifacts.push(normalize_artifact(
                adapter,
                artifact,
                &manifests,
                &mut findings,
            ));
        }
        for rejection in &adapter.rejected {
            push_rejection_finding(&mut findings, rejection);
        }
    }
    for manifest in &manifests {
        for artifact in &manifest.artifacts {
            let manifest_path = manifest_artifact_source_path(artifact);
            if !normalized_artifacts
                .iter()
                .any(|item| item.source_path == manifest_path)
            {
                push_finding(
                    &mut findings,
                    "error",
                    &manifest.source_path,
                    "manifest-artifact-missing",
                    format!(
                        "Manifest `{}` references `{}` but no imported artifact matched it.",
                        manifest.manifest_id, manifest_path
                    ),
                    "Place the referenced file under the adapter input directory or fix the manifest path.",
                );
            }
        }
    }
    normalized_artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let bundle_bindings = bundle_bindings_from_normalized(&normalized_artifacts, &mut findings);
    let freeze_bindings = release_freeze_bindings(&normalized_artifacts);
    let status = report_status(&findings, &normalized_artifacts);
    Ok(CertificationIntegrationReport {
        root: root.display().to_string(),
        status,
        import_report,
        normalized_artifacts,
        bundle_bindings,
        freeze_bindings,
        findings,
    })
}

pub fn certification_integration_import_report_json(
    abi_version: u32,
    report: &CertificationIntegrationReport,
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-integration-import-report");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "status", report.status);
    out.push(',');
    push_json_str(&mut out, "root", &report.root);
    out.push(',');
    push_json_str(
        &mut out,
        "manifest_schema",
        CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
    );
    out.push(',');
    push_json_str(
        &mut out,
        "boundary",
        "normalization, hash binding, and release-freeze preparation only; external authorities still decide acceptance",
    );
    out.push_str(",\"normalized_artifacts\":[");
    for (idx, artifact) in report.normalized_artifacts.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_normalized_artifact_json(&mut out, artifact);
    }
    out.push_str("],\"bundle_artifact_hashes\":[");
    for (idx, binding) in report.bundle_bindings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_bundle_binding_json(&mut out, binding);
    }
    out.push_str("],\"release_freeze_bindings\":[");
    for (idx, binding) in report.freeze_bindings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_freeze_binding_json(&mut out, binding);
    }
    out.push_str("],\"findings\":[");
    for (idx, finding) in report.findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_finding_json(&mut out, finding);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_integration_import_report_markdown(
    abi_version: u32,
    report: &CertificationIntegrationReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Integration Import Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Status: `{}`", report.status);
    let _ = writeln!(out, "- Root: `{}`", report.root);
    let _ = writeln!(
        out,
        "- Manifest schema: `{}`",
        CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
    );
    let _ = writeln!(out, "- Boundary: normalization, hash binding, and release-freeze preparation only; external authorities still decide acceptance.");
    let _ = writeln!(out);
    let _ = writeln!(out, "## Normalized Artifacts");
    let _ = writeln!(
        out,
        "| Artifact ID | Adapter | Source | Kind | Status | Bundle Field | Freeze Slot | SHA-256 |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for artifact in &report.normalized_artifacts {
        let _ = writeln!(
            out,
            "| `{}` | {} | `{}` | {} | {} | {} | {} | `{}` |",
            artifact.artifact_id,
            artifact.adapter_id,
            artifact.source_path,
            artifact.artifact_kind,
            artifact.semantic_status,
            artifact.bundle_field.as_deref().unwrap_or("none"),
            artifact.freeze_artifact_id.as_deref().unwrap_or("none"),
            artifact.sha256_hex
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Release Freeze Bindings");
    let _ = writeln!(
        out,
        "| Freeze Artifact | Status | Source | SHA-256 | Required Metadata |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for binding in &report.freeze_bindings {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            binding.freeze_artifact_id,
            binding.status,
            binding.source_path.as_deref().unwrap_or("pending"),
            binding.sha256_hex.as_deref().unwrap_or("pending"),
            binding.required_metadata.join(", ")
        );
    }
    if !report.findings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Findings");
        for finding in &report.findings {
            let _ = writeln!(
                out,
                "- `{}` `{}` `{}`: {} Suggestion: {}",
                finding.severity,
                finding.code,
                finding.source_path,
                finding.message,
                finding.suggestion
            );
        }
    }
    out
}

pub fn certification_release_freeze_json(
    abi_version: u32,
    report: &CertificationIntegrationReport,
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-release-freeze");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(&mut out, "status", report.status);
    out.push(',');
    push_json_str(&mut out, "source_root", &report.root);
    out.push(',');
    push_json_str(
        &mut out,
        "boundary",
        "repeatable release hash binding only; authority acceptance remains external",
    );
    out.push_str(",\"release_freeze_bindings\":[");
    for (idx, binding) in report.freeze_bindings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_freeze_binding_json(&mut out, binding);
    }
    out.push_str("],\"bundle_artifact_hashes\":[");
    for (idx, binding) in report.bundle_bindings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_bundle_binding_json(&mut out, binding);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_release_freeze_markdown(
    abi_version: u32,
    report: &CertificationIntegrationReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Release Freeze");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Status: `{}`", report.status);
    let _ = writeln!(out, "- Source root: `{}`", report.root);
    let _ = writeln!(
        out,
        "- Boundary: repeatable release hash binding only; authority acceptance remains external."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Freeze Artifact | Status | Bound Source | SHA-256 | Required Metadata |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for binding in &report.freeze_bindings {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            binding.freeze_artifact_id,
            binding.status,
            binding.source_path.as_deref().unwrap_or("pending"),
            binding.sha256_hex.as_deref().unwrap_or("pending"),
            binding.required_metadata.join(", ")
        );
    }
    out
}

pub fn certification_bundle_artifact_bindings(
    report: &CertificationIntegrationReport,
) -> &[ArtifactHashBinding] {
    &report.bundle_bindings
}

fn load_integration_manifests(
    root: &Path,
    findings: &mut Vec<IntegrationFinding>,
) -> io::Result<Vec<IntegrationManifest>> {
    let mut manifests = Vec::new();
    let root_manifest = root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE);
    if root_manifest.is_file() {
        read_manifest(root, &root_manifest, findings, &mut manifests)?;
    }
    for spec in ARTIFACT_ADAPTER_SPECS {
        let path = root
            .join(spec.input_dir)
            .join(CERTIFICATION_INTEGRATION_MANIFEST_FILE);
        if path.is_file() {
            read_manifest(root, &path, findings, &mut manifests)?;
        }
    }
    manifests.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    Ok(manifests)
}

fn read_manifest(
    root: &Path,
    path: &Path,
    findings: &mut Vec<IntegrationFinding>,
    manifests: &mut Vec<IntegrationManifest>,
) -> io::Result<()> {
    let bytes = fs::read(path)?;
    let source_path = normalize_path(root, path);
    if bytes.len() > MAX_INTEGRATION_MANIFEST_BYTES {
        push_finding(
            findings,
            "error",
            &source_path,
            "manifest-too-large",
            "Integration manifest exceeds the maximum accepted size.".to_string(),
            "Split the manifest or remove non-essential authority payload data.",
        );
        return Ok(());
    }
    match parse_integration_manifest(&bytes, &source_path) {
        Ok(manifest) => manifests.push(manifest),
        Err(err) => push_finding(
            findings,
            "error",
            &source_path,
            "manifest-parse-failed",
            format!("Integration manifest failed strict schema validation: {err}."),
            "Use the documented manifest schema and keep proprietary payload bytes in referenced artifacts.",
        ),
    }
    Ok(())
}

fn parse_integration_manifest(
    input: &[u8],
    source_path: &str,
) -> KernelResult<IntegrationManifest> {
    let root = JsonParser::new(input).parse()?;
    let object = root.as_object()?;
    reject_unknown_fields(
        object,
        &["schema_version", "manifest_id", "authority", "artifacts"],
    )?;
    if required_string(object, "schema_version")?
        != CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
    {
        return Err(KernelError::InvalidProfile);
    }
    let artifacts = object
        .get("artifacts")
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    if artifacts.is_empty() || artifacts.len() > 128 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(IntegrationManifest {
        source_path: source_path.to_string(),
        manifest_id: clean_identifier(required_string(object, "manifest_id")?)?.to_string(),
        authority: clean_text(required_string(object, "authority")?)?.to_string(),
        artifacts: artifacts
            .iter()
            .map(parse_manifest_artifact)
            .collect::<KernelResult<Vec<_>>>()?,
    })
}

fn parse_manifest_artifact(value: &JsonValue) -> KernelResult<ManifestArtifact> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "path",
            "adapter_id",
            "artifact_id",
            "artifact_kind",
            "binds_open_issues",
            "bundle_field",
            "freeze_artifact_id",
            "expected_sha256_hex",
            "metadata",
        ],
    )?;
    let expected_sha256_hex = optional_string(object, "expected_sha256_hex")
        .map(validate_sha256_hex)
        .transpose()?;
    Ok(ManifestArtifact {
        path: clean_path(required_string(object, "path")?)?.to_string(),
        adapter_id: optional_string(object, "adapter_id").map(str::to_string),
        artifact_id: clean_identifier(required_string(object, "artifact_id")?)?.to_string(),
        artifact_kind: clean_text(required_string(object, "artifact_kind")?)?.to_string(),
        binds_open_issues: required_string_array(object, "binds_open_issues")?,
        bundle_field: optional_string(object, "bundle_field").map(str::to_string),
        freeze_artifact_id: optional_string(object, "freeze_artifact_id").map(str::to_string),
        expected_sha256_hex,
        metadata: optional_string_array(object, "metadata")?,
    })
}

fn normalize_artifact(
    adapter: &AdapterImport,
    artifact: &ImportedArtifact,
    manifests: &[IntegrationManifest],
    findings: &mut Vec<IntegrationFinding>,
) -> NormalizedCertificationArtifact {
    let manifest_artifact = manifests
        .iter()
        .flat_map(|manifest| manifest.artifacts.iter())
        .find(|candidate| manifest_artifact_source_path(candidate) == artifact.source_path);
    let default_id = default_artifact_id(adapter.spec.id, &artifact.source_path);
    let default_kind = default_artifact_kind(adapter.spec.id, &artifact.source_path);
    let default_freeze = default_freeze_artifact_id(adapter.spec.id, &artifact.source_path);
    let default_bundle_field = default_bundle_field(adapter.spec.id, &artifact.source_path);
    let default_issues = adapter
        .spec
        .open_issues
        .iter()
        .map(|issue| (*issue).to_string())
        .collect::<Vec<_>>();
    let mut normalized = NormalizedCertificationArtifact {
        adapter_id: adapter.spec.id,
        source_path: artifact.source_path.clone(),
        normalized_path: artifact.normalized_path.clone(),
        artifact_id: default_id,
        artifact_kind: default_kind,
        sha256_hex: artifact.sha256.clone(),
        size_bytes: artifact.size_bytes,
        binds_open_issues: default_issues,
        bundle_field: default_bundle_field.map(str::to_string),
        freeze_artifact_id: default_freeze.map(str::to_string),
        semantic_status: semantic_status(adapter.spec.id, &artifact.source_path),
    };
    if let Some(manifest) = manifest_artifact {
        if manifest
            .adapter_id
            .as_deref()
            .is_some_and(|id| id != adapter.spec.id)
        {
            push_finding(
                findings,
                "error",
                &artifact.source_path,
                "manifest-adapter-mismatch",
                format!(
                    "Manifest adapter `{}` does not match imported adapter `{}`.",
                    manifest.adapter_id.as_deref().unwrap_or(""),
                    adapter.spec.id
                ),
                "Keep manifest adapter_id aligned with the directory lane that contains the artifact.",
            );
        }
        if manifest
            .expected_sha256_hex
            .as_deref()
            .is_some_and(|expected| expected != artifact.sha256)
        {
            push_finding(
                findings,
                "error",
                &artifact.source_path,
                "manifest-sha-mismatch",
                "Manifest expected_sha256_hex does not match the imported artifact digest.".to_string(),
                "Re-fetch the authority artifact or update the manifest only after reviewer approval.",
            );
        }
        if manifest.metadata.is_empty() {
            push_finding(
                findings,
                "warning",
                &artifact.source_path,
                "manifest-metadata-empty",
                "Manifest artifact has no metadata key list.".to_string(),
                "Record authority, retrieval date, tool version, submitted binary hash, profile hash, and disposition metadata where applicable.",
            );
        }
        normalized.artifact_id = manifest.artifact_id.clone();
        normalized.artifact_kind = manifest.artifact_kind.clone();
        normalized.binds_open_issues = manifest.binds_open_issues.clone();
        normalized.bundle_field = manifest.bundle_field.clone();
        normalized.freeze_artifact_id = manifest.freeze_artifact_id.clone();
        normalized.semantic_status = "manifest_bound_unreviewed";
    }
    normalized
}

fn bundle_bindings_from_normalized(
    normalized: &[NormalizedCertificationArtifact],
    findings: &mut Vec<IntegrationFinding>,
) -> Vec<ArtifactHashBinding> {
    let mut bindings = Vec::new();
    for artifact in normalized {
        if artifact.bundle_field.is_some() || artifact.freeze_artifact_id.is_some() {
            if bindings.iter().any(|existing: &ArtifactHashBinding| {
                existing.artifact_id == artifact.artifact_id
                    && existing.sha256_hex != artifact.sha256_hex
            }) {
                push_finding(
                    findings,
                    "error",
                    &artifact.source_path,
                    "duplicate-artifact-id",
                    format!(
                        "Artifact ID `{}` is bound to more than one digest.",
                        artifact.artifact_id
                    ),
                    "Use stable unique artifact_id values or supersede the prior artifact explicitly.",
                );
            }
            bindings.push(ArtifactHashBinding {
                artifact_id: artifact.artifact_id.clone(),
                artifact_kind: artifact.artifact_kind.clone(),
                sha256_hex: artifact.sha256_hex.clone(),
                binds_open_issues: artifact.binds_open_issues.clone(),
            });
        }
    }
    bindings.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    bindings
}

fn release_freeze_bindings(
    normalized: &[NormalizedCertificationArtifact],
) -> Vec<ReleaseFreezeBinding> {
    FREEZE_TARGETS
        .iter()
        .map(|target| {
            let matched = normalized
                .iter()
                .filter(|artifact| artifact.freeze_artifact_id.as_deref() == Some(target.id))
                .min_by(|left, right| left.source_path.cmp(&right.source_path));
            ReleaseFreezeBinding {
                freeze_artifact_id: target.id,
                title: target.title,
                artifact_kind: target.artifact_kind,
                source_path: matched.map(|artifact| artifact.source_path.clone()),
                sha256_hex: matched.map(|artifact| artifact.sha256_hex.clone()),
                status: if matched.is_some() {
                    "bound_unreviewed"
                } else {
                    "pending"
                },
                required_metadata: target.required_metadata,
            }
        })
        .collect()
}

fn report_status(
    findings: &[IntegrationFinding],
    normalized: &[NormalizedCertificationArtifact],
) -> &'static str {
    if findings.iter().any(|finding| finding.severity == "error") {
        "fail"
    } else if normalized.is_empty() {
        "missing"
    } else if findings.iter().any(|finding| finding.severity == "warning") {
        "warn"
    } else {
        "pass_unreviewed"
    }
}

fn push_rejection_finding(findings: &mut Vec<IntegrationFinding>, rejection: &RejectedArtifact) {
    push_finding(
        findings,
        if rejection.reason == "private-key-material-not-accepted" {
            "error"
        } else {
            "warning"
        },
        &rejection.source_path,
        rejection.reason,
        format!(
            "Artifact in adapter `{}` was rejected during fail-closed classification.",
            rejection.adapter_id
        ),
        "Remove unsupported or unsafe files, or add a reviewed adapter for that authority format.",
    );
}

fn push_finding(
    findings: &mut Vec<IntegrationFinding>,
    severity: &'static str,
    source_path: &str,
    code: &'static str,
    message: String,
    suggestion: &str,
) {
    if findings.len() < MAX_INTEGRATION_FINDINGS {
        findings.push(IntegrationFinding {
            severity,
            source_path: source_path.to_string(),
            code,
            message,
            suggestion: suggestion.to_string(),
        });
    }
}

fn default_artifact_id(adapter_id: &str, source_path: &str) -> String {
    format!(
        "{}.{}",
        adapter_id.to_ascii_lowercase(),
        sanitize_identifier(source_path)
    )
}

fn default_artifact_kind(adapter_id: &str, source_path: &str) -> String {
    match adapter_id {
        "LAB-APPROVAL" => "approval-artifact",
        "SCHEME-PROFILE" => "scheme-profile",
        "CAPK" => "capk-authority",
        "VECTOR" => "test-vectors",
        "DEVICE" => "device-evidence",
        "REPORT" if source_path.ends_with(".lcov") => "coverage-report",
        "REPORT" if source_path.ends_with(".sarif") => "static-analysis-report",
        "REPORT" if source_path.contains("trace") => "trace-pack",
        "REPORT" => "integration-report",
        _ => "external-artifact",
    }
    .to_string()
}

fn default_freeze_artifact_id(adapter_id: &str, source_path: &str) -> Option<&'static str> {
    match adapter_id {
        "LAB-APPROVAL" => Some("approval_package_hash"),
        "SCHEME-PROFILE" => Some("scheme_profile_hash"),
        "CAPK" => Some("capk_bundle_hash"),
        "VECTOR" => Some("test_vector_hash"),
        "DEVICE" => Some("kernel_binary_hash"),
        "REPORT" if source_path.ends_with(".lcov") || source_path.contains("coverage") => {
            Some("coverage_report_hash")
        }
        "REPORT" if source_path.ends_with(".sarif") || source_path.contains("fuzz") => {
            Some("static_fuzz_report_hash")
        }
        "REPORT" if source_path.contains("trace") => Some("trace_pack_hash"),
        "REPORT" => Some("trace_pack_hash"),
        _ => None,
    }
}

fn default_bundle_field(adapter_id: &str, source_path: &str) -> Option<&'static str> {
    match adapter_id {
        "SCHEME-PROFILE" if source_path.ends_with(".json") => {
            Some("payload.scheme_profile_set_json")
        }
        "VECTOR" if source_path.ends_with(".json") => Some("payload.vector_bundle_json"),
        _ => None,
    }
}

fn semantic_status(adapter_id: &str, source_path: &str) -> &'static str {
    match adapter_id {
        "SCHEME-PROFILE" | "CAPK" | "VECTOR" | "LAB-APPROVAL" | "DEVICE" | "REPORT" => {
            if source_path.ends_with(CERTIFICATION_INTEGRATION_MANIFEST_FILE) {
                "manifest_self_description"
            } else {
                "hash_bound_unreviewed"
            }
        }
        _ => "unknown_adapter",
    }
}

fn manifest_artifact_source_path(artifact: &ManifestArtifact) -> String {
    if artifact.path.contains('/') {
        artifact.path.clone()
    } else if let Some(adapter_id) = &artifact.adapter_id {
        if let Some(spec) = ARTIFACT_ADAPTER_SPECS
            .iter()
            .find(|spec| spec.id == adapter_id.as_str())
        {
            format!("{}/{}", spec.input_dir, artifact.path)
        } else {
            artifact.path.clone()
        }
    } else {
        artifact.path.clone()
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

fn sanitize_identifier(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' => out.push(byte as char),
            _ => out.push('_'),
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_string()
}

fn required_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<&'a str> {
    object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_string()
}

fn optional_string<'a>(object: &'a BTreeMap<String, JsonValue>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(JsonValue::as_string_opt)
}

fn required_string_array(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<Vec<String>> {
    let array = object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    if array.is_empty() || array.len() > 128 {
        return Err(KernelError::InvalidProfile);
    }
    array
        .iter()
        .map(|item| clean_text(item.as_string()?).map(str::to_string))
        .collect()
}

fn optional_string_array(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<Vec<String>> {
    match object.get(key) {
        Some(value) => value
            .as_array()?
            .iter()
            .map(|item| clean_text(item.as_string()?).map(str::to_string))
            .collect(),
        None => Ok(Vec::new()),
    }
}

fn reject_unknown_fields(
    object: &BTreeMap<String, JsonValue>,
    allowed: &[&str],
) -> KernelResult<()> {
    if object
        .keys()
        .all(|key| allowed.iter().any(|field| *field == key))
    {
        Ok(())
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn clean_identifier(value: &str) -> KernelResult<&str> {
    clean_text(value)?;
    if value
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        Ok(value)
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn clean_path(value: &str) -> KernelResult<&str> {
    clean_text(value)?;
    if value.starts_with('/') || value.contains("..") || value.contains('\\') {
        Err(KernelError::InvalidProfile)
    } else {
        Ok(value)
    }
}

fn clean_text(value: &str) -> KernelResult<&str> {
    if value.is_empty()
        || value.len() > 4096
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        Err(KernelError::InvalidProfile)
    } else {
        Ok(value)
    }
}

fn validate_sha256_hex(value: &str) -> KernelResult<String> {
    clean_identifier(value)?;
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn push_normalized_artifact_json(out: &mut String, artifact: &NormalizedCertificationArtifact) {
    out.push('{');
    push_json_str(out, "adapter_id", artifact.adapter_id);
    out.push(',');
    push_json_str(out, "source_path", &artifact.source_path);
    out.push(',');
    push_json_str(out, "normalized_path", &artifact.normalized_path);
    out.push(',');
    push_json_str(out, "artifact_id", &artifact.artifact_id);
    out.push(',');
    push_json_str(out, "artifact_kind", &artifact.artifact_kind);
    out.push(',');
    push_json_str(out, "sha256_hex", &artifact.sha256_hex);
    out.push(',');
    push_json_number(out, "size_bytes", artifact.size_bytes);
    out.push_str(",\"binds_open_issues\":[");
    push_json_string_array(out, &artifact.binds_open_issues);
    out.push(']');
    if let Some(value) = &artifact.bundle_field {
        out.push(',');
        push_json_str(out, "bundle_field", value);
    }
    if let Some(value) = &artifact.freeze_artifact_id {
        out.push(',');
        push_json_str(out, "freeze_artifact_id", value);
    }
    out.push(',');
    push_json_str(out, "semantic_status", artifact.semantic_status);
    out.push('}');
}

fn push_bundle_binding_json(out: &mut String, binding: &ArtifactHashBinding) {
    out.push('{');
    push_json_str(out, "artifact_id", &binding.artifact_id);
    out.push(',');
    push_json_str(out, "artifact_kind", &binding.artifact_kind);
    out.push(',');
    push_json_str(out, "sha256_hex", &binding.sha256_hex);
    out.push_str(",\"binds_open_issues\":[");
    push_json_string_array(out, &binding.binds_open_issues);
    out.push_str("]}");
}

fn push_freeze_binding_json(out: &mut String, binding: &ReleaseFreezeBinding) {
    out.push('{');
    push_json_str(out, "freeze_artifact_id", binding.freeze_artifact_id);
    out.push(',');
    push_json_str(out, "title", binding.title);
    out.push(',');
    push_json_str(out, "artifact_kind", binding.artifact_kind);
    out.push(',');
    push_json_str(out, "status", binding.status);
    if let Some(value) = &binding.source_path {
        out.push(',');
        push_json_str(out, "source_path", value);
    }
    if let Some(value) = &binding.sha256_hex {
        out.push(',');
        push_json_str(out, "sha256_hex", value);
    }
    out.push_str(",\"required_metadata\":[");
    push_json_str_slice(out, binding.required_metadata);
    out.push_str("]}");
}

fn push_finding_json(out: &mut String, finding: &IntegrationFinding) {
    out.push('{');
    push_json_str(out, "severity", finding.severity);
    out.push(',');
    push_json_str(out, "source_path", &finding.source_path);
    out.push(',');
    push_json_str(out, "code", finding.code);
    out.push(',');
    push_json_str(out, "message", &finding.message);
    out.push(',');
    push_json_str(out, "suggestion", &finding.suggestion);
    out.push('}');
}

fn push_json_string_array(out: &mut String, values: &[String]) {
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(out, value);
    }
}

fn push_json_str_slice(out: &mut String, values: &[&str]) {
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
    use crate::provenance::{sha256, to_hex};
    use std::env;
    use std::path::PathBuf;
    use std::process;

    #[test]
    fn integration_compiler_binds_real_artifacts_through_manifest() {
        let root = temp_root("hyperion-integration-import-bound");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("scheme")).unwrap();
        fs::create_dir_all(root.join("vectors")).unwrap();
        fs::create_dir_all(root.join("reports")).unwrap();
        fs::write(
            root.join("scheme/profile.json"),
            b"{\"schema_version\":\"1.0\"}",
        )
        .unwrap();
        fs::write(
            root.join("vectors/oda.json"),
            b"{\"vector_class\":\"CERTIFICATION\",\"cases\":[\"sda dda cda\"]}",
        )
        .unwrap();
        fs::write(root.join("reports/coverage.lcov"), b"TN:\nend_of_record\n").unwrap();
        let profile_sha = to_hex(&sha256(b"{\"schema_version\":\"1.0\"}"));
        let manifest = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"authority.2026\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/profile.json\",\"adapter_id\":\"SCHEME-PROFILE\",\"artifact_id\":\"scheme_profile_set_json\",\"artifact_kind\":\"scheme-profile\",\"binds_open_issues\":[\"CERT-OPEN-002\",\"CERT-OPEN-005\"],\"bundle_field\":\"payload.scheme_profile_set_json\",\"freeze_artifact_id\":\"scheme_profile_hash\",\"expected_sha256_hex\":\"{}\",\"metadata\":[\"authority\",\"retrieval_date\"]}},{{\"path\":\"vectors/oda.json\",\"adapter_id\":\"VECTOR\",\"artifact_id\":\"vector_bundle_json\",\"artifact_kind\":\"test-vectors\",\"binds_open_issues\":[\"CERT-OPEN-004\"],\"bundle_field\":\"payload.vector_bundle_json\",\"freeze_artifact_id\":\"test_vector_hash\",\"metadata\":[\"vector_class\"]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
            profile_sha
        );
        fs::write(root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE), manifest).unwrap();

        let report = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(report.status, "pass_unreviewed");
        assert!(report.findings.is_empty());
        assert!(report
            .bundle_bindings
            .iter()
            .any(|binding| binding.artifact_id == "scheme_profile_set_json"));
        assert!(report
            .freeze_bindings
            .iter()
            .any(
                |binding| binding.freeze_artifact_id == "coverage_report_hash"
                    && binding.status == "bound_unreviewed"
            ));
        let json = certification_integration_import_report_json(2, &report);
        let markdown = certification_integration_import_report_markdown(2, &report);
        let freeze = certification_release_freeze_json(2, &report);
        let freeze_md = certification_release_freeze_markdown(2, &report);
        assert!(json.contains("certification-integration-import-report"));
        assert!(json.contains("bundle_artifact_hashes"));
        assert!(markdown.contains("Release Freeze Bindings"));
        assert!(freeze.contains("certification-release-freeze"));
        assert!(freeze_md.contains("trace_pack_hash"));
        assert_eq!(certification_bundle_artifact_bindings(&report).len(), 3);

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn integration_compiler_fails_closed_on_manifest_and_rejection_edges() {
        let root = temp_root("hyperion-integration-import-reject");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("scheme")).unwrap();
        fs::create_dir_all(root.join("reports")).unwrap();
        fs::write(root.join("scheme/private.key"), b"secret").unwrap();
        fs::write(root.join("reports/analysis.sarif"), b"{}").unwrap();
        fs::write(
            root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            format!(
                "{{\"schema_version\":\"{}\",\"manifest_id\":\"bad\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/missing.json\",\"artifact_id\":\"dup\",\"artifact_kind\":\"scheme-profile\",\"binds_open_issues\":[\"CERT-OPEN-002\"],\"metadata\":[]}},{{\"path\":\"reports/analysis.sarif\",\"adapter_id\":\"REPORT\",\"artifact_id\":\"dup\",\"artifact_kind\":\"static-analysis-report\",\"binds_open_issues\":[\"CERT-OPEN-010\"],\"freeze_artifact_id\":\"static_fuzz_report_hash\",\"expected_sha256_hex\":\"{}\",\"metadata\":[]}}]}}",
                CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
                "00".repeat(32)
            ),
        )
        .unwrap();

        let report = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(report.status, "fail");
        for code in [
            "private-key-material-not-accepted",
            "manifest-artifact-missing",
            "manifest-sha-mismatch",
            "manifest-metadata-empty",
        ] {
            assert!(report.findings.iter().any(|finding| finding.code == code));
        }
        assert!(report
            .freeze_bindings
            .iter()
            .any(
                |binding| binding.freeze_artifact_id == "static_fuzz_report_hash"
                    && binding.status == "bound_unreviewed"
            ));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn integration_manifest_parser_rejects_unsafe_shapes_and_json_escapes() {
        assert!(parse_integration_manifest(b"{}", "root").is_err());
        let too_many = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"many\",\"authority\":\"lab\",\"artifacts\":[{}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
            (0..129)
                .map(|idx| format!("{{\"path\":\"scheme/a{idx}.json\",\"artifact_id\":\"a{idx}\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(parse_integration_manifest(too_many.as_bytes(), "root").is_err());
        let bad_path = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"bad\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"../secret\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(bad_path.as_bytes(), "root").is_err());
        let mut out = String::new();
        push_json_string(&mut out, "quote\" slash\\ line\n tab\t high\u{00ff}");
        assert_eq!(
            out,
            "\"quote\\\" slash\\\\ line\\n tab\\t high\\u00c3\\u00bf\""
        );
        assert_eq!(sanitize_identifier("a/b c"), "a_b_c");
        assert_eq!(
            manifest_artifact_source_path(&ManifestArtifact {
                path: "profile.json".to_string(),
                adapter_id: Some("SCHEME-PROFILE".to_string()),
                artifact_id: "profile".to_string(),
                artifact_kind: "scheme-profile".to_string(),
                binds_open_issues: vec!["CERT-OPEN-002".to_string()],
                bundle_field: None,
                freeze_artifact_id: None,
                expected_sha256_hex: None,
                metadata: Vec::new(),
            }),
            "scheme/profile.json"
        );
    }

    #[test]
    fn integration_compiler_reports_manifest_source_and_size_failures() {
        let root = temp_root("hyperion-integration-import-manifest-edges");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("scheme")).unwrap();
        fs::write(root.join("scheme/profile.json"), b"{}").unwrap();
        fs::write(
            root.join("scheme").join(CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            format!(
                "{{\"schema_version\":\"{}\",\"manifest_id\":\"scheme.manifest\",\"authority\":\"scheme\",\"artifacts\":[{{\"path\":\"profile.json\",\"adapter_id\":\"SCHEME-PROFILE\",\"artifact_id\":\"scheme.profile\",\"artifact_kind\":\"scheme-profile\",\"binds_open_issues\":[\"CERT-OPEN-002\"],\"bundle_field\":\"payload.scheme_profile_set_json\",\"freeze_artifact_id\":\"scheme_profile_hash\",\"metadata\":[\"authority\"]}}]}}",
                CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
            ),
        )
        .unwrap();
        let report = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(report.status, "pass_unreviewed");
        assert!(report
            .normalized_artifacts
            .iter()
            .any(|artifact| artifact.artifact_id == "scheme.profile"));

        fs::remove_dir_all(&root).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            vec![b' '; MAX_INTEGRATION_MANIFEST_BYTES + 1],
        )
        .unwrap();
        let too_large = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(too_large.status, "fail");
        assert!(too_large
            .findings
            .iter()
            .any(|finding| finding.code == "manifest-too-large"));

        fs::write(
            root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            b"{not-json",
        )
        .unwrap();
        let malformed = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(malformed.status, "fail");
        assert!(malformed
            .findings
            .iter()
            .any(|finding| finding.code == "manifest-parse-failed"));
        let json = certification_integration_import_report_json(2, &malformed);
        assert!(json.contains("manifest-parse-failed"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn integration_compiler_flags_manifest_mismatch_duplicates_and_warning_status() {
        let root = temp_root("hyperion-integration-import-warning-edges");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("reports")).unwrap();
        fs::write(root.join("reports/trace-one.json"), b"one").unwrap();
        fs::write(root.join("reports/trace-two.json"), b"two").unwrap();
        let one_sha = to_hex(&sha256(b"one"));
        let two_sha = to_hex(&sha256(b"two"));
        fs::write(
            root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            format!(
                "{{\"schema_version\":\"{}\",\"manifest_id\":\"warn\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"reports/trace-one.json\",\"adapter_id\":\"SCHEME-PROFILE\",\"artifact_id\":\"duplicate.trace\",\"artifact_kind\":\"trace-pack\",\"binds_open_issues\":[\"CERT-OPEN-009\"],\"freeze_artifact_id\":\"trace_pack_hash\",\"expected_sha256_hex\":\"{}\",\"metadata\":[]}},{{\"path\":\"reports/trace-two.json\",\"adapter_id\":\"REPORT\",\"artifact_id\":\"duplicate.trace\",\"artifact_kind\":\"trace-pack\",\"binds_open_issues\":[\"CERT-OPEN-009\"],\"freeze_artifact_id\":\"trace_pack_hash\",\"expected_sha256_hex\":\"{}\",\"metadata\":[\"tool_version\"]}}]}}",
                CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
                one_sha,
                two_sha
            ),
        )
        .unwrap();
        let fail_report = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(fail_report.status, "fail");
        for code in [
            "manifest-adapter-mismatch",
            "manifest-metadata-empty",
            "duplicate-artifact-id",
        ] {
            assert!(fail_report
                .findings
                .iter()
                .any(|finding| finding.code == code));
        }
        let fail_json = certification_integration_import_report_json(2, &fail_report);
        assert!(fail_json.contains("manifest-adapter-mismatch"));
        assert!(fail_json.contains(",{"));

        fs::write(
            root.join(CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            format!(
                "{{\"schema_version\":\"{}\",\"manifest_id\":\"warn\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"reports/trace-one.json\",\"adapter_id\":\"REPORT\",\"artifact_id\":\"trace.one\",\"artifact_kind\":\"trace-pack\",\"binds_open_issues\":[\"CERT-OPEN-009\"],\"freeze_artifact_id\":\"trace_pack_hash\",\"expected_sha256_hex\":\"{}\",\"metadata\":[]}}]}}",
                CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
                one_sha
            ),
        )
        .unwrap();
        let warn_report = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(warn_report.status, "warn");
        assert!(warn_report
            .findings
            .iter()
            .any(|finding| finding.code == "manifest-metadata-empty"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn integration_manifest_validation_edges_are_explicit() {
        let bad_schema = b"{\"schema_version\":\"wrong\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"artifacts\":[{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}]}";
        assert!(parse_integration_manifest(bad_schema, "root").is_err());
        let extra_root = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"extra\":true,\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(extra_root.as_bytes(), "root").is_err());
        let extra_artifact = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"],\"extra\":true}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(extra_artifact.as_bytes(), "root").is_err());
        let empty_issues = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(empty_issues.as_bytes(), "root").is_err());
        let bad_identifier = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"bad id\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(bad_identifier.as_bytes(), "root").is_err());
        let empty_authority = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"\",\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(empty_authority.as_bytes(), "root").is_err());
        let bad_sha = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"],\"expected_sha256_hex\":\"abc\"}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        assert!(parse_integration_manifest(bad_sha.as_bytes(), "root").is_err());
        let valid_without_metadata = format!(
            "{{\"schema_version\":\"{}\",\"manifest_id\":\"m\",\"authority\":\"lab\",\"artifacts\":[{{\"path\":\"scheme/a.json\",\"artifact_id\":\"a\",\"artifact_kind\":\"kind\",\"binds_open_issues\":[\"CERT-OPEN-002\"]}}]}}",
            CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
        );
        let parsed = parse_integration_manifest(valid_without_metadata.as_bytes(), "root").unwrap();
        assert!(parsed.artifacts[0].metadata.is_empty());
    }

    #[test]
    fn default_mapping_helpers_cover_all_general_lanes() {
        assert_eq!(
            default_artifact_kind("LAB-APPROVAL", "lab/approval.pdf"),
            "approval-artifact"
        );
        assert_eq!(
            default_artifact_kind("SCHEME-PROFILE", "scheme/profile.xml"),
            "scheme-profile"
        );
        assert_eq!(
            default_artifact_kind("CAPK", "capk/capks.pem"),
            "capk-authority"
        );
        assert_eq!(
            default_artifact_kind("VECTOR", "vectors/cda.json"),
            "test-vectors"
        );
        assert_eq!(
            default_artifact_kind("DEVICE", "device/l1.pdf"),
            "device-evidence"
        );
        assert_eq!(
            default_artifact_kind("REPORT", "reports/coverage.lcov"),
            "coverage-report"
        );
        assert_eq!(
            default_artifact_kind("REPORT", "reports/result.sarif"),
            "static-analysis-report"
        );
        assert_eq!(
            default_artifact_kind("REPORT", "reports/trace-pack.json"),
            "trace-pack"
        );
        assert_eq!(
            default_artifact_kind("REPORT", "reports/l3.json"),
            "integration-report"
        );
        assert_eq!(
            default_artifact_kind("OTHER", "other.bin"),
            "external-artifact"
        );

        assert_eq!(
            default_freeze_artifact_id("LAB-APPROVAL", "lab/approval.pdf"),
            Some("approval_package_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("SCHEME-PROFILE", "scheme/profile.json"),
            Some("scheme_profile_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("CAPK", "capk/capks.json"),
            Some("capk_bundle_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("VECTOR", "vectors/cda.json"),
            Some("test_vector_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("DEVICE", "device/firmware.json"),
            Some("kernel_binary_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("REPORT", "reports/coverage.xml"),
            Some("coverage_report_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("REPORT", "reports/fuzz.txt"),
            Some("static_fuzz_report_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("REPORT", "reports/trace.txt"),
            Some("trace_pack_hash")
        );
        assert_eq!(
            default_freeze_artifact_id("REPORT", "reports/reconciliation.pdf"),
            Some("trace_pack_hash")
        );
        assert_eq!(default_freeze_artifact_id("OTHER", "other.bin"), None);

        assert_eq!(
            semantic_status("REPORT", CERTIFICATION_INTEGRATION_MANIFEST_FILE),
            "manifest_self_description"
        );
        assert_eq!(semantic_status("OTHER", "other.bin"), "unknown_adapter");
        assert_eq!(
            manifest_artifact_source_path(&ManifestArtifact {
                path: "artifact.json".to_string(),
                adapter_id: Some("UNKNOWN".to_string()),
                artifact_id: "artifact".to_string(),
                artifact_kind: "kind".to_string(),
                binds_open_issues: vec!["CERT-OPEN-002".to_string()],
                bundle_field: None,
                freeze_artifact_id: None,
                expected_sha256_hex: None,
                metadata: Vec::new(),
            }),
            "artifact.json"
        );
        assert_eq!(sanitize_identifier("a///b"), "a_b");
        assert_eq!(
            manifest_artifact_source_path(&ManifestArtifact {
                path: "artifact.json".to_string(),
                adapter_id: None,
                artifact_id: "artifact".to_string(),
                artifact_kind: "kind".to_string(),
                binds_open_issues: vec!["CERT-OPEN-002".to_string()],
                bundle_field: None,
                freeze_artifact_id: None,
                expected_sha256_hex: None,
                metadata: Vec::new(),
            }),
            "artifact.json"
        );
        let unbound = NormalizedCertificationArtifact {
            adapter_id: "REPORT",
            source_path: "reports/advisory.txt".to_string(),
            normalized_path: "CERT-OPEN-009/advisory.txt".to_string(),
            artifact_id: "advisory".to_string(),
            artifact_kind: "integration-report".to_string(),
            sha256_hex: "00".repeat(32),
            size_bytes: 1,
            binds_open_issues: vec!["CERT-OPEN-009".to_string()],
            bundle_field: None,
            freeze_artifact_id: None,
            semantic_status: "hash_bound_unreviewed",
        };
        let mut findings = Vec::new();
        assert!(bundle_bindings_from_normalized(&[unbound], &mut findings).is_empty());
        push_rejection_finding(
            &mut findings,
            &RejectedArtifact {
                adapter_id: "REPORT",
                source_path: "reports/tool.bin".to_string(),
                reason: "unsupported-extension",
            },
        );
        assert!(findings.iter().any(
            |finding| finding.severity == "warning" && finding.code == "unsupported-extension"
        ));
        let mut escaped = String::new();
        push_json_string(&mut escaped, "carriage\rreturn");
        assert_eq!(escaped, "\"carriage\\rreturn\"");
    }

    #[test]
    fn missing_root_report_is_missing_with_pending_freeze_slots() {
        let root = temp_root("hyperion-integration-import-missing");
        let _ = fs::remove_dir_all(&root);
        let report = compile_certification_integration_artifacts(&root).unwrap();
        assert_eq!(report.status, "missing");
        assert!(report.normalized_artifacts.is_empty());
        assert!(report
            .freeze_bindings
            .iter()
            .all(|binding| binding.status == "pending"));
    }

    fn temp_root(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!("{prefix}-{}", process::id()))
    }
}
