//! Data-driven certification bundle loading, validation, and provisioning.
//!
//! The kernel keeps EMV protocol algorithms in Rust, while certification
//! choices live in signed or hash-pinned data bundles. This module validates a
//! complete certification bundle, binds it to trust-anchor data, loads the
//! embedded scheme profile set, and emits static provisioning surfaces.

use crate::config::{
    decode_hex, load_profile_set, BuildMode, ConfigLoadPolicy, JsonParser, JsonValue, ProfileSet,
    SignatureStatus,
};
use crate::error::{KernelError, KernelResult};
use crate::provenance::{sha256, to_hex};
use crate::restrictions::EmvDate;
use core::fmt::Write;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::BTreeMap;

pub const CERTIFICATION_BUNDLE_SCHEMA_VERSION: &str = "hyperion-certification-bundle-1.0";
pub const CERTIFICATION_BUNDLE_SIGNATURE_ALGORITHM: &str = "hyperion-ed25519-sha256-v1";
pub const CERTIFICATION_BUNDLE_TEST_ALGORITHM: &str = "hyperion-sha256-test-attestation-v1";
pub const CERTIFICATION_BUNDLE_SIGNATURE_DOMAIN: &[u8] =
    b"Hyperion certification bundle Ed25519 signature v1";
const DEFAULT_FIXTURE_SIGNING_PRIVATE_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
pub const MAX_CERTIFICATION_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EMBEDDED_PROFILE_BYTES: usize = 1024 * 1024;
pub const MAX_BUNDLE_STRING_BYTES: usize = 4096;
pub const MAX_BUNDLE_COLLECTION_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleClass {
    Testing,
    Certification,
}

impl BundleClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Testing => "TESTING",
            Self::Certification => "CERTIFICATION",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleLoadPolicy {
    pub mode: BuildMode,
    pub installed_rollback_counter: u64,
    pub evaluation_date: EmvDate,
    pub trust_anchors: Vec<BundleTrustAnchor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleTrustAnchor {
    pub signer_id: String,
    pub signing_key_fingerprint: String,
    pub verification_public_key_hex: String,
    pub allowed_payload_sha256: String,
    pub not_after: Option<EmvDate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub bundle_version: u64,
    pub rollback_counter: u64,
    pub bundle_class: BundleClass,
    pub created: EmvDate,
    pub payload: CertificationBundlePayload,
    pub signature: BundleSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationBundlePayload {
    pub submission_scope: SubmissionScope,
    pub standards_target: StandardsTarget,
    pub terminal_profile: TerminalProfile,
    pub runtime_policy: RuntimePolicy,
    pub kernel_registry: Vec<KernelProfileRegistration>,
    pub cvm_extensions: Vec<CvmExtensionRule>,
    pub test_plan: Vec<CertificationTestCase>,
    pub artifact_hashes: Vec<ArtifactHashBinding>,
    pub scheme_profile_set_json: String,
    pub vector_bundle_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionScope {
    pub product_name: String,
    pub product_version: String,
    pub certification_target: String,
    pub interfaces: Vec<String>,
    pub authorities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardsTarget {
    pub emv_contact_version: String,
    pub emv_contactless_kernel: String,
    pub bulletins_included: Vec<String>,
    pub bulletins_excluded: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProfile {
    pub terminal_type: String,
    pub device_model: String,
    pub firmware_version: String,
    pub l1_approval_reference: String,
    pub pci_pts_reference: String,
    pub supported_interfaces: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallbackTimeoutProfile {
    pub apdu_transport_timeout_ms: i32,
    pub host_authorization_timeout_ms: i32,
    pub pin_entry_timeout_ms: i32,
    pub contactless_ui_timeout_ms: i32,
}

impl CallbackTimeoutProfile {
    pub const fn defaults() -> Self {
        Self {
            apdu_transport_timeout_ms: 500,
            host_authorization_timeout_ms: 30_000,
            pin_entry_timeout_ms: 30_000,
            contactless_ui_timeout_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub callback_timeouts: CallbackTimeoutProfile,
    pub offline_counter_persistence: String,
    pub trace_masking_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProfileRegistration {
    pub kernel_profile_id: String,
    pub interface: String,
    pub algorithm: String,
    pub c8_package: String,
    pub scheme_scope: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CvmExtensionRule {
    pub rule_id: String,
    pub scheme_scope: Vec<String>,
    pub cvm_code_hex: String,
    pub meaning: String,
    pub tvr_on_failure_hex: String,
    pub continue_on_failure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationTestCase {
    pub case_id: String,
    pub vector_class: String,
    pub expected_outcome: String,
    pub trace_requirement: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactHashBinding {
    pub artifact_id: String,
    pub artifact_kind: String,
    pub sha256_hex: String,
    pub binds_open_issues: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleSignature {
    pub algorithm: String,
    pub signer_id: String,
    pub signing_key_fingerprint: String,
    pub payload_sha256: String,
    pub signature_hex: String,
    pub signature_artifact_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedCertificationBundle {
    pub bundle: CertificationBundle,
    pub profile_set: ProfileSet,
    pub bundle_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub scheme_profile_sha256: [u8; 32],
    pub vector_bundle_sha256: [u8; 32],
    pub verification_status: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleLintSeverity {
    Info,
    Warning,
    Error,
}

impl BundleLintSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleLintFinding {
    pub severity: BundleLintSeverity,
    pub field_path: String,
    pub title: String,
    pub impact: String,
    pub suggestion: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmvCapabilityCoverage {
    pub id: &'static str,
    pub area: &'static str,
    pub role: &'static str,
    pub bundle_source: &'static str,
    pub status: &'static str,
    pub suggestion: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleCompileReport {
    pub status: &'static str,
    pub mode: BuildMode,
    pub findings: Vec<BundleLintFinding>,
    pub coverage: Vec<EmvCapabilityCoverage>,
    pub bundle_sha256: Option<String>,
    pub payload_sha256: Option<String>,
    pub scheme_profile_sha256: Option<String>,
    pub vector_bundle_sha256: Option<String>,
    pub verification_status: Option<&'static str>,
}

pub fn certification_bundle_compile_report(
    bundle_json: &[u8],
    trust_anchors_json: &[u8],
    policy: &BundleLoadPolicy,
) -> BundleCompileReport {
    let mut report = BundleCompileReport {
        status: "pass",
        mode: policy.mode,
        findings: Vec::new(),
        coverage: Vec::new(),
        bundle_sha256: None,
        payload_sha256: None,
        scheme_profile_sha256: None,
        vector_bundle_sha256: None,
        verification_status: None,
    };

    if bundle_json.is_empty() {
        push_finding(
            &mut report,
            BundleLintSeverity::Error,
            "bundle_json",
            "Bundle JSON is empty",
            "The kernel cannot parse, authenticate, or load an empty bundle.",
            "Export a populated certification bundle before compiling.",
        );
    }
    if trust_anchors_json.is_empty() {
        push_finding(
            &mut report,
            BundleLintSeverity::Error,
            "trust_anchors_json",
            "Trust-anchor JSON is empty",
            "Certification and production modes require trusted signer metadata before bundle authentication.",
            "Provision at least one signer trust anchor with an allowed payload hash.",
        );
    }

    let parsed_bundle = match parse_certification_bundle(bundle_json) {
        Ok(bundle) => {
            lint_parsed_bundle(&mut report, &bundle, policy);
            Some(bundle)
        }
        Err(err) => {
            push_finding(
                &mut report,
                BundleLintSeverity::Error,
                "bundle_json",
                "Bundle schema validation failed",
                "The compiled runtime will reject this bundle before any EMV transaction can use it.",
                &format!("Fix the JSON shape, required fields, identifiers, hashes, and bounds reported by the parser: {err}"),
            );
            None
        }
    };

    let parsed_anchors = match parse_trust_anchors(trust_anchors_json) {
        Ok(anchors) => {
            lint_trust_anchors(&mut report, &anchors, policy);
            Some(anchors)
        }
        Err(err) => {
            push_finding(
                &mut report,
                BundleLintSeverity::Error,
                "trust_anchors_json",
                "Trust-anchor validation failed",
                "The compiled runtime cannot authenticate a certification or production bundle without valid trust anchors.",
                &format!("Fix the trust-anchor schema, signer IDs, fingerprints, secret length, dates, and allowed payload hashes: {err}"),
            );
            None
        }
    };

    if let (Some(_bundle), Some(anchors)) = (parsed_bundle.as_ref(), parsed_anchors) {
        let mut load_policy = policy.clone();
        load_policy.trust_anchors = anchors;
        match load_certification_bundle(bundle_json, &load_policy) {
            Ok(loaded) => {
                report.bundle_sha256 = Some(to_hex(&loaded.bundle_sha256));
                report.payload_sha256 = Some(to_hex(&loaded.payload_sha256));
                report.scheme_profile_sha256 = Some(to_hex(&loaded.scheme_profile_sha256));
                report.vector_bundle_sha256 = Some(to_hex(&loaded.vector_bundle_sha256));
                report.verification_status = Some(loaded.verification_status);
                push_finding(
                    &mut report,
                    BundleLintSeverity::Info,
                    "bundle",
                    "Bundle compiled and authenticated",
                    "The same kernel binary can load this data bundle under the selected policy.",
                    "Keep the bundle, trust anchors, fingerprints, reports, and submitted binary hash together in the certification pack.",
                );
                report.coverage = emv_capability_coverage(&loaded);
            }
            Err(err) => {
                push_finding(
                    &mut report,
                    BundleLintSeverity::Error,
                    "bundle",
                    "Bundle compile/authentication failed",
                    "The runtime loader will reject this bundle under the selected mode, rollback, date, or trust policy.",
                    &format!("Reconcile payload hash, signer trust anchor, rollback counter, bundle class, profile signatures, and evaluation date: {err}"),
                );
                if let Some(bundle) = parsed_bundle.as_ref() {
                    report.coverage = payload_capability_coverage(bundle);
                }
            }
        }
    } else if let Some(bundle) = parsed_bundle.as_ref() {
        report.coverage = payload_capability_coverage(bundle);
    }

    finalize_compile_status(&mut report);
    report
}

pub fn certification_bundle_compile_report_json(report: &BundleCompileReport) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(
        &mut out,
        "type",
        "hyperion-certification-bundle-compile-report",
    );
    out.push(',');
    push_json_str(&mut out, "status", report.status);
    out.push(',');
    push_json_str(&mut out, "mode", build_mode_as_str(report.mode));
    if let Some(value) = &report.bundle_sha256 {
        out.push(',');
        push_json_str(&mut out, "bundle_sha256", value);
    }
    if let Some(value) = &report.payload_sha256 {
        out.push(',');
        push_json_str(&mut out, "payload_sha256", value);
    }
    if let Some(value) = &report.scheme_profile_sha256 {
        out.push(',');
        push_json_str(&mut out, "scheme_profile_sha256", value);
    }
    if let Some(value) = &report.vector_bundle_sha256 {
        out.push(',');
        push_json_str(&mut out, "vector_bundle_sha256", value);
    }
    if let Some(value) = report.verification_status {
        out.push(',');
        push_json_str(&mut out, "verification_status", value);
    }
    out.push_str(",\"findings\":[");
    for (idx, finding) in report.findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_lint_finding_json(&mut out, finding);
    }
    out.push_str("],\"capability_coverage\":[");
    for (idx, coverage) in report.coverage.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_capability_coverage_json(&mut out, coverage);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_bundle_compile_report_markdown(report: &BundleCompileReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Bundle Compile Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Status: `{}`", report.status);
    let _ = writeln!(out, "- Mode: `{}`", build_mode_as_str(report.mode));
    if let Some(value) = &report.bundle_sha256 {
        let _ = writeln!(out, "- Bundle SHA-256: `{value}`");
    }
    if let Some(value) = &report.payload_sha256 {
        let _ = writeln!(out, "- Payload SHA-256: `{value}`");
    }
    if let Some(value) = report.verification_status {
        let _ = writeln!(out, "- Verification status: `{value}`");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    if report.findings.is_empty() {
        let _ = writeln!(out, "No findings.");
    } else {
        for finding in &report.findings {
            let _ = writeln!(
                out,
                "- `{}` `{}`: {} Suggestion: {}",
                finding.severity.as_str(),
                finding.field_path,
                finding.title,
                finding.suggestion
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## EMV Capability Coverage");
    let _ = writeln!(out);
    let _ = writeln!(out, "| ID | Area | Status | Bundle Source | Role |");
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for item in &report.coverage {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | {} |",
            item.id, item.area, item.status, item.bundle_source, item.role
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Boundary: this report proves repository loader compatibility and data coverage. It does not replace external EMVCo, scheme, laboratory, device, L1, PCI/PED, or acquirer evidence.");
    out
}

pub fn load_certification_bundle(
    bundle_json: &[u8],
    policy: &BundleLoadPolicy,
) -> KernelResult<LoadedCertificationBundle> {
    if bundle_json.is_empty() || bundle_json.len() > MAX_CERTIFICATION_BUNDLE_BYTES {
        return Err(KernelError::LengthOverflow);
    }
    let bundle = parse_certification_bundle(bundle_json)?;
    validate_bundle_for_policy(&bundle, policy)?;
    let payload_json = payload_canonical_json(&bundle.payload);
    let payload_sha256 = sha256(payload_json.as_bytes());
    if bundle.signature.payload_sha256 != to_hex(&payload_sha256) {
        return Err(KernelError::InvalidProfile);
    }
    let verification_status = verify_bundle_signature(&bundle, &payload_sha256, policy)?;
    let signature_status = if verification_status == "testing-self-attested" {
        SignatureStatus::NotPresent
    } else {
        SignatureStatus::Verified
    };
    let profile_mode = if bundle.bundle_class == BundleClass::Testing {
        BuildMode::Test
    } else {
        policy.mode
    };
    let profile_set = load_profile_set(
        bundle.payload.scheme_profile_set_json.as_bytes(),
        &ConfigLoadPolicy {
            mode: profile_mode,
            signature_status,
            installed_version: policy.installed_rollback_counter,
            candidate_version: bundle.rollback_counter,
            evaluation_date: policy.evaluation_date,
        },
    )?;
    Ok(LoadedCertificationBundle {
        scheme_profile_sha256: sha256(bundle.payload.scheme_profile_set_json.as_bytes()),
        vector_bundle_sha256: sha256(bundle.payload.vector_bundle_json.as_bytes()),
        bundle_sha256: sha256(bundle_json),
        payload_sha256,
        bundle,
        profile_set,
        verification_status,
    })
}

pub fn parse_certification_bundle(input: &[u8]) -> KernelResult<CertificationBundle> {
    let root = JsonParser::new(input).parse()?;
    let object = root.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "schema_version",
            "bundle_id",
            "bundle_version",
            "rollback_counter",
            "bundle_class",
            "created",
            "payload",
            "signature",
        ],
    )?;
    let schema_version = required_string(object, "schema_version")?.to_string();
    if schema_version != CERTIFICATION_BUNDLE_SCHEMA_VERSION {
        return Err(KernelError::InvalidProfile);
    }
    let bundle_id = required_clean_string(object, "bundle_id")?.to_string();
    validate_identifier(&bundle_id)?;
    let bundle_version = required_u64(object, "bundle_version")?;
    let rollback_counter = required_u64(object, "rollback_counter")?;
    if bundle_version == 0 || rollback_counter == 0 {
        return Err(KernelError::InvalidProfile);
    }
    let bundle_class = parse_bundle_class(required_string(object, "bundle_class")?)?;
    let created = parse_iso_date(required_string(object, "created")?)?;
    let payload = parse_payload(object.get("payload").ok_or(KernelError::InvalidProfile)?)?;
    let signature = parse_signature(object.get("signature").ok_or(KernelError::InvalidProfile)?)?;
    Ok(CertificationBundle {
        schema_version,
        bundle_id,
        bundle_version,
        rollback_counter,
        bundle_class,
        created,
        payload,
        signature,
    })
}

pub fn parse_trust_anchors(input: &[u8]) -> KernelResult<Vec<BundleTrustAnchor>> {
    if input.is_empty() || input.len() > MAX_CERTIFICATION_BUNDLE_BYTES {
        return Err(KernelError::LengthOverflow);
    }
    let root = JsonParser::new(input).parse()?;
    let object = root.as_object()?;
    reject_unknown_fields(object, &["schema_version", "trust_anchors"])?;
    if required_string(object, "schema_version")? != "hyperion-certification-trust-anchors-1.0" {
        return Err(KernelError::InvalidProfile);
    }
    let anchors = object
        .get("trust_anchors")
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    bounded_len(anchors.len())?;
    if anchors.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    anchors.iter().map(parse_trust_anchor).collect()
}

pub fn trust_anchors_json(anchors: &[BundleTrustAnchor]) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(
        &mut out,
        "schema_version",
        "hyperion-certification-trust-anchors-1.0",
    );
    out.push_str(",\"trust_anchors\":[");
    for (idx, anchor) in anchors.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "signer_id", &anchor.signer_id);
        out.push(',');
        push_json_str(
            &mut out,
            "signing_key_fingerprint",
            &anchor.signing_key_fingerprint,
        );
        out.push(',');
        push_json_str(
            &mut out,
            "verification_public_key_hex",
            &anchor.verification_public_key_hex,
        );
        out.push(',');
        push_json_str(
            &mut out,
            "allowed_payload_sha256",
            &anchor.allowed_payload_sha256,
        );
        if let Some(not_after) = anchor.not_after {
            out.push(',');
            push_json_str(&mut out, "not_after", &format_date(not_after));
        }
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

pub fn certification_bundle_json(bundle: &CertificationBundle) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "schema_version", &bundle.schema_version);
    out.push(',');
    push_json_str(&mut out, "bundle_id", &bundle.bundle_id);
    out.push(',');
    push_json_number(&mut out, "bundle_version", bundle.bundle_version);
    out.push(',');
    push_json_number(&mut out, "rollback_counter", bundle.rollback_counter);
    out.push(',');
    push_json_str(&mut out, "bundle_class", bundle.bundle_class.as_str());
    out.push(',');
    push_json_str(&mut out, "created", &format_date(bundle.created));
    out.push_str(",\"payload\":");
    out.push_str(&payload_canonical_json(&bundle.payload));
    out.push_str(",\"signature\":");
    push_signature_json(&mut out, &bundle.signature);
    out.push_str("}\n");
    out
}

pub fn create_bundle_from_inputs(
    input: BundleProvisioningInput<'_>,
) -> KernelResult<(String, String)> {
    validate_identifier(input.bundle_id)?;
    let callback_timeouts = input
        .callback_timeouts
        .unwrap_or_else(CallbackTimeoutProfile::defaults);
    validate_callback_timeouts(callback_timeouts)?;
    let secret = input
        .signing_private_key_hex
        .unwrap_or(DEFAULT_FIXTURE_SIGNING_PRIVATE_KEY_HEX);
    validate_hex_len(secret, 32)?;
    let payload = CertificationBundlePayload {
        submission_scope: SubmissionScope {
            product_name: input.product_name.to_string(),
            product_version: input.product_version.to_string(),
            certification_target: input.certification_target.to_string(),
            interfaces: split_csv(input.interfaces)?,
            authorities: split_csv(input.authorities)?,
        },
        standards_target: StandardsTarget {
            emv_contact_version: input.emv_contact_version.to_string(),
            emv_contactless_kernel: input.emv_contactless_kernel.to_string(),
            bulletins_included: split_csv(input.bulletins_included)?,
            bulletins_excluded: split_csv_allow_empty(input.bulletins_excluded)?,
        },
        terminal_profile: TerminalProfile {
            terminal_type: input.terminal_type.to_string(),
            device_model: input.device_model.to_string(),
            firmware_version: input.firmware_version.to_string(),
            l1_approval_reference: input.l1_approval_reference.to_string(),
            pci_pts_reference: input.pci_pts_reference.to_string(),
            supported_interfaces: split_csv(input.interfaces)?,
        },
        runtime_policy: RuntimePolicy {
            callback_timeouts,
            offline_counter_persistence: "terminal-nonvolatile-counter-required".to_string(),
            trace_masking_policy: "mask-pan-track-equivalent-cryptogram-pin-and-sensitive-tlv"
                .to_string(),
        },
        kernel_registry: vec![KernelProfileRegistration {
            kernel_profile_id: input.kernel_profile_id.to_string(),
            interface: input.kernel_interface.to_string(),
            algorithm: input.kernel_algorithm.to_string(),
            c8_package: input.c8_package.to_string(),
            scheme_scope: split_csv(input.scheme_scope)?,
        }],
        cvm_extensions: vec![CvmExtensionRule {
            rule_id: "baseline-cvm-extension-data".to_string(),
            scheme_scope: split_csv(input.scheme_scope)?,
            cvm_code_hex: "1E".to_string(),
            meaning: "signature-or-cdcvm-as-authority-profiled".to_string(),
            tvr_on_failure_hex: "0000000000".to_string(),
            continue_on_failure: true,
        }],
        test_plan: vec![CertificationTestCase {
            case_id: "CERT-DATA-0001".to_string(),
            vector_class: input.vector_class.to_string(),
            expected_outcome: "bundle-loads-and-profile-validates".to_string(),
            trace_requirement: "masked-apdu-trace-required-for-submission".to_string(),
        }],
        artifact_hashes: vec![
            ArtifactHashBinding {
                artifact_id: "scheme_profile_set_json".to_string(),
                artifact_kind: "scheme-profile".to_string(),
                sha256_hex: to_hex(&sha256(input.scheme_profile_set_json.as_bytes())),
                binds_open_issues: vec!["CERT-OPEN-002".to_string(), "CERT-OPEN-003".to_string()],
            },
            ArtifactHashBinding {
                artifact_id: "vector_bundle_json".to_string(),
                artifact_kind: "test-vectors".to_string(),
                sha256_hex: to_hex(&sha256(input.vector_bundle_json.as_bytes())),
                binds_open_issues: vec!["CERT-OPEN-004".to_string(), "CERT-OPEN-012".to_string()],
            },
        ],
        scheme_profile_set_json: input.scheme_profile_set_json.to_string(),
        vector_bundle_json: input.vector_bundle_json.to_string(),
    };
    validate_payload(&payload)?;
    let payload_json = payload_canonical_json(&payload);
    let payload_hash = sha256(payload_json.as_bytes());
    let signing_key = signing_key_from_hex(secret)?;
    let verification_public_key = signing_key.verifying_key().to_bytes();
    let verification_public_key_hex = to_hex(&verification_public_key);
    let signing_key_fingerprint = to_hex(&sha256(&verification_public_key));
    let signature_hex = signature_ed25519_hex(
        &signing_key,
        input.signer_id,
        &signing_key_fingerprint,
        &payload_hash,
    );
    let signature_artifact_sha256 = to_hex(&sha256(signature_hex.as_bytes()));
    let bundle = CertificationBundle {
        schema_version: CERTIFICATION_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: input.bundle_id.to_string(),
        bundle_version: input.bundle_version,
        rollback_counter: input.rollback_counter,
        bundle_class: input.bundle_class,
        created: input.created,
        payload,
        signature: BundleSignature {
            algorithm: CERTIFICATION_BUNDLE_SIGNATURE_ALGORITHM.to_string(),
            signer_id: input.signer_id.to_string(),
            signing_key_fingerprint: signing_key_fingerprint.clone(),
            payload_sha256: to_hex(&payload_hash),
            signature_hex,
            signature_artifact_sha256,
        },
    };
    let anchor = BundleTrustAnchor {
        signer_id: input.signer_id.to_string(),
        signing_key_fingerprint,
        verification_public_key_hex,
        allowed_payload_sha256: to_hex(&payload_hash),
        not_after: input.trust_not_after,
    };
    Ok((
        certification_bundle_json(&bundle),
        trust_anchors_json(&[anchor]),
    ))
}

pub struct BundleProvisioningInput<'a> {
    pub bundle_id: &'a str,
    pub bundle_version: u64,
    pub rollback_counter: u64,
    pub bundle_class: BundleClass,
    pub created: EmvDate,
    pub product_name: &'a str,
    pub product_version: &'a str,
    pub certification_target: &'a str,
    pub interfaces: &'a str,
    pub authorities: &'a str,
    pub emv_contact_version: &'a str,
    pub emv_contactless_kernel: &'a str,
    pub bulletins_included: &'a str,
    pub bulletins_excluded: &'a str,
    pub terminal_type: &'a str,
    pub device_model: &'a str,
    pub firmware_version: &'a str,
    pub l1_approval_reference: &'a str,
    pub pci_pts_reference: &'a str,
    pub kernel_profile_id: &'a str,
    pub kernel_interface: &'a str,
    pub kernel_algorithm: &'a str,
    pub c8_package: &'a str,
    pub scheme_scope: &'a str,
    pub vector_class: &'a str,
    pub signer_id: &'a str,
    pub signing_private_key_hex: Option<&'a str>,
    pub trust_not_after: Option<EmvDate>,
    pub callback_timeouts: Option<CallbackTimeoutProfile>,
    pub scheme_profile_set_json: &'a str,
    pub vector_bundle_json: &'a str,
}

pub fn certification_bundle_report_markdown(loaded: &LoadedCertificationBundle) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Data-Driven Certification Bundle");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Bundle ID: `{}`", loaded.bundle.bundle_id);
    let _ = writeln!(
        out,
        "- Bundle class: `{}`",
        loaded.bundle.bundle_class.as_str()
    );
    let _ = writeln!(
        out,
        "- Rollback counter: `{}`",
        loaded.bundle.rollback_counter
    );
    let _ = writeln!(
        out,
        "- Verification status: `{}`",
        loaded.verification_status
    );
    let _ = writeln!(
        out,
        "- Payload SHA-256: `{}`",
        to_hex(&loaded.payload_sha256)
    );
    let _ = writeln!(out, "- Bundle SHA-256: `{}`", to_hex(&loaded.bundle_sha256));
    let _ = writeln!(
        out,
        "- Scheme profile SHA-256: `{}`",
        to_hex(&loaded.scheme_profile_sha256)
    );
    let _ = writeln!(
        out,
        "- Vector bundle SHA-256: `{}`",
        to_hex(&loaded.vector_bundle_sha256)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Data-Driven Scope");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Product: `{}` `{}`",
        loaded.bundle.payload.submission_scope.product_name,
        loaded.bundle.payload.submission_scope.product_version
    );
    let _ = writeln!(
        out,
        "- Target: `{}`",
        loaded.bundle.payload.submission_scope.certification_target
    );
    let _ = writeln!(
        out,
        "- Interfaces: `{}`",
        loaded.bundle.payload.submission_scope.interfaces.join(", ")
    );
    let _ = writeln!(
        out,
        "- Kernel registry entries: `{}`",
        loaded.bundle.payload.kernel_registry.len()
    );
    let _ = writeln!(
        out,
        "- Test-plan cases: `{}`",
        loaded.bundle.payload.test_plan.len()
    );
    let _ = writeln!(
        out,
        "- Artifact bindings: `{}`",
        loaded.bundle.payload.artifact_hashes.len()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Boundary: the same Rust binary can load a different certification bundle without source changes, provided the bundle verifies against configured trust-anchor data. External lab, scheme, device, PCI/PED, CAPK, vector, and approval evidence remains authoritative.");
    out
}

pub fn certification_bundle_workbench_html(bundle_json: &str, trust_anchors_json: &str) -> String {
    let mut out = String::new();
    out.push_str(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hyperion Data Bundle Workbench</title><style>
:root{--ink:#1f252c;--muted:#5e6876;--line:#d7dde5;--panel:#ffffff;--wash:#f5f7fa;--nav:#162231;--nav2:#22344a;--blue:#1f6aa5;--green:#0f7b4f;--amber:#9a5b00;--red:#a32929;--cyan:#0f6f78;--violet:#654a93}*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--wash);color:var(--ink)}header{background:linear-gradient(180deg,var(--nav),var(--nav2));color:#fff;padding:18px 24px;border-bottom:4px solid #70b6c8}header h1{margin:0;font-size:24px;letter-spacing:0}header p{margin:6px 0 0;color:#d9e5ef;max-width:980px}.shell{display:grid;grid-template-columns:320px minmax(0,1fr);gap:18px;padding:18px}.sidebar{background:#fff;border:1px solid var(--line);border-radius:6px;padding:14px;align-self:start;position:sticky;top:12px}.brand{display:flex;align-items:center;gap:10px;margin-bottom:12px}.mark{width:34px;height:34px;border-radius:6px;background:#1f6aa5;display:grid;place-items:center;color:#fff;font-weight:800}.status-pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;background:#fff;font-weight:700}.status-pass{color:var(--green);border-color:#a7d9c1}.status-warn{color:var(--amber);border-color:#e7c884}.status-fail{color:var(--red);border-color:#e0a0a0}.steps{display:grid;gap:8px;margin:12px 0}.step{display:grid;grid-template-columns:24px 1fr;gap:8px;padding:8px;border:1px solid var(--line);border-radius:6px;background:#fbfcfd}.step b{display:grid;place-items:center;width:24px;height:24px;border-radius:50%;background:#e6eef7;color:#15466d}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}button{border:1px solid #1b5a8f;background:var(--blue);color:#fff;border-radius:5px;padding:8px 10px;font-weight:700;cursor:pointer}button.secondary{background:#fff;color:#1b4c75;border-color:#9bb5cc}button.ghost{background:#f9fbfd;color:#344153;border-color:var(--line)}button:focus,input:focus,select:focus,textarea:focus{outline:2px solid #70b6c8;outline-offset:1px}.content{display:grid;gap:18px}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.metric{background:#fff;border:1px solid var(--line);border-radius:6px;padding:12px}.metric strong{display:block;font-size:22px}.metric span{color:var(--muted);font-size:12px}.panel{background:#fff;border:1px solid var(--line);border-radius:6px;padding:14px}.panel h2{margin:0 0 10px;font-size:18px}.panel h3{margin:14px 0 8px;font-size:15px}.tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}.tab{background:#fff;color:#1f3f5e;border-color:var(--line)}.tab[aria-pressed="true"]{background:#1f6aa5;color:#fff;border-color:#1f6aa5}.form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.field label{font-weight:700;display:block;margin-bottom:4px}.field input,.field select,.field textarea,textarea.editor{width:100%;border:1px solid #bac4d0;border-radius:5px;padding:8px;font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:#fff;color:#1e2730}.field small{display:block;color:var(--muted);margin-top:4px}.help-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.help{border-left:4px solid #70b6c8;background:#f8fbfd;padding:10px;border-radius:4px}.help b{display:block;margin-bottom:4px}.help dl{margin:0;display:grid;grid-template-columns:82px 1fr;gap:4px}.help dt{font-weight:700;color:#3d4b5b}.help dd{margin:0;color:#33404e}.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.editor{min-height:300px;resize:vertical}.compiled{min-height:420px}.findings{display:grid;gap:8px}.finding{border:1px solid var(--line);border-radius:6px;padding:10px;background:#fff}.finding .top{display:flex;gap:8px;align-items:center;justify-content:space-between}.severity{border-radius:999px;padding:2px 8px;font-weight:800;font-size:12px}.sev-info{background:#e7f2fb;color:#125381}.sev-warning{background:#fff2d2;color:#7a4a00}.sev-error{background:#fde6e6;color:#8f1d1d}.coverage{overflow:auto}.coverage table{width:100%;border-collapse:collapse;min-width:940px}.coverage th,.coverage td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}.coverage th{background:#f1f4f8;color:#314050}.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:12px;font-weight:700}.covered{color:var(--green);border-color:#a7d9c1;background:#eefaf3}.incomplete{color:var(--red);border-color:#e0a0a0;background:#fff0f0}.external_required,.warning{color:var(--amber);border-color:#e7c884;background:#fff8e8}pre{white-space:pre-wrap;background:#111a24;color:#e6eef7;border-radius:6px;padding:10px;overflow:auto}code{background:#edf1f5;border:1px solid #d8dee6;border-radius:3px;padding:1px 4px}.hidden{display:none}.note{color:var(--muted)}@media(max-width:1050px){.shell{grid-template-columns:1fr}.sidebar{position:static}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.form-grid,.split,.help-grid{grid-template-columns:1fr}}@media(max-width:620px){.shell{padding:10px}.summary{grid-template-columns:1fr}header{padding:14px}.actions button{width:100%}}
</style></head><body><header><h1>Hyperion Data Bundle Workbench</h1><p>Author, lint, compile, and explain data-driven EMV certification bundles. This local workbench keeps sensitive profile, CAPK, vector, and evidence data in your browser and pairs every setting with its role, impact, utilization, and security consequences.</p></header><main class="shell"><aside class="sidebar"><div class="brand"><div class="mark">HX</div><div><strong>Bundle Builder</strong><div class="note">Certification data provisioning</div></div></div><div id="status-pill" class="status-pill status-warn">Status: checking</div><div class="steps"><div class="step"><b>1</b><span>Describe product, target scope, interfaces, authorities, and standards.</span></div><div class="step"><b>2</b><span>Attach scheme profiles, CAPKs, vectors, kernel registry, CVM rules, and runtime policy.</span></div><div class="step"><b>3</b><span>Compile and lint locally, then run the Rust validator for authoritative loader checks.</span></div><div class="step"><b>4</b><span>Freeze fingerprints with external lab, scheme, L1, device, PCI/PED, and trace evidence.</span></div></div><div class="actions"><button type="button" onclick="compileBundle()">Compile</button><button class="secondary" type="button" onclick="syncFromJson()">Sync From JSON</button><button class="ghost" type="button" onclick="resetFixture()">Reset Fixture</button></div><p class="note">This page never uploads data; no network calls are made by this page. Browser checks are advisory; the Rust command below is the authority.</p><pre>cargo run --quiet --example krn_certification_bundle -- --lint --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json</pre></aside><section class="content"><div class="summary"><div class="metric"><strong id="finding-count">0</strong><span>lint findings</span></div><div class="metric"><strong id="coverage-count">0</strong><span>capability areas</span></div><div class="metric"><strong id="hash-prefix">pending</strong><span>bundle hash prefix</span></div><div class="metric"><strong id="external-count">0</strong><span>external evidence gates</span></div></div><section class="panel"><div class="tabs" role="toolbar" aria-label="Workbench sections"><button class="tab" data-view="guided" aria-pressed="true">Guided Fields</button><button class="tab" data-view="profiles" aria-pressed="false">Profiles & Vectors</button><button class="tab" data-view="lint" aria-pressed="false">Lint & Suggestions</button><button class="tab" data-view="coverage" aria-pressed="false">EMV Coverage</button><button class="tab" data-view="compiled" aria-pressed="false">Compiled JSON</button></div><div id="guided"><h2>Guided Bundle Fields</h2><div class="form-grid"><div class="field"><label for="bundle_id">Bundle ID</label><input id="bundle_id"><small>Stable identifier used in reports, rollback records, and evidence packs.</small></div><div class="field"><label for="bundle_class">Bundle Class</label><select id="bundle_class"><option>CERTIFICATION</option><option>TESTING</option></select><small>Certification mode rejects TESTING bundles.</small></div><div class="field"><label for="rollback_counter">Rollback Counter</label><input id="rollback_counter" type="number" min="1"><small>Must increase for every replacement bundle.</small></div><div class="field"><label for="product_name">Product Name</label><input id="product_name"><small>Name shown to lab, acquirer, scheme, and evidence reports.</small></div><div class="field"><label for="product_version">Product Version</label><input id="product_version"><small>Must match submitted binary and report pack.</small></div><div class="field"><label for="certification_target">Certification Target</label><input id="certification_target"><small>Defines claimed interface and approval scope.</small></div><div class="field"><label for="interfaces">Interfaces</label><input id="interfaces"><small>Comma-separated: contact, contactless.</small></div><div class="field"><label for="authorities">Authorities</label><input id="authorities"><small>Lab, scheme, acquirer, and internal authority references.</small></div><div class="field"><label for="bulletins_included">Bulletins Included</label><input id="bulletins_included"><small>Standards-watch and bulletin reconciliation data.</small></div></div><h3>Runtime Policy</h3><div class="form-grid"><div class="field"><label for="apdu_timeout">APDU Timeout MS</label><input id="apdu_timeout" type="number" min="1" max="60000"></div><div class="field"><label for="host_timeout">Host Authorization Timeout MS</label><input id="host_timeout" type="number" min="1" max="60000"></div><div class="field"><label for="pin_timeout">PIN Entry Timeout MS</label><input id="pin_timeout" type="number" min="1" max="60000"></div><div class="field"><label for="ui_timeout">Contactless UI Timeout MS</label><input id="ui_timeout" type="number" min="1" max="60000"></div><div class="field"><label for="l1_ref">L1 Approval Reference</label><input id="l1_ref"></div><div class="field"><label for="pci_ref">PCI/PED Reference</label><input id="pci_ref"></div></div><h3>Field Impact Guide</h3><div id="field-help" class="help-grid"></div></div><div id="profiles" class="hidden"><h2>Profiles, Vectors, Trust Anchors</h2><div class="split"><div><h3>Bundle JSON</h3><textarea id="bundle" class="editor">"#);
    push_html_text(&mut out, bundle_json);
    out.push_str(
        r#"</textarea></div><div><h3>Trust Anchors JSON</h3><textarea id="trust" class="editor">"#,
    );
    push_html_text(&mut out, trust_anchors_json);
    out.push_str(r#"</textarea></div></div><div class="split"><div><h3>Embedded Scheme Profile Set JSON</h3><textarea id="scheme_profile" class="editor"></textarea></div><div><h3>Embedded Vector Bundle JSON</h3><textarea id="vector_bundle" class="editor"></textarea></div></div></div><div id="lint" class="hidden"><h2>Lint Findings and Suggestions</h2><div id="findings" class="findings"></div></div><div id="coverage" class="hidden"><h2>EMV Capability Coverage</h2><p class="note">Coverage means the bundle has data fields and bindings for the capability. External certification evidence is still required where marked.</p><div class="coverage"><table><thead><tr><th>ID</th><th>Area</th><th>Status</th><th>Bundle Source</th><th>Role</th><th>Suggestion</th></tr></thead><tbody id="coverage-body"></tbody></table></div></div><div id="compiled" class="hidden"><h2>Compiled Outputs</h2><div class="split"><div><h3>Normalized Bundle JSON</h3><textarea id="compiled_bundle" class="editor compiled"></textarea></div><div><h3>Compile Report JSON</h3><textarea id="compiled_report" class="editor compiled"></textarea></div></div></div></section></section></main><script>
const initialBundleText = document.getElementById('bundle').value;
const initialTrustText = document.getElementById('trust').value;
const help = [
 {field:'bundle_id',role:'Stable bundle identity',impact:'Appears in reports, freeze manifests, rollback records, and support handoffs.',used:'Loader reports, evidence pack, audit trail',security:'Do not reuse an ID for materially different certified scope.'},
 {field:'bundle_class',role:'Mode boundary',impact:'TESTING is allowed only in test mode; CERTIFICATION is required for submission and production policy.',used:'Bundle loader policy',security:'Prevents test fixtures from being promoted accidentally.'},
 {field:'rollback_counter',role:'Anti-rollback version',impact:'The runtime rejects counters less than or equal to the installed counter.',used:'BundleLoadPolicy',security:'Protects terminals from downgrades to weaker data.'},
 {field:'interfaces',role:'Claimed interface scope',impact:'Determines whether contact and contactless capabilities must be present in profiles and kernel registry.',used:'Selection, contact L2, C-8, reports',security:'Do not claim interfaces without matching device and L1 evidence.'},
 {field:'scheme_profile_set_json',role:'Variable EMV profile data',impact:'Carries AIDs, TAC/IAC, CAPKs, CVM/TRM settings, CDA behavior, scripts, and relay resistance.',used:'Selection, ODA, CVM, TRM, TAA, issuer scripts',security:'Must be signed or hash-pinned and authority approved.'},
 {field:'vector_bundle_json',role:'Certification vector binding',impact:'Links expected ODA and APDU test behavior to the profile and submitted build.',used:'Lab replay, trace pack, ODA reports',security:'Fixture vectors must be replaced by accepted certification vectors.'},
 {field:'trust_anchors',role:'Authentication root',impact:'Maps signer and fingerprint to an allowed payload hash.',used:'Bundle signature verification',security:'Provision public verification keys here; keep private signing keys outside generated workbench files.'},
 {field:'callback_timeouts',role:'Runtime callback bounds',impact:'Controls APDU transport, host, PIN, and contactless UI waiting behavior.',used:'C ABI and runtime policy',security:'Keep bounded to avoid denial-of-service and inconsistent certification traces.'},
 {field:'artifact_hashes',role:'Evidence freeze binding',impact:'Pins profiles, vectors, traces, reports, and external attachments by SHA-256.',used:'Certification report pack',security:'Every accepted artifact should be immutable and hash-bound.'},
 {field:'terminal_profile',role:'Device and PED scope',impact:'Names terminal type, model, firmware, L1, and PCI/PED evidence references.',used:'Submission manifest and external gates',security:'Must match submitted hardware and firmware.'}
];
const capabilityDefinitions = [
 {id:'selection',area:'Application selection',source:'payload.scheme_profile_set_json.schemes[].aids',role:'PSE/PPSE and AID candidate matching remain data-driven.',check:s=>countAids(s.profile)>0,suggestion:'Add AID entries for each claimed scheme and interface.'},
 {id:'contact_l2',area:'Contact EMV L2',source:'interfaces + contact_kernel_type + contact AIDs',role:'Contact kernel behavior, TAC/IAC, DOL, CVM, TRM, and scripts come from profile data.',check:s=>s.interfaces.includes('contact')&&hasAidInterface(s.profile,'contact')&&s.profile.schemes.some(x=>x.contact_kernel_type),suggestion:'Add contact scope, contact AID profiles, and contact_kernel_type.'},
 {id:'contactless_c8',area:'Contactless Kernel C-8',source:'kernel_registry + contactless AIDs',role:'C-8 package, TTQ, CDCVM, relay resistance, and contactless limits are configured as data.',check:s=>s.interfaces.includes('contactless')&&s.registry.some(x=>x.interface==='contactless')&&hasAidInterface(s.profile,'contactless'),suggestion:'Add a contactless kernel registry entry and contactless AID profiles.'},
 {id:'capk_authority',area:'CAPK authority',source:'scheme_profile_set_json.schemes[].capks',role:'RID/index public keys, expiry, checksum, and provenance for ODA.',check:s=>s.profile.schemes.some(x=>(x.capks||[]).length>0),suggestion:'Attach authority-approved CAPKs and bind their hashes.'},
 {id:'oda_vectors',area:'SDA/DDA/CDA vectors',source:'vector_bundle_json + artifact_hashes',role:'Binds ODA expected outputs, CDA behavior, and trace replay evidence.',check:s=>s.vector.vector_class==='CERTIFICATION'&&(s.vector.cases||s.vector.test_vectors||[]).length>0&&!JSON.stringify(s.vector).toLowerCase().match(/fixture|pending|placeholder/),suggestion:'Replace fixture vectors with lab/scheme CERTIFICATION vectors containing non-empty SDA, DDA, and CDA cases.'},
 {id:'cvm_pin',area:'CVM and PIN',source:'cvm_extensions + aid CVM limits',role:'Controls online PIN, offline PIN, signature, CDCVM, and certified extension codes.',check:s=>s.cvm.length>0||allAids(s.profile).some(a=>a.cvm_limit_contact||a.contactless_cvm_limit||a.cdcvm_supported),suggestion:'Add CVM limits, extension rules, and PED-owned PIN evidence.'},
 {id:'trm',area:'Terminal risk management',source:'aid floor/random/offline limits',role:'Defines floor limits, random selection, transaction type limits, and offline counters.',check:s=>allAids(s.profile).some(a=>a.floor_limit||a.random_selection_percent||a.lower_consecutive_offline_limit||a.upper_consecutive_offline_limit||(a.transaction_type_floor_limits||[]).length),suggestion:'Add TRM limits for the target schemes and transaction types.'},
 {id:'taa',area:'Terminal action analysis',source:'scheme_profile_set_json.schemes[].taa',role:'Keeps TAC/IAC behavior outside compiled code.',check:s=>s.profile.schemes.some(x=>x.taa),suggestion:'Attach scheme-approved TAC/IAC profile material.'},
 {id:'issuer_scripts',area:'Issuer scripts',source:'critical_issuer_script_ins',role:'Defines critical issuer script INS values for post-authorization processing.',check:s=>allAids(s.profile).some(a=>(a.critical_issuer_script_ins||[]).length),suggestion:'Add script policy where schemes require it.'},
 {id:'relay_resistance',area:'Relay resistance',source:'aid relay_resistance',role:'Controls contactless relay resistance when required by profile.',check:s=>allAids(s.profile).some(a=>a.relay_resistance),suggestion:'Add relay resistance data for applicable contactless profiles.'},
 {id:'runtime_abi',area:'Runtime ABI and timeouts',source:'runtime_policy.callback_timeouts',role:'Sets bounded callback behavior for APDU, host, PIN, and UI operations.',check:s=>Object.values(s.timeouts).every(v=>Number.isInteger(v)&&v>=1&&v<=60000),suggestion:'Keep every timeout in the 1..60000 ms range.'},
 {id:'security_trust',area:'Signature and trust',source:'signature + trust_anchors',role:'Authenticates payload hash and signer identity before loading.',check:s=>s.trust.trust_anchors&&s.trust.trust_anchors.length>0&&s.bundle.signature&&s.bundle.signature.payload_sha256,suggestion:'Provision protected authority public verification keys and allowed payload hashes.'},
 {id:'device_l1',area:'Device and L1 evidence',source:'terminal_profile.l1_approval_reference',role:'Binds device/reader evidence to the submitted scope.',check:s=>externalStatus(s.bundle.payload?.terminal_profile?.l1_approval_reference)==='covered',status:s=>externalStatus(s.bundle.payload?.terminal_profile?.l1_approval_reference),suggestion:'Replace pre-lab placeholders with accepted L1/device references.'},
 {id:'pci_ped',area:'PCI/PED evidence',source:'terminal_profile.pci_pts_reference',role:'Binds PED-owned PIN and PCI PTS evidence to the target.',check:s=>externalStatus(s.bundle.payload?.terminal_profile?.pci_pts_reference)==='covered',status:s=>externalStatus(s.bundle.payload?.terminal_profile?.pci_pts_reference),suggestion:'Replace pre-lab placeholders with PCI/PED references.'},
 {id:'standards_bulletins',area:'Standards and bulletins',source:'standards_target',role:'Captures contact/contactless target versions and bulletin reconciliation.',check:s=>(s.bundle.payload?.standards_target?.bulletins_included||[]).length>0,suggestion:'Add the accepted standards-watch or bulletin set.'},
 {id:'evidence_freeze',area:'Evidence freeze',source:'test_plan + artifact_hashes',role:'Pins profiles, vectors, reports, traces, and external evidence by hash.',check:s=>(s.bundle.payload?.test_plan||[]).length>0&&hasArtifact(s.bundle,'scheme_profile_set_json')&&hasArtifact(s.bundle,'vector_bundle_json'),suggestion:'Bind every report, trace pack, vector set, and submitted binary.'},
 {id:'trace_privacy',area:'Trace privacy',source:'runtime_policy.trace_masking_policy',role:'Prevents sensitive PAN, track, cryptogram, and PIN-adjacent data in artifacts.',check:s=>(s.bundle.payload?.runtime_policy?.trace_masking_policy||'').toLowerCase().includes('mask'),suggestion:'Use a masking policy that covers PAN, track-equivalent data, cryptograms, PIN, and sensitive TLVs.'}
];
function parseJson(id, findings){try{return JSON.parse(document.getElementById(id).value)}catch(e){findings.push({severity:'error',field_path:id,title:'Invalid JSON',impact:'This document cannot be parsed or compiled.',suggestion:e.message});return null}}
function csv(v){return String(v||'').split(',').map(x=>x.trim()).filter(Boolean)}
function allAids(profile){return (profile.schemes||[]).flatMap(s=>s.aids||[])}
function countAids(profile){return allAids(profile).length}
function hasAidInterface(profile,name){return allAids(profile).some(a=>(a.interfaces||[]).includes(name))}
function hasArtifact(bundle,id){return (bundle.payload?.artifact_hashes||[]).some(a=>a.artifact_id===id)}
function externalStatus(value){const v=String(value||'').toLowerCase();return (!v||v.includes('pending')||v.includes('required')||v.includes('external-'))?'external_required':'covered'}
function classifyText(value){const v=String(value||'').toLowerCase();return v.includes('pending')||v.includes('required')||v.includes('external-')}
async function sha256Hex(text){const data=new TextEncoder().encode(text);const hash=await crypto.subtle.digest('SHA-256',data);return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('')}
function readState(findings){const bundle=parseJson('bundle',findings)||{};const trust=parseJson('trust',findings)||{};let profile={schemes:[]};let vector={};try{profile=JSON.parse(bundle.payload?.scheme_profile_set_json||'{}')}catch(e){findings.push({severity:'error',field_path:'payload.scheme_profile_set_json',title:'Embedded scheme profile JSON is invalid',impact:'The Rust loader cannot parse AIDs, CAPKs, TAC/IAC, CVM, TRM, or scripts.',suggestion:e.message})}try{vector=JSON.parse(bundle.payload?.vector_bundle_json||'{}')}catch(e){findings.push({severity:'error',field_path:'payload.vector_bundle_json',title:'Embedded vector bundle JSON is invalid',impact:'ODA and trace vector bindings cannot be verified.',suggestion:e.message})}return {bundle,trust,profile,vector,interfaces:bundle.payload?.submission_scope?.interfaces||[],registry:bundle.payload?.kernel_registry||[],cvm:bundle.payload?.cvm_extensions||[],timeouts:bundle.payload?.runtime_policy?.callback_timeouts||{}}}
function syncFromJson(){const findings=[];const s=readState(findings);const b=s.bundle;const p=b.payload||{};const scope=p.submission_scope||{};const term=p.terminal_profile||{};const std=p.standards_target||{};const rt=p.runtime_policy||{};const t=rt.callback_timeouts||{};set('bundle_id',b.bundle_id);set('bundle_class',b.bundle_class);set('rollback_counter',b.rollback_counter);set('product_name',scope.product_name);set('product_version',scope.product_version);set('certification_target',scope.certification_target);set('interfaces',(scope.interfaces||[]).join(','));set('authorities',(scope.authorities||[]).join(','));set('bulletins_included',(std.bulletins_included||[]).join(','));set('apdu_timeout',t.apdu_transport_timeout_ms);set('host_timeout',t.host_authorization_timeout_ms);set('pin_timeout',t.pin_entry_timeout_ms);set('ui_timeout',t.contactless_ui_timeout_ms);set('l1_ref',term.l1_approval_reference);set('pci_ref',term.pci_pts_reference);set('scheme_profile',p.scheme_profile_set_json||'');set('vector_bundle',p.vector_bundle_json||'');compileBundle()}
function applyGuidedToBundle(){const findings=[];const bundle=parseJson('bundle',findings);if(!bundle)return null;bundle.bundle_id=val('bundle_id')||bundle.bundle_id;bundle.bundle_class=val('bundle_class')||bundle.bundle_class;bundle.rollback_counter=Number(val('rollback_counter'))||bundle.rollback_counter;bundle.payload=bundle.payload||{};bundle.payload.submission_scope=bundle.payload.submission_scope||{};bundle.payload.submission_scope.product_name=val('product_name')||bundle.payload.submission_scope.product_name;bundle.payload.submission_scope.product_version=val('product_version')||bundle.payload.submission_scope.product_version;bundle.payload.submission_scope.certification_target=val('certification_target')||bundle.payload.submission_scope.certification_target;bundle.payload.submission_scope.interfaces=csv(val('interfaces'));bundle.payload.submission_scope.authorities=csv(val('authorities'));bundle.payload.standards_target=bundle.payload.standards_target||{};bundle.payload.standards_target.bulletins_included=csv(val('bulletins_included'));bundle.payload.terminal_profile=bundle.payload.terminal_profile||{};bundle.payload.terminal_profile.supported_interfaces=csv(val('interfaces'));bundle.payload.terminal_profile.l1_approval_reference=val('l1_ref')||bundle.payload.terminal_profile.l1_approval_reference;bundle.payload.terminal_profile.pci_pts_reference=val('pci_ref')||bundle.payload.terminal_profile.pci_pts_reference;bundle.payload.runtime_policy=bundle.payload.runtime_policy||{};bundle.payload.runtime_policy.callback_timeouts={apdu_transport_timeout_ms:Number(val('apdu_timeout')),host_authorization_timeout_ms:Number(val('host_timeout')),pin_entry_timeout_ms:Number(val('pin_timeout')),contactless_ui_timeout_ms:Number(val('ui_timeout'))};bundle.payload.scheme_profile_set_json=val('scheme_profile')||bundle.payload.scheme_profile_set_json;bundle.payload.vector_bundle_json=val('vector_bundle')||bundle.payload.vector_bundle_json;document.getElementById('bundle').value=JSON.stringify(bundle,null,2);return bundle}
function val(id){return document.getElementById(id).value}function set(id,v){document.getElementById(id).value=v??''}
function required(findings,obj,path,title,suggestion){const parts=path.split('.');let cur=obj;for(const part of parts){cur=cur?.[part]}if(cur===undefined||cur===null||cur===''||(Array.isArray(cur)&&cur.length===0)){findings.push({severity:'error',field_path:path,title,impact:'Required bundle data is missing, so the runtime or certification report cannot use it.',suggestion})}}
function lintState(s,findings){const b=s.bundle;required(findings,b,'schema_version','Missing schema version','Use hyperion-certification-bundle-1.0.');required(findings,b,'bundle_id','Missing bundle ID','Assign a stable identifier.');required(findings,b,'payload','Missing payload','Create a payload with scope, profiles, vectors, runtime policy, tests, and hashes.');required(findings,b,'signature','Missing signature','Sign the canonical payload and bind it to a trust anchor.');if(b.bundle_class==='TESTING')findings.push({severity:'warning',field_path:'bundle_class',title:'Testing bundle selected',impact:'Certification and production loaders reject testing bundles.',suggestion:'Use CERTIFICATION for submission bundles.'});if(Number(b.rollback_counter)<=1)findings.push({severity:'warning',field_path:'rollback_counter',title:'Rollback counter is low',impact:'A deployed terminal rejects counters not greater than the installed value.',suggestion:'Increase monotonically for every replacement bundle.'});for(const [path,value] of [['certification_target',b.payload?.submission_scope?.certification_target],['l1_approval_reference',b.payload?.terminal_profile?.l1_approval_reference],['pci_pts_reference',b.payload?.terminal_profile?.pci_pts_reference]]){if(classifyText(value))findings.push({severity:'warning',field_path:path,title:'External evidence reference remains pending',impact:'The bundle may compile for pre-lab use, but certification closure requires accepted evidence.',suggestion:'Attach accepted authority evidence and update this reference.'})}if(!s.trust.trust_anchors||!s.trust.trust_anchors.length)findings.push({severity:'error',field_path:'trust_anchors',title:'No trust anchors',impact:'The runtime cannot authenticate the payload.',suggestion:'Provision protected signer trust anchors.'});for(const [k,v] of Object.entries(s.timeouts)){if(!Number.isInteger(v)||v<1||v>60000)findings.push({severity:'error',field_path:'runtime_policy.callback_timeouts.'+k,title:'Timeout outside allowed range',impact:'The Rust loader rejects callback timeouts outside 1..60000 ms.',suggestion:'Choose a bounded timeout in milliseconds.'})}if((b.payload?.runtime_policy?.trace_masking_policy||'').toLowerCase().indexOf('mask')<0)findings.push({severity:'error',field_path:'runtime_policy.trace_masking_policy',title:'Trace masking is not explicit',impact:'Reports and trace packs can leak sensitive card data.',suggestion:'Declare masking for PAN, track-equivalent data, cryptograms, PIN material, and sensitive TLVs.'})}
async function compileBundle(applyGuided=true){if(applyGuided)applyGuidedToBundle();const findings=[];const s=readState(findings);lintState(s,findings);const coverage=capabilityDefinitions.map(def=>{let status='incomplete';try{status=def.status?def.status(s):(def.check(s)?'covered':'incomplete')}catch(e){status='incomplete'}return {...def,status}});for(const c of coverage){if(c.status==='incomplete')findings.push({severity:'error',field_path:c.source,title:c.area+' is incomplete',impact:c.role,suggestion:c.suggestion})}const bundleText=document.getElementById('bundle').value;let hash='unavailable';try{hash=await sha256Hex(bundleText)}catch(e){}const report={type:'hyperion-browser-bundle-compile-report',status:findings.some(f=>f.severity==='error')?'fail':(findings.some(f=>f.severity==='warning')||coverage.some(c=>c.status==='external_required')?'warn':'pass'),bundle_sha256:hash,findings,capability_coverage:coverage,browser_advisory:true,rust_authority:'cargo run --quiet --example krn_certification_bundle -- --lint --bundle <bundle> --trust-anchors <trust>'};render(report);localStorage.setItem('hyperion_bundle_workbench_bundle',bundleText);localStorage.removeItem('hyperion_bundle_workbench_trust')}
function render(report){document.getElementById('compiled_bundle').value=document.getElementById('bundle').value;document.getElementById('compiled_report').value=JSON.stringify(report,null,2);const pill=document.getElementById('status-pill');pill.textContent='Status: '+report.status;pill.className='status-pill status-'+report.status;document.getElementById('finding-count').textContent=String(report.findings.length);document.getElementById('coverage-count').textContent=String(report.capability_coverage.length);document.getElementById('hash-prefix').textContent=report.bundle_sha256.slice(0,12);document.getElementById('external-count').textContent=String(report.capability_coverage.filter(c=>c.status==='external_required').length);document.getElementById('findings').innerHTML=report.findings.length?report.findings.map(f=>`<div class="finding"><div class="top"><strong>${esc(f.title)}</strong><span class="severity sev-${esc(f.severity)}">${esc(f.severity)}</span></div><div><code>${esc(f.field_path)}</code></div><p>${esc(f.impact)}</p><p><b>Suggestion:</b> ${esc(f.suggestion)}</p></div>`).join(''):'<p>No findings.</p>';document.getElementById('coverage-body').innerHTML=report.capability_coverage.map(c=>`<tr><td><code>${esc(c.id)}</code></td><td>${esc(c.area)}</td><td><span class="tag ${esc(c.status)}">${esc(c.status)}</span></td><td><code>${esc(c.source)}</code></td><td>${esc(c.role)}</td><td>${esc(c.suggestion)}</td></tr>`).join('')}
function esc(v){return String(v??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function resetFixture(){document.getElementById('bundle').value=initialBundleText;document.getElementById('trust').value=initialTrustText;syncFromJson()}
document.querySelectorAll('.tab').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.setAttribute('aria-pressed','false'));btn.setAttribute('aria-pressed','true');for(const id of ['guided','profiles','lint','coverage','compiled'])document.getElementById(id).classList.toggle('hidden',id!==btn.dataset.view)}));
document.getElementById('field-help').innerHTML=help.map(h=>`<div class="help"><b>${esc(h.field)}</b><dl><dt>Role</dt><dd>${esc(h.role)}</dd><dt>Impact</dt><dd>${esc(h.impact)}</dd><dt>Used by</dt><dd>${esc(h.used)}</dd><dt>Security</dt><dd>${esc(h.security)}</dd></dl></div>`).join('');
for(const id of ['bundle','trust'])document.getElementById(id).addEventListener('input',()=>compileBundle(false));
for(const id of ['scheme_profile','vector_bundle','bundle_id','bundle_class','rollback_counter','product_name','product_version','certification_target','interfaces','authorities','bulletins_included','apdu_timeout','host_timeout','pin_timeout','ui_timeout','l1_ref','pci_ref'])document.getElementById(id).addEventListener('input',()=>compileBundle(true));
const savedBundle=localStorage.getItem('hyperion_bundle_workbench_bundle');localStorage.removeItem('hyperion_bundle_workbench_trust');if(savedBundle)document.getElementById('bundle').value=savedBundle;syncFromJson();
</script></body></html>
"#);
    out
}

fn push_finding(
    report: &mut BundleCompileReport,
    severity: BundleLintSeverity,
    field_path: &str,
    title: &str,
    impact: &str,
    suggestion: &str,
) {
    report.findings.push(BundleLintFinding {
        severity,
        field_path: field_path.to_string(),
        title: title.to_string(),
        impact: impact.to_string(),
        suggestion: suggestion.to_string(),
    });
}

fn lint_parsed_bundle(
    report: &mut BundleCompileReport,
    bundle: &CertificationBundle,
    policy: &BundleLoadPolicy,
) {
    if bundle.bundle_class == BundleClass::Testing && policy.mode != BuildMode::Test {
        push_finding(
            report,
            BundleLintSeverity::Error,
            "bundle_class",
            "Testing bundle selected outside test mode",
            "Certification and production loaders must not accept a testing bundle.",
            "Switch the bundle_class to CERTIFICATION and use an authority-backed signature, or load it only with --mode test.",
        );
    }
    if bundle.rollback_counter <= policy.installed_rollback_counter {
        push_finding(
            report,
            BundleLintSeverity::Error,
            "rollback_counter",
            "Rollback counter is not newer than installed policy",
            "The runtime anti-rollback guard will reject older or equal bundles.",
            "Increase rollback_counter above the installed counter for any replacement bundle.",
        );
    }
    if bundle.created > policy.evaluation_date {
        push_finding(
            report,
            BundleLintSeverity::Error,
            "created",
            "Bundle creation date is after evaluation date",
            "A future-dated bundle cannot be accepted as current certification material.",
            "Set the evaluation date to the lab date or regenerate the bundle with a valid creation date.",
        );
    }
    if bundle.signature.algorithm == CERTIFICATION_BUNDLE_TEST_ALGORITHM {
        push_finding(
            report,
            BundleLintSeverity::Warning,
            "signature.algorithm",
            "Self-attested test signature detected",
            "Self-attestation is acceptable for local testing only and is not certification authority evidence.",
            "Use the certification bundle signature algorithm with a protected trust anchor before submission.",
        );
    }
    lint_pending_text(
        report,
        "submission_scope.certification_target",
        &bundle.payload.submission_scope.certification_target,
    );
    lint_pending_text(
        report,
        "terminal_profile.device_model",
        &bundle.payload.terminal_profile.device_model,
    );
    lint_pending_text(
        report,
        "terminal_profile.firmware_version",
        &bundle.payload.terminal_profile.firmware_version,
    );
    lint_pending_text(
        report,
        "terminal_profile.l1_approval_reference",
        &bundle.payload.terminal_profile.l1_approval_reference,
    );
    lint_pending_text(
        report,
        "terminal_profile.pci_pts_reference",
        &bundle.payload.terminal_profile.pci_pts_reference,
    );
    for (idx, authority) in bundle
        .payload
        .submission_scope
        .authorities
        .iter()
        .enumerate()
    {
        lint_pending_text(
            report,
            &format!("submission_scope.authorities[{idx}]"),
            authority,
        );
    }
    if bundle
        .payload
        .standards_target
        .bulletins_included
        .is_empty()
    {
        push_finding(
            report,
            BundleLintSeverity::Error,
            "standards_target.bulletins_included",
            "No standards bulletin reconciliation is present",
            "Certification scope changes must be tied to explicit standards and bulletin data.",
            "Add the public or licensed standards-watch identifier that applies to the target submission.",
        );
    }
    if !bundle
        .payload
        .runtime_policy
        .trace_masking_policy
        .to_ascii_lowercase()
        .contains("mask")
    {
        push_finding(
            report,
            BundleLintSeverity::Error,
            "runtime_policy.trace_masking_policy",
            "Trace masking policy does not declare masking",
            "APDU and report artifacts can leak PAN, track-equivalent, cryptogram, or PIN-adjacent data without a masking policy.",
            "Use a masking policy that explicitly covers PAN, track-equivalent data, cryptograms, PIN material, and sensitive TLVs.",
        );
    }
    if bundle.payload.artifact_hashes.len() < 2 {
        push_finding(
            report,
            BundleLintSeverity::Warning,
            "artifact_hashes",
            "Few artifact bindings are present",
            "A certification bundle should bind profiles, CAPKs, vectors, reports, traces, and external evidence to stable hashes.",
            "Add hash bindings for every certification artifact before freezing the submission.",
        );
    }
    match certification_vector_bundle_status(&bundle.payload.vector_bundle_json) {
        "covered" => {}
        "external_required" => push_finding(
            report,
            BundleLintSeverity::Warning,
            "payload.vector_bundle_json",
            "Certification vector bundle is still fixture or empty data",
            "The bundle can be linted for pre-lab flow, but fixture, pending, structural, or empty vector data cannot close ODA certification coverage.",
            "Replace the vector bundle with authority/lab supplied CERTIFICATION data containing non-empty SDA, DDA, and CDA cases before final submission.",
        ),
        _ => push_finding(
            report,
            BundleLintSeverity::Error,
            "payload.vector_bundle_json",
            "Vector bundle is malformed or incomplete",
            "ODA coverage cannot be assessed because the vector bundle does not have a supported schema shape.",
            "Provide a JSON object with vector_class and non-empty cases or test_vectors arrays.",
        ),
    }
}

fn lint_pending_text(report: &mut BundleCompileReport, field_path: &str, value: &str) {
    let lower = value.to_ascii_lowercase();
    if lower.contains("pending") || lower.contains("external-") || lower.contains("required") {
        push_finding(
            report,
            BundleLintSeverity::Warning,
            field_path,
            "External evidence placeholder remains",
            "The bundle can compile for pre-lab use, but this field must be replaced or backed by accepted authority evidence for certification closure.",
            "Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.",
        );
    }
}

fn lint_trust_anchors(
    report: &mut BundleCompileReport,
    anchors: &[BundleTrustAnchor],
    policy: &BundleLoadPolicy,
) {
    if anchors.is_empty() {
        push_finding(
            report,
            BundleLintSeverity::Error,
            "trust_anchors",
            "No trust anchors are provisioned",
            "Certification and production bundles cannot be authenticated without authority metadata.",
            "Provision a signer trust anchor in a protected store and bind it to the accepted payload hash.",
        );
    }
    for (idx, anchor) in anchors.iter().enumerate() {
        if anchor.verification_public_key_hex == default_fixture_public_key_hex().as_str() {
            push_finding(
                report,
                BundleLintSeverity::Warning,
                &format!("trust_anchors[{idx}].verification_public_key_hex"),
                "Fixture verification key is still present",
                "The checked-in fixture public key identifies a deterministic local signing key and must not be used for production or final certification submissions.",
                "Generate and custody a submission-specific signing key outside the repository fixture and provision only its public verification key here.",
            );
        }
        if anchor
            .not_after
            .is_some_and(|not_after| not_after < policy.evaluation_date)
        {
            push_finding(
                report,
                BundleLintSeverity::Error,
                &format!("trust_anchors[{idx}].not_after"),
                "Trust anchor has expired for the evaluation date",
                "The runtime will reject bundles signed by expired anchors.",
                "Rotate the trust anchor or evaluate against the correct lab date.",
            );
        }
    }
}

fn emv_capability_coverage(loaded: &LoadedCertificationBundle) -> Vec<EmvCapabilityCoverage> {
    let bundle = &loaded.bundle;
    let profile = &loaded.profile_set;
    let has_contact_scope = has_value(&bundle.payload.submission_scope.interfaces, "contact");
    let has_contactless_scope =
        has_value(&bundle.payload.submission_scope.interfaces, "contactless");
    let has_contact_aid = profile_aids_with_interface(profile, "contact") > 0;
    let has_contactless_aid = profile_aids_with_interface(profile, "contactless") > 0;
    let has_contact_kernel = profile
        .schemes
        .iter()
        .any(|scheme| scheme.contact_kernel_type.is_some());
    let has_contactless_kernel = bundle
        .payload
        .kernel_registry
        .iter()
        .any(|entry| entry.interface == "contactless");
    let has_capk = profile
        .schemes
        .iter()
        .any(|scheme| !scheme.capks.is_empty());
    let has_cda = profile
        .schemes
        .iter()
        .flat_map(|scheme| scheme.aids.iter())
        .any(|aid| aid.cda_allowed_by_profile());
    let has_trm = profile
        .schemes
        .iter()
        .flat_map(|scheme| scheme.aids.iter())
        .any(|aid| {
            aid.floor_limit > 0
                || aid.random_selection_percent > 0
                || aid.lower_consecutive_offline_limit.is_some()
                || aid.upper_consecutive_offline_limit.is_some()
                || !aid.transaction_type_floor_limits.is_empty()
        });
    let has_cvm = !bundle.payload.cvm_extensions.is_empty()
        || profile
            .schemes
            .iter()
            .flat_map(|scheme| scheme.aids.iter())
            .any(|aid| {
                aid.cvm_limit_contact > 0 || aid.contactless_cvm_limit > 0 || aid.cdcvm_supported
            });
    let has_issuer_scripts = profile
        .schemes
        .iter()
        .flat_map(|scheme| scheme.aids.iter())
        .any(|aid| !aid.critical_issuer_script_ins.is_empty());
    let has_relay_resistance = profile
        .schemes
        .iter()
        .flat_map(|scheme| scheme.aids.iter())
        .any(|aid| aid.relay_resistance.is_some());
    let has_vector_binding = bundle
        .payload
        .artifact_hashes
        .iter()
        .any(|artifact| artifact.artifact_id == "vector_bundle_json");
    let vector_bundle_status =
        certification_vector_bundle_status(&bundle.payload.vector_bundle_json);
    let has_profile_binding = bundle
        .payload
        .artifact_hashes
        .iter()
        .any(|artifact| artifact.artifact_id == "scheme_profile_set_json");
    let has_l1_ref =
        external_reference_status(&bundle.payload.terminal_profile.l1_approval_reference);
    let has_pci_ref = external_reference_status(&bundle.payload.terminal_profile.pci_pts_reference);

    vec![
        coverage_item("selection", "Application selection", "Selects PSE/PPSE, matches configured AIDs, and keeps scheme choice data-driven.", "payload.scheme_profile_set_json.schemes[].aids", profile.schemes.iter().any(|scheme| !scheme.aids.is_empty()), "Add at least one scheme profile with AID entries for each claimed interface."),
        coverage_item("contact_l2", "Contact EMV L2", "Binds contact interface, contact kernel type, TAC/IAC, DOL, CVM, TRM, and scripts to profile data.", "payload.submission_scope.interfaces + scheme_profile_set_json", has_contact_scope && has_contact_aid && has_contact_kernel, "Add contact to the claimed interfaces and include contact AID/profile material with contact_kernel_type."),
        coverage_item("contactless_c8", "Contactless Kernel C-8", "Binds contactless scope to C-8 package data, TTQ/CVM limits, relay resistance, and masked traces.", "payload.kernel_registry + scheme_profile_set_json", has_contactless_scope && has_contactless_aid && has_contactless_kernel, "Add a contactless kernel registry entry and contactless AID profile data for every claimed scheme."),
        coverage_item("capk_authority", "CAPK authority data", "Supplies RID/index public keys, expiry, checksums, and provenance for ODA validation.", "payload.scheme_profile_set_json.schemes[].capks", has_capk, "Attach accepted CAPK material with checksums and authority provenance."),
        coverage_status_item("oda_vectors", "SDA/DDA/CDA and ODA vectors", "Binds cryptographic vector evidence and CDA request behavior to bundle hashes.", "payload.vector_bundle_json + payload.artifact_hashes", if has_cda && has_vector_binding { vector_bundle_status } else { "incomplete" }, "Attach lab or scheme ODA vectors with non-empty SDA, DDA, and CDA cases and bind their hash in artifact_hashes."),
        coverage_item("cvm_pin", "CVM and PIN integration", "Controls CVM limits, CDCVM support, extension codes, and PED-owned offline PIN behavior.", "payload.cvm_extensions + scheme_profile_set_json.aids", has_cvm, "Add CVM limits, certified CVM code handling, and PED integration evidence."),
        coverage_item("trm", "Terminal risk management", "Drives floor limits, random selection, transaction type limits, and offline counters from profile data.", "payload.scheme_profile_set_json.aids[].trm", has_trm, "Add floor limits, random selection settings, and offline counter bounds for the target schemes."),
        coverage_item("taa", "Terminal action analysis", "Keeps TAC/IAC policy in signed profile data rather than compiled constants.", "payload.scheme_profile_set_json.schemes[].taa", !profile.schemes.is_empty(), "Attach scheme-approved TAC/IAC profile material."),
        coverage_item("issuer_scripts", "Issuer script handling", "Defines which issuer script INS values are critical for post-authorization handling.", "payload.scheme_profile_set_json.aids[].critical_issuer_script_ins", has_issuer_scripts, "Add critical issuer script INS policy for each scheme profile that requires it."),
        coverage_status_item("relay_resistance", "Relay resistance", "Controls contactless relay resistance behavior where required by scheme/profile.", "payload.scheme_profile_set_json.aids[].relay_resistance", if has_relay_resistance { "covered" } else { "warning" }, "Add relay resistance parameters for contactless profiles that claim it."),
        coverage_item("runtime_abi", "Runtime ABI and timeouts", "Sets APDU, host authorization, PIN entry, and contactless UI callback bounds from bundle data.", "payload.runtime_policy.callback_timeouts", true, "Keep timeout values within 1..60000 ms and document device-specific rationale."),
        coverage_item("security_trust", "Signature, trust, and anti-rollback", "Authenticates bundle payloads, enforces rollback counters, and records verification status.", "signature + trust_anchors + rollback_counter", loaded.verification_status == "trust-anchor-verified", "Use authority-managed trust anchors and keep rollback counters monotonic."),
        coverage_status_item("device_l1", "Device and L1 evidence", "Binds target device, firmware, interface, and L1 approval references to the bundle.", "payload.terminal_profile", has_l1_ref, "Replace pre-lab placeholders with accepted L1/device references."),
        coverage_status_item("pci_ped", "PCI/PED evidence", "Records PED/PIN custody evidence for CVM and offline PIN integration.", "payload.terminal_profile.pci_pts_reference", has_pci_ref, "Replace pre-lab placeholders with PCI PTS or assessor evidence references."),
        coverage_item("standards_bulletins", "Standards and bulletins", "Captures contact/contactless target versions and bulletin inclusions/exclusions as data.", "payload.standards_target", !bundle.payload.standards_target.bulletins_included.is_empty(), "Add accepted standards and bulletin reconciliation data."),
        coverage_item("evidence_freeze", "Evidence freeze and reports", "Binds test plan, artifact hashes, fingerprints, and report pack outputs for reproducible submissions.", "payload.test_plan + payload.artifact_hashes", !bundle.payload.test_plan.is_empty() && has_profile_binding && has_vector_binding, "Bind every external report, trace pack, vector set, profile, and submitted binary by hash."),
        coverage_item("trace_privacy", "Trace privacy", "Requires masked APDU traces and prevents sensitive data from becoming report content.", "payload.runtime_policy.trace_masking_policy", bundle.payload.runtime_policy.trace_masking_policy.to_ascii_lowercase().contains("mask"), "Use the repository masking policy and audit trace packs before submission."),
    ]
}

fn certification_vector_bundle_status(vector_json: &str) -> &'static str {
    let Ok(root) = JsonParser::new(vector_json.as_bytes()).parse() else {
        return "incomplete";
    };
    let Ok(object) = root.as_object() else {
        return "incomplete";
    };
    let Ok(vector_class) = required_string(object, "vector_class") else {
        return "incomplete";
    };
    let lower = vector_json.to_ascii_lowercase();
    if vector_class != "CERTIFICATION"
        || lower.contains("fixture")
        || lower.contains("pending")
        || lower.contains("placeholder")
    {
        return "external_required";
    }
    let case_count = object
        .get("cases")
        .and_then(|value| value.as_array().ok())
        .map_or(0, |items| items.len());
    let test_vector_count = object
        .get("test_vectors")
        .and_then(|value| value.as_array().ok())
        .map_or(0, |items| items.len());
    if case_count == 0 && test_vector_count == 0 {
        return "external_required";
    }
    let sda = lower.contains("sda");
    let dda = lower.contains("dda");
    let cda = lower.contains("cda");
    if sda && dda && cda {
        "covered"
    } else {
        "external_required"
    }
}

fn payload_capability_coverage(bundle: &CertificationBundle) -> Vec<EmvCapabilityCoverage> {
    let has_contact_scope = has_value(&bundle.payload.submission_scope.interfaces, "contact");
    let has_contactless_scope =
        has_value(&bundle.payload.submission_scope.interfaces, "contactless");
    let has_contactless_kernel = bundle
        .payload
        .kernel_registry
        .iter()
        .any(|entry| entry.interface == "contactless");
    vec![
        coverage_item(
            "selection",
            "Application selection",
            "Selects PSE/PPSE, matches configured AIDs, and keeps scheme choice data-driven.",
            "payload.scheme_profile_set_json",
            true,
            "Compile the embedded scheme profile set to verify concrete AID coverage.",
        ),
        coverage_item(
            "contact_l2",
            "Contact EMV L2",
            "Binds contact interface to profile material.",
            "payload.submission_scope.interfaces",
            has_contact_scope,
            "Add contact interface data and compile the embedded profile set.",
        ),
        coverage_item(
            "contactless_c8",
            "Contactless Kernel C-8",
            "Binds contactless scope to C-8 package data.",
            "payload.kernel_registry",
            has_contactless_scope && has_contactless_kernel,
            "Add contactless scope and a contactless kernel registry entry.",
        ),
        coverage_item(
            "security_trust",
            "Signature, trust, and anti-rollback",
            "Authenticates bundle payloads and enforces rollback counters.",
            "signature + trust_anchors",
            false,
            "Fix compile/authentication errors before treating this bundle as usable.",
        ),
    ]
}

fn coverage_item(
    id: &'static str,
    area: &'static str,
    role: &'static str,
    bundle_source: &'static str,
    covered: bool,
    suggestion: &'static str,
) -> EmvCapabilityCoverage {
    EmvCapabilityCoverage {
        id,
        area,
        role,
        bundle_source,
        status: if covered { "covered" } else { "incomplete" },
        suggestion,
    }
}

fn coverage_status_item(
    id: &'static str,
    area: &'static str,
    role: &'static str,
    bundle_source: &'static str,
    status: &'static str,
    suggestion: &'static str,
) -> EmvCapabilityCoverage {
    EmvCapabilityCoverage {
        id,
        area,
        role,
        bundle_source,
        status,
        suggestion,
    }
}

fn external_reference_status(value: &str) -> &'static str {
    let lower = value.to_ascii_lowercase();
    if lower.contains("pending") || lower.contains("required") || lower.contains("external-") {
        "external_required"
    } else {
        "covered"
    }
}

fn profile_aids_with_interface(profile: &ProfileSet, interface: &str) -> usize {
    profile
        .schemes
        .iter()
        .flat_map(|scheme| scheme.aids.iter())
        .filter(|aid| aid.interfaces.iter().any(|item| item == interface))
        .count()
}

fn has_value(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

fn finalize_compile_status(report: &mut BundleCompileReport) {
    report.status = if report
        .findings
        .iter()
        .any(|finding| finding.severity == BundleLintSeverity::Error)
        || report
            .coverage
            .iter()
            .any(|item| item.status == "incomplete")
    {
        "fail"
    } else if report
        .findings
        .iter()
        .any(|finding| finding.severity == BundleLintSeverity::Warning)
        || report
            .coverage
            .iter()
            .any(|item| item.status == "external_required")
    {
        "warn"
    } else {
        "pass"
    };
}

fn build_mode_as_str(mode: BuildMode) -> &'static str {
    match mode {
        BuildMode::Test => "test",
        BuildMode::Certification => "certification",
        BuildMode::Production => "production",
    }
}

fn push_lint_finding_json(out: &mut String, finding: &BundleLintFinding) {
    out.push('{');
    push_json_str(out, "severity", finding.severity.as_str());
    out.push(',');
    push_json_str(out, "field_path", &finding.field_path);
    out.push(',');
    push_json_str(out, "title", &finding.title);
    out.push(',');
    push_json_str(out, "impact", &finding.impact);
    out.push(',');
    push_json_str(out, "suggestion", &finding.suggestion);
    out.push('}');
}

fn push_capability_coverage_json(out: &mut String, coverage: &EmvCapabilityCoverage) {
    out.push('{');
    push_json_str(out, "id", coverage.id);
    out.push(',');
    push_json_str(out, "area", coverage.area);
    out.push(',');
    push_json_str(out, "role", coverage.role);
    out.push(',');
    push_json_str(out, "bundle_source", coverage.bundle_source);
    out.push(',');
    push_json_str(out, "status", coverage.status);
    out.push(',');
    push_json_str(out, "suggestion", coverage.suggestion);
    out.push('}');
}

fn parse_payload(value: &JsonValue) -> KernelResult<CertificationBundlePayload> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "submission_scope",
            "standards_target",
            "terminal_profile",
            "runtime_policy",
            "kernel_registry",
            "cvm_extensions",
            "test_plan",
            "artifact_hashes",
            "scheme_profile_set_json",
            "vector_bundle_json",
        ],
    )?;
    let payload = CertificationBundlePayload {
        submission_scope: parse_submission_scope(required_object(object, "submission_scope")?)?,
        standards_target: parse_standards_target(required_object(object, "standards_target")?)?,
        terminal_profile: parse_terminal_profile(required_object(object, "terminal_profile")?)?,
        runtime_policy: parse_runtime_policy(required_object(object, "runtime_policy")?)?,
        kernel_registry: parse_array(object, "kernel_registry", parse_kernel_registration)?,
        cvm_extensions: parse_array(object, "cvm_extensions", parse_cvm_extension)?,
        test_plan: parse_array(object, "test_plan", parse_test_case)?,
        artifact_hashes: parse_array(object, "artifact_hashes", parse_artifact_hash)?,
        scheme_profile_set_json: required_string(object, "scheme_profile_set_json")?.to_string(),
        vector_bundle_json: required_string(object, "vector_bundle_json")?.to_string(),
    };
    validate_payload(&payload)?;
    Ok(payload)
}

fn validate_payload(payload: &CertificationBundlePayload) -> KernelResult<()> {
    validate_non_empty_set(&payload.submission_scope.interfaces)?;
    validate_non_empty_set(&payload.submission_scope.authorities)?;
    validate_non_empty_set(&payload.terminal_profile.supported_interfaces)?;
    validate_non_empty_set(&payload.standards_target.bulletins_included)?;
    bounded_len(payload.kernel_registry.len())?;
    bounded_len(payload.cvm_extensions.len())?;
    bounded_len(payload.test_plan.len())?;
    bounded_len(payload.artifact_hashes.len())?;
    if payload.kernel_registry.is_empty()
        || payload.test_plan.is_empty()
        || payload.artifact_hashes.is_empty()
    {
        return Err(KernelError::InvalidProfile);
    }
    if payload.scheme_profile_set_json.len() > MAX_EMBEDDED_PROFILE_BYTES
        || payload.vector_bundle_json.len() > MAX_EMBEDDED_PROFILE_BYTES
    {
        return Err(KernelError::LengthOverflow);
    }
    JsonParser::new(payload.scheme_profile_set_json.as_bytes()).parse()?;
    JsonParser::new(payload.vector_bundle_json.as_bytes()).parse()?;
    validate_callback_timeouts(payload.runtime_policy.callback_timeouts)?;
    let has_contactless = payload
        .submission_scope
        .interfaces
        .iter()
        .any(|item| item == "contactless");
    if has_contactless
        && !payload
            .kernel_registry
            .iter()
            .any(|entry| entry.interface == "contactless")
    {
        return Err(KernelError::InvalidProfile);
    }
    for entry in &payload.kernel_registry {
        validate_identifier(&entry.kernel_profile_id)?;
        validate_known_interface(&entry.interface)?;
        reject_blank(&entry.algorithm)?;
        reject_blank(&entry.c8_package)?;
        validate_non_empty_set(&entry.scheme_scope)?;
    }
    for artifact in &payload.artifact_hashes {
        validate_identifier(&artifact.artifact_id)?;
        validate_hex_len(&artifact.sha256_hex, 32)?;
        validate_non_empty_set(&artifact.binds_open_issues)?;
    }
    Ok(())
}

fn verify_bundle_signature(
    bundle: &CertificationBundle,
    payload_sha256: &[u8; 32],
    policy: &BundleLoadPolicy,
) -> KernelResult<&'static str> {
    if bundle.signature.algorithm == CERTIFICATION_BUNDLE_TEST_ALGORITHM
        && bundle.bundle_class == BundleClass::Testing
        && policy.mode == BuildMode::Test
    {
        validate_hex_len(&bundle.signature.signature_hex, 32)?;
        return Ok("testing-self-attested");
    }
    if bundle.signature.algorithm != CERTIFICATION_BUNDLE_SIGNATURE_ALGORITHM {
        return Err(KernelError::InvalidProfile);
    }
    let anchor = policy
        .trust_anchors
        .iter()
        .find(|anchor| {
            anchor.signer_id == bundle.signature.signer_id
                && anchor.signing_key_fingerprint == bundle.signature.signing_key_fingerprint
        })
        .ok_or(KernelError::InvalidProfile)?;
    if anchor
        .not_after
        .is_some_and(|not_after| not_after < policy.evaluation_date)
    {
        return Err(KernelError::InvalidProfile);
    }
    if anchor.allowed_payload_sha256 != to_hex(payload_sha256) {
        return Err(KernelError::InvalidProfile);
    }
    let verification_key = verifying_key_from_hex(&anchor.verification_public_key_hex)?;
    let public_key_bytes = verification_key.to_bytes();
    if to_hex(&sha256(&public_key_bytes)) != bundle.signature.signing_key_fingerprint {
        return Err(KernelError::InvalidProfile);
    }
    let signature = signature_from_hex(&bundle.signature.signature_hex)?;
    let message = bundle_signature_message(
        &bundle.signature.signer_id,
        &bundle.signature.signing_key_fingerprint,
        payload_sha256,
    );
    verification_key
        .verify(&message, &signature)
        .map_err(|_| KernelError::InvalidProfile)?;
    Ok("trust-anchor-verified")
}

fn validate_bundle_for_policy(
    bundle: &CertificationBundle,
    policy: &BundleLoadPolicy,
) -> KernelResult<()> {
    if bundle.created > policy.evaluation_date {
        return Err(KernelError::InvalidProfile);
    }
    if bundle.rollback_counter <= policy.installed_rollback_counter {
        return Err(KernelError::InvalidProfile);
    }
    match policy.mode {
        BuildMode::Test => Ok(()),
        BuildMode::Certification | BuildMode::Production => {
            if bundle.bundle_class != BundleClass::Certification {
                return Err(KernelError::InvalidProfile);
            }
            if policy.trust_anchors.is_empty() {
                return Err(KernelError::InvalidProfile);
            }
            Ok(())
        }
    }
}

fn parse_submission_scope(object: &BTreeMap<String, JsonValue>) -> KernelResult<SubmissionScope> {
    reject_unknown_fields(
        object,
        &[
            "product_name",
            "product_version",
            "certification_target",
            "interfaces",
            "authorities",
        ],
    )?;
    Ok(SubmissionScope {
        product_name: required_clean_string(object, "product_name")?.to_string(),
        product_version: required_clean_string(object, "product_version")?.to_string(),
        certification_target: required_clean_string(object, "certification_target")?.to_string(),
        interfaces: required_string_array(object, "interfaces")?,
        authorities: required_string_array(object, "authorities")?,
    })
}

fn parse_standards_target(object: &BTreeMap<String, JsonValue>) -> KernelResult<StandardsTarget> {
    reject_unknown_fields(
        object,
        &[
            "emv_contact_version",
            "emv_contactless_kernel",
            "bulletins_included",
            "bulletins_excluded",
        ],
    )?;
    Ok(StandardsTarget {
        emv_contact_version: required_clean_string(object, "emv_contact_version")?.to_string(),
        emv_contactless_kernel: required_clean_string(object, "emv_contactless_kernel")?
            .to_string(),
        bulletins_included: required_string_array(object, "bulletins_included")?,
        bulletins_excluded: required_string_array_allow_empty(object, "bulletins_excluded")?,
    })
}

fn parse_terminal_profile(object: &BTreeMap<String, JsonValue>) -> KernelResult<TerminalProfile> {
    reject_unknown_fields(
        object,
        &[
            "terminal_type",
            "device_model",
            "firmware_version",
            "l1_approval_reference",
            "pci_pts_reference",
            "supported_interfaces",
        ],
    )?;
    Ok(TerminalProfile {
        terminal_type: required_clean_string(object, "terminal_type")?.to_string(),
        device_model: required_clean_string(object, "device_model")?.to_string(),
        firmware_version: required_clean_string(object, "firmware_version")?.to_string(),
        l1_approval_reference: required_clean_string(object, "l1_approval_reference")?.to_string(),
        pci_pts_reference: required_clean_string(object, "pci_pts_reference")?.to_string(),
        supported_interfaces: required_string_array(object, "supported_interfaces")?,
    })
}

fn parse_runtime_policy(object: &BTreeMap<String, JsonValue>) -> KernelResult<RuntimePolicy> {
    reject_unknown_fields(
        object,
        &[
            "callback_timeouts",
            "offline_counter_persistence",
            "trace_masking_policy",
        ],
    )?;
    Ok(RuntimePolicy {
        callback_timeouts: parse_callback_timeouts(required_object(object, "callback_timeouts")?)?,
        offline_counter_persistence: required_clean_string(object, "offline_counter_persistence")?
            .to_string(),
        trace_masking_policy: required_clean_string(object, "trace_masking_policy")?.to_string(),
    })
}

fn parse_callback_timeouts(
    object: &BTreeMap<String, JsonValue>,
) -> KernelResult<CallbackTimeoutProfile> {
    reject_unknown_fields(
        object,
        &[
            "apdu_transport_timeout_ms",
            "host_authorization_timeout_ms",
            "pin_entry_timeout_ms",
            "contactless_ui_timeout_ms",
        ],
    )?;
    let timeouts = CallbackTimeoutProfile {
        apdu_transport_timeout_ms: required_timeout(object, "apdu_transport_timeout_ms")?,
        host_authorization_timeout_ms: required_timeout(object, "host_authorization_timeout_ms")?,
        pin_entry_timeout_ms: required_timeout(object, "pin_entry_timeout_ms")?,
        contactless_ui_timeout_ms: required_timeout(object, "contactless_ui_timeout_ms")?,
    };
    validate_callback_timeouts(timeouts)?;
    Ok(timeouts)
}

fn parse_kernel_registration(value: &JsonValue) -> KernelResult<KernelProfileRegistration> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "kernel_profile_id",
            "interface",
            "algorithm",
            "c8_package",
            "scheme_scope",
        ],
    )?;
    Ok(KernelProfileRegistration {
        kernel_profile_id: required_clean_string(object, "kernel_profile_id")?.to_string(),
        interface: required_clean_string(object, "interface")?.to_string(),
        algorithm: required_clean_string(object, "algorithm")?.to_string(),
        c8_package: required_clean_string(object, "c8_package")?.to_string(),
        scheme_scope: required_string_array(object, "scheme_scope")?,
    })
}

fn parse_cvm_extension(value: &JsonValue) -> KernelResult<CvmExtensionRule> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "rule_id",
            "scheme_scope",
            "cvm_code_hex",
            "meaning",
            "tvr_on_failure_hex",
            "continue_on_failure",
        ],
    )?;
    let cvm_code_hex = required_clean_string(object, "cvm_code_hex")?.to_string();
    validate_hex_len(&cvm_code_hex, 1)?;
    let tvr = required_clean_string(object, "tvr_on_failure_hex")?.to_string();
    validate_hex_len(&tvr, 5)?;
    Ok(CvmExtensionRule {
        rule_id: required_clean_string(object, "rule_id")?.to_string(),
        scheme_scope: required_string_array(object, "scheme_scope")?,
        cvm_code_hex,
        meaning: required_clean_string(object, "meaning")?.to_string(),
        tvr_on_failure_hex: tvr,
        continue_on_failure: required_bool(object, "continue_on_failure")?,
    })
}

fn parse_test_case(value: &JsonValue) -> KernelResult<CertificationTestCase> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "case_id",
            "vector_class",
            "expected_outcome",
            "trace_requirement",
        ],
    )?;
    let case_id = required_clean_string(object, "case_id")?.to_string();
    validate_identifier(&case_id)?;
    Ok(CertificationTestCase {
        case_id,
        vector_class: required_clean_string(object, "vector_class")?.to_string(),
        expected_outcome: required_clean_string(object, "expected_outcome")?.to_string(),
        trace_requirement: required_clean_string(object, "trace_requirement")?.to_string(),
    })
}

fn parse_artifact_hash(value: &JsonValue) -> KernelResult<ArtifactHashBinding> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "artifact_id",
            "artifact_kind",
            "sha256_hex",
            "binds_open_issues",
        ],
    )?;
    let sha = required_clean_string(object, "sha256_hex")?.to_string();
    validate_hex_len(&sha, 32)?;
    Ok(ArtifactHashBinding {
        artifact_id: required_clean_string(object, "artifact_id")?.to_string(),
        artifact_kind: required_clean_string(object, "artifact_kind")?.to_string(),
        sha256_hex: sha,
        binds_open_issues: required_string_array(object, "binds_open_issues")?,
    })
}

fn parse_signature(value: &JsonValue) -> KernelResult<BundleSignature> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "algorithm",
            "signer_id",
            "signing_key_fingerprint",
            "payload_sha256",
            "signature_hex",
            "signature_artifact_sha256",
        ],
    )?;
    let payload_sha256 = required_clean_string(object, "payload_sha256")?.to_string();
    validate_hex_len(&payload_sha256, 32)?;
    let algorithm = required_clean_string(object, "algorithm")?.to_string();
    let signature_hex = required_clean_string(object, "signature_hex")?.to_string();
    let signature_len = if algorithm == CERTIFICATION_BUNDLE_SIGNATURE_ALGORITHM {
        64
    } else {
        32
    };
    validate_hex_len(&signature_hex, signature_len)?;
    let artifact_sha = required_clean_string(object, "signature_artifact_sha256")?.to_string();
    validate_hex_len(&artifact_sha, 32)?;
    Ok(BundleSignature {
        algorithm,
        signer_id: required_clean_string(object, "signer_id")?.to_string(),
        signing_key_fingerprint: required_clean_string(object, "signing_key_fingerprint")?
            .to_string(),
        payload_sha256,
        signature_hex,
        signature_artifact_sha256: artifact_sha,
    })
}

fn parse_trust_anchor(value: &JsonValue) -> KernelResult<BundleTrustAnchor> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "signer_id",
            "signing_key_fingerprint",
            "verification_public_key_hex",
            "allowed_payload_sha256",
            "not_after",
        ],
    )?;
    let public_key = required_clean_string(object, "verification_public_key_hex")?.to_string();
    validate_hex_len(&public_key, 32)?;
    let allowed = required_clean_string(object, "allowed_payload_sha256")?.to_string();
    validate_hex_len(&allowed, 32)?;
    Ok(BundleTrustAnchor {
        signer_id: required_clean_string(object, "signer_id")?.to_string(),
        signing_key_fingerprint: required_clean_string(object, "signing_key_fingerprint")?
            .to_string(),
        verification_public_key_hex: public_key,
        allowed_payload_sha256: allowed,
        not_after: object
            .get("not_after")
            .map(|value| parse_iso_date(value.as_string()?))
            .transpose()?,
    })
}

fn payload_canonical_json(payload: &CertificationBundlePayload) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"submission_scope\":");
    push_submission_scope_json(&mut out, &payload.submission_scope);
    out.push_str(",\"standards_target\":");
    push_standards_target_json(&mut out, &payload.standards_target);
    out.push_str(",\"terminal_profile\":");
    push_terminal_profile_json(&mut out, &payload.terminal_profile);
    out.push_str(",\"runtime_policy\":");
    push_runtime_policy_json(&mut out, &payload.runtime_policy);
    out.push_str(",\"kernel_registry\":[");
    for (idx, item) in payload.kernel_registry.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_kernel_registration_json(&mut out, item);
    }
    out.push_str("],\"cvm_extensions\":[");
    for (idx, item) in payload.cvm_extensions.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_cvm_extension_json(&mut out, item);
    }
    out.push_str("],\"test_plan\":[");
    for (idx, item) in payload.test_plan.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_test_case_json(&mut out, item);
    }
    out.push_str("],\"artifact_hashes\":[");
    for (idx, item) in payload.artifact_hashes.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_artifact_hash_json(&mut out, item);
    }
    out.push_str("],");
    push_json_str(
        &mut out,
        "scheme_profile_set_json",
        &payload.scheme_profile_set_json,
    );
    out.push(',');
    push_json_str(&mut out, "vector_bundle_json", &payload.vector_bundle_json);
    out.push('}');
    out
}

fn push_submission_scope_json(out: &mut String, value: &SubmissionScope) {
    out.push('{');
    push_json_str(out, "product_name", &value.product_name);
    out.push(',');
    push_json_str(out, "product_version", &value.product_version);
    out.push(',');
    push_json_str(out, "certification_target", &value.certification_target);
    out.push(',');
    push_json_array(out, "interfaces", &value.interfaces);
    out.push(',');
    push_json_array(out, "authorities", &value.authorities);
    out.push('}');
}

fn push_standards_target_json(out: &mut String, value: &StandardsTarget) {
    out.push('{');
    push_json_str(out, "emv_contact_version", &value.emv_contact_version);
    out.push(',');
    push_json_str(out, "emv_contactless_kernel", &value.emv_contactless_kernel);
    out.push(',');
    push_json_array(out, "bulletins_included", &value.bulletins_included);
    out.push(',');
    push_json_array(out, "bulletins_excluded", &value.bulletins_excluded);
    out.push('}');
}

fn push_terminal_profile_json(out: &mut String, value: &TerminalProfile) {
    out.push('{');
    push_json_str(out, "terminal_type", &value.terminal_type);
    out.push(',');
    push_json_str(out, "device_model", &value.device_model);
    out.push(',');
    push_json_str(out, "firmware_version", &value.firmware_version);
    out.push(',');
    push_json_str(out, "l1_approval_reference", &value.l1_approval_reference);
    out.push(',');
    push_json_str(out, "pci_pts_reference", &value.pci_pts_reference);
    out.push(',');
    push_json_array(out, "supported_interfaces", &value.supported_interfaces);
    out.push('}');
}

fn push_runtime_policy_json(out: &mut String, value: &RuntimePolicy) {
    out.push('{');
    out.push_str("\"callback_timeouts\":{");
    push_json_number(
        out,
        "apdu_transport_timeout_ms",
        value.callback_timeouts.apdu_transport_timeout_ms as u64,
    );
    out.push(',');
    push_json_number(
        out,
        "host_authorization_timeout_ms",
        value.callback_timeouts.host_authorization_timeout_ms as u64,
    );
    out.push(',');
    push_json_number(
        out,
        "pin_entry_timeout_ms",
        value.callback_timeouts.pin_entry_timeout_ms as u64,
    );
    out.push(',');
    push_json_number(
        out,
        "contactless_ui_timeout_ms",
        value.callback_timeouts.contactless_ui_timeout_ms as u64,
    );
    out.push_str("},");
    push_json_str(
        out,
        "offline_counter_persistence",
        &value.offline_counter_persistence,
    );
    out.push(',');
    push_json_str(out, "trace_masking_policy", &value.trace_masking_policy);
    out.push('}');
}

fn push_kernel_registration_json(out: &mut String, value: &KernelProfileRegistration) {
    out.push('{');
    push_json_str(out, "kernel_profile_id", &value.kernel_profile_id);
    out.push(',');
    push_json_str(out, "interface", &value.interface);
    out.push(',');
    push_json_str(out, "algorithm", &value.algorithm);
    out.push(',');
    push_json_str(out, "c8_package", &value.c8_package);
    out.push(',');
    push_json_array(out, "scheme_scope", &value.scheme_scope);
    out.push('}');
}

fn push_cvm_extension_json(out: &mut String, value: &CvmExtensionRule) {
    out.push('{');
    push_json_str(out, "rule_id", &value.rule_id);
    out.push(',');
    push_json_array(out, "scheme_scope", &value.scheme_scope);
    out.push(',');
    push_json_str(out, "cvm_code_hex", &value.cvm_code_hex);
    out.push(',');
    push_json_str(out, "meaning", &value.meaning);
    out.push(',');
    push_json_str(out, "tvr_on_failure_hex", &value.tvr_on_failure_hex);
    out.push(',');
    push_json_bool(out, "continue_on_failure", value.continue_on_failure);
    out.push('}');
}

fn push_test_case_json(out: &mut String, value: &CertificationTestCase) {
    out.push('{');
    push_json_str(out, "case_id", &value.case_id);
    out.push(',');
    push_json_str(out, "vector_class", &value.vector_class);
    out.push(',');
    push_json_str(out, "expected_outcome", &value.expected_outcome);
    out.push(',');
    push_json_str(out, "trace_requirement", &value.trace_requirement);
    out.push('}');
}

fn push_artifact_hash_json(out: &mut String, value: &ArtifactHashBinding) {
    out.push('{');
    push_json_str(out, "artifact_id", &value.artifact_id);
    out.push(',');
    push_json_str(out, "artifact_kind", &value.artifact_kind);
    out.push(',');
    push_json_str(out, "sha256_hex", &value.sha256_hex);
    out.push(',');
    push_json_array(out, "binds_open_issues", &value.binds_open_issues);
    out.push('}');
}

fn push_signature_json(out: &mut String, signature: &BundleSignature) {
    out.push('{');
    push_json_str(out, "algorithm", &signature.algorithm);
    out.push(',');
    push_json_str(out, "signer_id", &signature.signer_id);
    out.push(',');
    push_json_str(
        out,
        "signing_key_fingerprint",
        &signature.signing_key_fingerprint,
    );
    out.push(',');
    push_json_str(out, "payload_sha256", &signature.payload_sha256);
    out.push(',');
    push_json_str(out, "signature_hex", &signature.signature_hex);
    out.push(',');
    push_json_str(
        out,
        "signature_artifact_sha256",
        &signature.signature_artifact_sha256,
    );
    out.push('}');
}

fn signing_key_from_hex(secret_hex: &str) -> KernelResult<SigningKey> {
    let secret = decode_hex(secret_hex)?;
    let bytes: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| KernelError::InvalidProfile)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_hex(public_key_hex: &str) -> KernelResult<VerifyingKey> {
    let public_key = decode_hex(public_key_hex)?;
    let bytes: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| KernelError::InvalidProfile)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KernelError::InvalidProfile)
}

fn signature_from_hex(signature_hex: &str) -> KernelResult<Signature> {
    let signature = decode_hex(signature_hex)?;
    let bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| KernelError::InvalidProfile)?;
    Ok(Signature::from_bytes(&bytes))
}

fn bundle_signature_message(
    signer_id: &str,
    fingerprint: &str,
    payload_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut material = Vec::with_capacity(
        CERTIFICATION_BUNDLE_SIGNATURE_DOMAIN.len()
            + signer_id.len()
            + fingerprint.len()
            + payload_sha256.len()
            + 6,
    );
    material.extend_from_slice(CERTIFICATION_BUNDLE_SIGNATURE_DOMAIN);
    material.push(0);
    material.extend_from_slice(signer_id.as_bytes());
    material.push(0);
    material.extend_from_slice(fingerprint.as_bytes());
    material.push(0);
    material.extend_from_slice(payload_sha256);
    material
}

fn signature_ed25519_hex(
    signing_key: &SigningKey,
    signer_id: &str,
    fingerprint: &str,
    payload_sha256: &[u8; 32],
) -> String {
    let message = bundle_signature_message(signer_id, fingerprint, payload_sha256);
    to_hex(&signing_key.sign(&message).to_bytes())
}

fn default_fixture_public_key_hex() -> String {
    signing_key_from_hex(DEFAULT_FIXTURE_SIGNING_PRIVATE_KEY_HEX)
        .map(|key| to_hex(&key.verifying_key().to_bytes()))
        .unwrap_or_default()
}

fn parse_bundle_class(input: &str) -> KernelResult<BundleClass> {
    match input {
        "TESTING" => Ok(BundleClass::Testing),
        "CERTIFICATION" => Ok(BundleClass::Certification),
        _ => Err(KernelError::InvalidProfile),
    }
}

fn parse_array<T>(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    parser: fn(&JsonValue) -> KernelResult<T>,
) -> KernelResult<Vec<T>> {
    let array = object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    bounded_len(array.len())?;
    array.iter().map(parser).collect()
}

fn required_object<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<&'a BTreeMap<String, JsonValue>> {
    object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_object()
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

fn required_clean_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<&'a str> {
    let value = required_string(object, key)?;
    validate_clean_string(value)?;
    Ok(value)
}

fn required_u64(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<u64> {
    object.get(key).ok_or(KernelError::InvalidProfile)?.as_u64()
}

fn required_bool(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<bool> {
    object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_bool()
}

fn required_timeout(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<i32> {
    let value = required_u64(object, key)?;
    if value > i32::MAX as u64 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(value as i32)
}

fn required_string_array(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<Vec<String>> {
    let values = object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    bounded_len(values.len())?;
    if values.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_string()?;
            validate_clean_string(value)?;
            Ok(value.to_string())
        })
        .collect::<KernelResult<Vec<_>>>()
        .and_then(|values| {
            validate_non_empty_set(&values)?;
            Ok(values)
        })
}

fn required_string_array_allow_empty(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<Vec<String>> {
    let values = object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    bounded_len(values.len())?;
    let out = values
        .iter()
        .map(|value| {
            let value = value.as_string()?;
            validate_clean_string(value)?;
            Ok(value.to_string())
        })
        .collect::<KernelResult<Vec<_>>>()?;
    reject_duplicates(&out)?;
    Ok(out)
}

fn validate_clean_string(value: &str) -> KernelResult<()> {
    if value.is_empty()
        || value.len() > MAX_BUNDLE_STRING_BYTES
        || value.trim().len() != value.len()
        || value.chars().any(char::is_control)
    {
        return Err(KernelError::InvalidProfile);
    }
    let upper = value.to_ascii_uppercase();
    if upper.contains("PLACEHOLDER") || upper.contains("...") || upper.contains("DUMMY") {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn reject_blank(value: &str) -> KernelResult<()> {
    if value.trim().is_empty() {
        Err(KernelError::InvalidProfile)
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str) -> KernelResult<()> {
    validate_clean_string(value)?;
    if value
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn validate_known_interface(value: &str) -> KernelResult<()> {
    match value {
        "contact" | "contactless" => Ok(()),
        _ => Err(KernelError::InvalidProfile),
    }
}

fn validate_hex_len(value: &str, expected_len: usize) -> KernelResult<()> {
    let bytes = decode_hex(value)?;
    if bytes.len() == expected_len {
        Ok(())
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn validate_callback_timeouts(timeouts: CallbackTimeoutProfile) -> KernelResult<()> {
    for timeout in [
        timeouts.apdu_transport_timeout_ms,
        timeouts.host_authorization_timeout_ms,
        timeouts.pin_entry_timeout_ms,
        timeouts.contactless_ui_timeout_ms,
    ] {
        if !(1..=60_000).contains(&timeout) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
}

fn validate_non_empty_set(values: &[String]) -> KernelResult<()> {
    if values.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    reject_duplicates(values)
}

fn reject_duplicates(values: &[String]) -> KernelResult<()> {
    for (idx, value) in values.iter().enumerate() {
        if values[..idx].iter().any(|prior| prior == value) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
}

fn bounded_len(len: usize) -> KernelResult<()> {
    if len > MAX_BUNDLE_COLLECTION_ITEMS {
        Err(KernelError::LengthOverflow)
    } else {
        Ok(())
    }
}

fn split_csv(input: &str) -> KernelResult<Vec<String>> {
    let values = input
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    validate_non_empty_set(&values)?;
    Ok(values)
}

fn split_csv_allow_empty(input: &str) -> KernelResult<Vec<String>> {
    let values = input
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    reject_duplicates(&values)?;
    Ok(values)
}

fn parse_iso_date(input: &str) -> KernelResult<EmvDate> {
    let bytes = input.as_bytes();
    if bytes.len() != 10
        || bytes[0] != b'2'
        || bytes[1] != b'0'
        || bytes[4] != b'-'
        || bytes[7] != b'-'
    {
        return Err(KernelError::ParseError);
    }
    let year = decimal_pair(bytes[2], bytes[3])?;
    let month = decimal_pair(bytes[5], bytes[6])?;
    let day = decimal_pair(bytes[8], bytes[9])?;
    EmvDate::new(year, month, day)
}

fn decimal_pair(high: u8, low: u8) -> KernelResult<u8> {
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return Err(KernelError::ParseError);
    }
    Ok((high - b'0') * 10 + low - b'0')
}

fn format_date(date: EmvDate) -> String {
    format!("20{:02}-{:02}-{:02}", date.year, date.month, date.day)
}

fn reject_unknown_fields(
    object: &BTreeMap<String, JsonValue>,
    allowed: &[&str],
) -> KernelResult<()> {
    if object
        .keys()
        .any(|key| !allowed.iter().any(|allowed_key| key == allowed_key))
    {
        Err(KernelError::InvalidProfile)
    } else {
        Ok(())
    }
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    push_json_escaped(out, value);
    out.push('"');
}

fn push_json_escaped(out: &mut String, value: &str) {
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
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    let _ = write!(out, "{value}");
}

fn push_json_bool(out: &mut String, key: &str, value: bool) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(if value { "true" } else { "false" });
}

fn push_json_array(out: &mut String, key: &str, values: &[String]) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        push_json_escaped(out, value);
        out.push('"');
    }
    out.push(']');
}

fn push_html_text(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = include_str!("../docs/scheme_profiles.cert.json");

    fn input<'a>() -> BundleProvisioningInput<'a> {
        BundleProvisioningInput {
            bundle_id: "hyperion-test-bundle",
            bundle_version: 2,
            rollback_counter: 2,
            bundle_class: BundleClass::Certification,
            created: EmvDate { year: 26, month: 5, day: 25 },
            product_name: "Hyperion Test Terminal",
            product_version: "0.1.0",
            certification_target: "prelab-testing",
            interfaces: "contact,contactless",
            authorities: "Hyperion Local Test Authority",
            emv_contact_version: "EMV 4.3",
            emv_contactless_kernel: "C-8",
            bulletins_included: "public-watch-2026-05-25",
            bulletins_excluded: "",
            terminal_type: "attended-online-pos",
            device_model: "hyperion-simulated-terminal",
            firmware_version: "0.1.0",
            l1_approval_reference: "external-evidence-required",
            pci_pts_reference: "external-evidence-required",
            kernel_profile_id: "c8-contactless-baseline",
            kernel_interface: "contactless",
            kernel_algorithm: "rust-c8-module",
            c8_package: "c8-public-baseline",
            scheme_scope: "Test Scheme",
            vector_class: "TESTING",
            signer_id: "hyperion-local-test-authority",
            signing_private_key_hex: Some(DEFAULT_FIXTURE_SIGNING_PRIVATE_KEY_HEX),
            trust_not_after: Some(EmvDate { year: 28, month: 1, day: 1 }),
            callback_timeouts: None,
            scheme_profile_set_json: PROFILE,
            vector_bundle_json: "{\"schema_version\":\"hyperion-vector-bundle-1.0\",\"vector_class\":\"TESTING\",\"cases\":[]}",
        }
    }

    #[test]
    fn generated_bundle_loads_with_data_only_trust_anchor() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let anchors = parse_trust_anchors(anchors_json.as_bytes()).unwrap();
        let loaded = load_certification_bundle(
            bundle_json.as_bytes(),
            &BundleLoadPolicy {
                mode: BuildMode::Certification,
                installed_rollback_counter: 1,
                evaluation_date: EmvDate {
                    year: 26,
                    month: 5,
                    day: 25,
                },
                trust_anchors: anchors,
            },
        )
        .unwrap();
        assert_eq!(loaded.verification_status, "trust-anchor-verified");
        assert_eq!(loaded.profile_set.version, 2);
        assert_eq!(
            loaded.bundle.payload.runtime_policy.callback_timeouts,
            CallbackTimeoutProfile::defaults()
        );
    }

    #[test]
    fn tampered_bundle_payload_is_rejected() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let tampered = bundle_json.replace("prelab-testing", "prelab-testing-modified");
        let anchors = parse_trust_anchors(anchors_json.as_bytes()).unwrap();
        let err = load_certification_bundle(
            tampered.as_bytes(),
            &BundleLoadPolicy {
                mode: BuildMode::Certification,
                installed_rollback_counter: 1,
                evaluation_date: EmvDate {
                    year: 26,
                    month: 5,
                    day: 25,
                },
                trust_anchors: anchors,
            },
        )
        .unwrap_err();
        assert_eq!(err, KernelError::InvalidProfile);
    }

    #[test]
    fn rollback_counter_is_rejected() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let anchors = parse_trust_anchors(anchors_json.as_bytes()).unwrap();
        let err = load_certification_bundle(
            bundle_json.as_bytes(),
            &BundleLoadPolicy {
                mode: BuildMode::Certification,
                installed_rollback_counter: 2,
                evaluation_date: EmvDate {
                    year: 26,
                    month: 5,
                    day: 25,
                },
                trust_anchors: anchors,
            },
        )
        .unwrap_err();
        assert_eq!(err, KernelError::InvalidProfile);
    }

    fn policy_with_anchors(
        anchors_json: &str,
        installed_rollback_counter: u64,
    ) -> BundleLoadPolicy {
        BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: parse_trust_anchors(anchors_json.as_bytes()).unwrap(),
        }
    }

    fn empty_report() -> BundleCompileReport {
        BundleCompileReport {
            status: "pass",
            mode: BuildMode::Certification,
            findings: Vec::new(),
            coverage: Vec::new(),
            bundle_sha256: None,
            payload_sha256: None,
            scheme_profile_sha256: None,
            vector_bundle_sha256: None,
            verification_status: None,
        }
    }

    #[test]
    fn compile_report_explains_empty_malformed_and_load_failure_inputs() {
        let policy = BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: Vec::new(),
        };
        let empty = certification_bundle_compile_report(b"", b"", &policy);
        assert_eq!(empty.status, "fail");
        assert!(empty
            .findings
            .iter()
            .any(|finding| finding.field_path == "bundle_json"));
        assert!(empty
            .findings
            .iter()
            .any(|finding| finding.field_path == "trust_anchors_json"));

        let malformed = certification_bundle_compile_report(b"{}", b"{}", &policy);
        assert_eq!(malformed.status, "fail");
        assert!(malformed
            .findings
            .iter()
            .any(|finding| finding.title == "Bundle schema validation failed"));
        assert!(malformed
            .findings
            .iter()
            .any(|finding| finding.title == "Trust-anchor validation failed"));

        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let load_failure = certification_bundle_compile_report(
            bundle_json.as_bytes(),
            anchors_json.as_bytes(),
            &policy_with_anchors(&anchors_json, 2),
        );
        assert_eq!(load_failure.status, "fail");
        assert!(load_failure
            .findings
            .iter()
            .any(|finding| finding.title == "Bundle compile/authentication failed"));
        assert!(!load_failure.coverage.is_empty());
    }

    #[test]
    fn lint_report_covers_policy_warnings_without_authenticating_mutated_payloads() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let mut bundle = parse_certification_bundle(bundle_json.as_bytes()).unwrap();
        bundle.bundle_class = BundleClass::Testing;
        bundle.rollback_counter = 1;
        bundle.created = EmvDate {
            year: 99,
            month: 1,
            day: 1,
        };
        bundle.payload.standards_target.bulletins_included.clear();
        bundle.payload.runtime_policy.trace_masking_policy = "redaction-disabled".to_string();
        bundle.payload.artifact_hashes.truncate(1);
        bundle.payload.vector_bundle_json = "{}".to_string();
        bundle.signature.algorithm = CERTIFICATION_BUNDLE_TEST_ALGORITHM.to_string();

        let mut report = empty_report();
        let policy = policy_with_anchors(&anchors_json, 1);
        lint_parsed_bundle(&mut report, &bundle, &policy);
        finalize_compile_status(&mut report);

        assert_eq!(report.status, "fail");
        for title in [
            "Testing bundle selected outside test mode",
            "Rollback counter is not newer than installed policy",
            "Bundle creation date is after evaluation date",
            "No standards bulletin reconciliation is present",
            "Trace masking policy does not declare masking",
            "Few artifact bindings are present",
            "Vector bundle is malformed or incomplete",
        ] {
            assert!(
                report.findings.iter().any(|finding| finding.title == title),
                "missing {title}"
            );
        }
    }

    #[test]
    fn trust_anchor_lint_flags_empty_fixture_and_expired_anchors() {
        let mut report = empty_report();
        let policy = BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: Vec::new(),
        };
        lint_trust_anchors(&mut report, &[], &policy);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.title == "No trust anchors are provisioned"));

        let (_, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let mut anchors = parse_trust_anchors(anchors_json.as_bytes()).unwrap();
        anchors[0].not_after = Some(EmvDate {
            year: 25,
            month: 1,
            day: 1,
        });
        lint_trust_anchors(&mut report, &anchors, &policy);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.title == "Fixture verification key is still present"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.title == "Trust anchor has expired for the evaluation date"));
    }

    #[test]
    fn vector_status_and_report_status_cover_all_outcomes() {
        assert_eq!(certification_vector_bundle_status("not json"), "incomplete");
        assert_eq!(certification_vector_bundle_status("[]"), "incomplete");
        assert_eq!(certification_vector_bundle_status("{}"), "incomplete");
        assert_eq!(
            certification_vector_bundle_status(
                "{\"vector_class\":\"TESTING\",\"cases\":[{\"id\":\"fixture\"}]}"
            ),
            "external_required"
        );
        assert_eq!(
            certification_vector_bundle_status("{\"vector_class\":\"CERTIFICATION\",\"cases\":[]}"),
            "external_required"
        );
        assert_eq!(
            certification_vector_bundle_status(
                "{\"vector_class\":\"CERTIFICATION\",\"test_vectors\":[{\"name\":\"sda dda cda\"}]}"
            ),
            "covered"
        );

        let mut report = empty_report();
        finalize_compile_status(&mut report);
        assert_eq!(report.status, "pass");
        let markdown = certification_bundle_compile_report_markdown(&report);
        assert!(markdown.contains("No findings."));

        report.coverage.push(coverage_status_item(
            "oda_vectors",
            "ODA",
            "role",
            "source",
            "external_required",
            "suggestion",
        ));
        finalize_compile_status(&mut report);
        assert_eq!(report.status, "warn");

        push_finding(
            &mut report,
            BundleLintSeverity::Error,
            "x",
            "bad",
            "impact",
            "suggestion",
        );
        finalize_compile_status(&mut report);
        assert_eq!(report.status, "fail");
    }

    #[test]
    fn parsers_reject_oversized_empty_and_schema_invalid_inputs() {
        let policy = BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: Vec::new(),
        };
        assert_eq!(
            load_certification_bundle(b"", &policy).unwrap_err(),
            KernelError::LengthOverflow
        );
        assert_eq!(
            parse_trust_anchors(b"").unwrap_err(),
            KernelError::LengthOverflow
        );
        assert_eq!(
            parse_certification_bundle(b"{\"schema_version\":\"wrong\"}").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_trust_anchors(b"{\"schema_version\":\"wrong\",\"trust_anchors\":[]}")
                .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_trust_anchors(b"{\"schema_version\":\"hyperion-certification-trust-anchors-1.0\",\"trust_anchors\":[]}").unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn testing_bundle_self_attestation_is_test_mode_only() {
        let (bundle_json, _) = create_bundle_from_inputs(input()).unwrap();
        let mut bundle = parse_certification_bundle(bundle_json.as_bytes()).unwrap();
        bundle.bundle_class = BundleClass::Testing;
        bundle.signature.algorithm = CERTIFICATION_BUNDLE_TEST_ALGORITHM.to_string();
        bundle.signature.signature_hex = "11".repeat(32);
        bundle.signature.signature_artifact_sha256 =
            to_hex(&sha256(bundle.signature.signature_hex.as_bytes()));
        let testing_json = certification_bundle_json(&bundle);

        let test_policy = BundleLoadPolicy {
            mode: BuildMode::Test,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: Vec::new(),
        };
        let loaded = load_certification_bundle(testing_json.as_bytes(), &test_policy).unwrap();
        assert_eq!(loaded.verification_status, "testing-self-attested");
        assert_eq!(loaded.bundle.bundle_class.as_str(), "TESTING");

        let certification_policy = BundleLoadPolicy {
            mode: BuildMode::Certification,
            ..test_policy
        };
        assert_eq!(
            load_certification_bundle(testing_json.as_bytes(), &certification_policy).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn bundle_helper_validators_cover_rejections_and_serializers() {
        assert_eq!(BundleClass::Testing.as_str(), "TESTING");
        assert_eq!(BundleLintSeverity::Warning.as_str(), "warning");
        assert_eq!(BundleLintSeverity::Error.as_str(), "error");
        assert_eq!(parse_bundle_class("TESTING"), Ok(BundleClass::Testing));
        assert_eq!(
            parse_bundle_class("LOCAL").unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut report = empty_report();
        report.bundle_sha256 = Some("aa".repeat(32));
        report.payload_sha256 = Some("bb".repeat(32));
        report.scheme_profile_sha256 = Some("cc".repeat(32));
        report.vector_bundle_sha256 = Some("dd".repeat(32));
        report.verification_status = Some("trust-anchor-verified");
        report.coverage.push(coverage_item(
            "selection",
            "Application selection",
            "role",
            "payload.scheme_profile_set_json",
            true,
            "covered",
        ));
        let json = certification_bundle_compile_report_json(&report);
        assert!(json.contains("bundle_sha256"));
        assert!(json.contains("scheme_profile_sha256"));
        assert!(json.contains("vector_bundle_sha256"));
        let markdown = certification_bundle_compile_report_markdown(&report);
        assert!(markdown.contains("Payload SHA-256"));
        assert!(markdown.contains("Verification status"));

        assert_eq!(split_csv("contact, contactless").unwrap().len(), 2);
        assert_eq!(
            split_csv("contact,contact").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(split_csv_allow_empty(""), Ok(Vec::new()));
        assert_eq!(
            split_csv_allow_empty("a,a").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            validate_clean_string("").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            validate_clean_string(" PLACEHOLDER").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(reject_blank("   "), Err(KernelError::InvalidProfile));
        assert_eq!(
            validate_identifier("bad/id").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            validate_known_interface("qr").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            validate_hex_len("aa", 32).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            validate_callback_timeouts(CallbackTimeoutProfile {
                apdu_transport_timeout_ms: 0,
                host_authorization_timeout_ms: 30_000,
                pin_entry_timeout_ms: 30_000,
                contactless_ui_timeout_ms: 5_000,
            })
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            bounded_len(MAX_BUNDLE_COLLECTION_ITEMS + 1),
            Err(KernelError::LengthOverflow)
        );
        assert_eq!(
            parse_iso_date("2026/05/25").unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_iso_date("20aa-05-25").unwrap_err(),
            KernelError::ParseError
        );

        let mut object = std::collections::BTreeMap::new();
        object.insert("known".to_string(), JsonValue::String("value".to_string()));
        assert_eq!(
            reject_unknown_fields(&object, &["other"]),
            Err(KernelError::InvalidProfile)
        );
        assert_eq!(
            required_object(&object, "missing"),
            Err(KernelError::InvalidProfile)
        );
        assert_eq!(
            required_u64(&object, "missing"),
            Err(KernelError::InvalidProfile)
        );
        assert_eq!(
            required_bool(&object, "missing"),
            Err(KernelError::InvalidProfile)
        );

        object.insert(
            "timeout".to_string(),
            JsonValue::Number(i32::MAX as u64 + 1),
        );
        assert_eq!(
            required_timeout(&object, "timeout"),
            Err(KernelError::InvalidProfile)
        );
        object.insert("items".to_string(), JsonValue::Array(Vec::new()));
        assert_eq!(
            required_string_array(&object, "items"),
            Err(KernelError::InvalidProfile)
        );
        object.insert(
            "items".to_string(),
            JsonValue::Array(vec![
                JsonValue::String("a".to_string()),
                JsonValue::String("a".to_string()),
            ]),
        );
        assert_eq!(
            required_string_array(&object, "items"),
            Err(KernelError::InvalidProfile)
        );
        assert_eq!(
            required_string_array_allow_empty(&object, "items"),
            Err(KernelError::InvalidProfile)
        );
    }

    fn unknown_object() -> std::collections::BTreeMap<String, JsonValue> {
        let mut object = std::collections::BTreeMap::new();
        object.insert(
            "unknown".to_string(),
            JsonValue::String("value".to_string()),
        );
        object
    }

    #[test]
    fn bundle_parser_policy_and_serializer_edges_fail_closed() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let bundle = parse_certification_bundle(bundle_json.as_bytes()).unwrap();
        let anchors = parse_trust_anchors(anchors_json.as_bytes()).unwrap();
        let policy = policy_with_anchors(&anchors_json, 1);

        let bad_anchor_report = certification_bundle_compile_report(
            bundle_json.as_bytes(),
            b"{\"schema_version\":\"wrong\",\"trust_anchors\":[]}",
            &policy,
        );
        assert_eq!(bad_anchor_report.status, "fail");
        assert!(!bad_anchor_report.coverage.is_empty());

        let zero_version = bundle_json.replace("\"bundle_version\":2", "\"bundle_version\":0");
        assert_ne!(zero_version, bundle_json);
        assert_eq!(
            parse_certification_bundle(zero_version.as_bytes()).unwrap_err(),
            KernelError::InvalidProfile
        );
        let unknown_bundle_field =
            bundle_json.replace("\"created\":", "\"unexpected\":1,\"created\":");
        assert_eq!(
            parse_certification_bundle(unknown_bundle_field.as_bytes()).unwrap_err(),
            KernelError::InvalidProfile
        );

        let two_anchor_json = trust_anchors_json(&[anchors[0].clone(), anchors[0].clone()]);
        assert!(two_anchor_json.contains("},{"));
        assert_eq!(build_mode_as_str(BuildMode::Test), "test");
        assert_eq!(build_mode_as_str(BuildMode::Production), "production");
        assert_eq!(
            external_reference_status("lab-approved-reference"),
            "covered"
        );
        assert_eq!(
            certification_vector_bundle_status(
                "{\"vector_class\":\"CERTIFICATION\",\"cases\":[{\"name\":\"sda dda only\"}]}"
            ),
            "external_required"
        );
        assert_eq!(
            validate_clean_string("PLACEHOLDER").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            validate_non_empty_set(&[]).unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut escaped_json = String::new();
        push_json_escaped(
            &mut escaped_json,
            "quote\" slash\\ line\n carriage\r tab\t nul\0",
        );
        assert_eq!(
            escaped_json,
            "quote\\\" slash\\\\ line\\n carriage\\r tab\\t nul\\u0000"
        );
        let mut html = String::new();
        push_html_text(&mut html, "<&>\"");
        assert_eq!(html, "&lt;&amp;&gt;&quot;");

        let mut future_bundle = bundle.clone();
        future_bundle.created = EmvDate {
            year: 27,
            month: 1,
            day: 1,
        };
        assert_eq!(
            validate_bundle_for_policy(&future_bundle, &policy).unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut testing_bundle = bundle.clone();
        testing_bundle.bundle_class = BundleClass::Testing;
        assert_eq!(
            validate_bundle_for_policy(&testing_bundle, &policy).unwrap_err(),
            KernelError::InvalidProfile
        );
        let no_anchor_policy = BundleLoadPolicy {
            trust_anchors: Vec::new(),
            ..policy.clone()
        };
        assert_eq!(
            validate_bundle_for_policy(&bundle, &no_anchor_policy).unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut expired_anchor_policy = policy.clone();
        expired_anchor_policy.trust_anchors[0].not_after = Some(EmvDate {
            year: 25,
            month: 1,
            day: 1,
        });
        assert_eq!(
            load_certification_bundle(bundle_json.as_bytes(), &expired_anchor_policy).unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut wrong_payload_policy = policy.clone();
        wrong_payload_policy.trust_anchors[0].allowed_payload_sha256 = "00".repeat(32);
        assert_eq!(
            load_certification_bundle(bundle_json.as_bytes(), &wrong_payload_policy).unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut wrong_fingerprint_policy = policy.clone();
        wrong_fingerprint_policy.trust_anchors[0].signing_key_fingerprint = "00".repeat(32);
        assert_eq!(
            load_certification_bundle(bundle_json.as_bytes(), &wrong_fingerprint_policy)
                .unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut wrong_algorithm_bundle = bundle.clone();
        wrong_algorithm_bundle.signature.algorithm =
            CERTIFICATION_BUNDLE_TEST_ALGORITHM.to_string();
        let payload_sha256 =
            sha256(payload_canonical_json(&wrong_algorithm_bundle.payload).as_bytes());
        assert_eq!(
            verify_bundle_signature(&wrong_algorithm_bundle, &payload_sha256, &policy).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            load_certification_bundle(
                certification_bundle_json(&wrong_algorithm_bundle).as_bytes(),
                &policy,
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut wrong_public_key_policy = policy.clone();
        let other_key = SigningKey::from_bytes(&[7u8; 32]);
        wrong_public_key_policy.trust_anchors[0].verification_public_key_hex =
            to_hex(&other_key.verifying_key().to_bytes());
        assert_eq!(
            load_certification_bundle(bundle_json.as_bytes(), &wrong_public_key_policy)
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut bad_profile_bundle = bundle.clone();
        bad_profile_bundle.bundle_class = BundleClass::Testing;
        bad_profile_bundle.payload.scheme_profile_set_json = "{}".to_string();
        let bad_payload_sha =
            sha256(payload_canonical_json(&bad_profile_bundle.payload).as_bytes());
        bad_profile_bundle.signature.algorithm = CERTIFICATION_BUNDLE_TEST_ALGORITHM.to_string();
        bad_profile_bundle.signature.payload_sha256 = to_hex(&bad_payload_sha);
        bad_profile_bundle.signature.signature_hex = "11".repeat(32);
        bad_profile_bundle.signature.signature_artifact_sha256 = to_hex(&sha256(
            bad_profile_bundle.signature.signature_hex.as_bytes(),
        ));
        let bad_profile_json = certification_bundle_json(&bad_profile_bundle);
        let test_policy = BundleLoadPolicy {
            mode: BuildMode::Test,
            installed_rollback_counter: 1,
            evaluation_date: policy.evaluation_date,
            trust_anchors: Vec::new(),
        };
        assert_eq!(
            load_certification_bundle(bad_profile_json.as_bytes(), &test_policy).unwrap_err(),
            KernelError::InvalidProfile
        );

        let loaded = load_certification_bundle(bundle_json.as_bytes(), &policy).unwrap();
        for (lower, upper, typed_limit) in [
            (Some(1), None, None),
            (None, Some(2), None),
            (
                None,
                None,
                Some(crate::trm::TransactionTypeFloorLimit {
                    transaction_type: 1,
                    floor_limit: 1,
                }),
            ),
        ] {
            let mut trm_loaded = loaded.clone();
            let aid = &mut trm_loaded.profile_set.schemes[0].aids[0];
            aid.floor_limit = 0;
            aid.random_selection_percent = 0;
            aid.lower_consecutive_offline_limit = lower;
            aid.upper_consecutive_offline_limit = upper;
            aid.transaction_type_floor_limits.clear();
            if let Some(limit) = typed_limit {
                aid.transaction_type_floor_limits.push(limit);
            }
            assert!(emv_capability_coverage(&trm_loaded)
                .iter()
                .any(|item| item.id == "trm" && item.status != "incomplete"));
        }
        let mut cvm_loaded = loaded.clone();
        cvm_loaded.bundle.payload.cvm_extensions.clear();
        let aid = &mut cvm_loaded.profile_set.schemes[0].aids[0];
        aid.cvm_limit_contact = 0;
        aid.contactless_cvm_limit = 0;
        aid.cdcvm_supported = true;
        assert!(emv_capability_coverage(&cvm_loaded)
            .iter()
            .any(|item| item.id == "cvm_pin" && item.status == "covered"));

        let mut payload = bundle.payload.clone();
        payload.kernel_registry.push(KernelProfileRegistration {
            kernel_profile_id: "contact-kernel-profile".to_string(),
            interface: "contact".to_string(),
            algorithm: "rust-contact-module".to_string(),
            c8_package: "contact-package".to_string(),
            scheme_scope: vec!["Test Scheme".to_string()],
        });
        payload.cvm_extensions.push(CvmExtensionRule {
            rule_id: "second-cvm-extension".to_string(),
            scheme_scope: vec!["Test Scheme".to_string()],
            cvm_code_hex: "1F".to_string(),
            meaning: "second-extension".to_string(),
            tvr_on_failure_hex: "0000000000".to_string(),
            continue_on_failure: false,
        });
        payload.test_plan.push(CertificationTestCase {
            case_id: "CERT-DATA-0002".to_string(),
            vector_class: "TESTING".to_string(),
            expected_outcome: "second-case".to_string(),
            trace_requirement: "masked-trace".to_string(),
        });
        payload.artifact_hashes.push(ArtifactHashBinding {
            artifact_id: "report_pack".to_string(),
            artifact_kind: "report".to_string(),
            sha256_hex: "22".repeat(32),
            binds_open_issues: vec!["CERT-OPEN-001".to_string()],
        });
        let canonical = payload_canonical_json(&payload);
        assert!(canonical.contains("second-cvm-extension"));
        assert!(canonical.contains("CERT-DATA-0002"));
        assert!(canonical.contains("report_pack"));

        let mut empty_kernel_payload = bundle.payload.clone();
        empty_kernel_payload.kernel_registry.clear();
        assert_eq!(
            validate_payload(&empty_kernel_payload).unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut oversize_payload = bundle.payload.clone();
        oversize_payload.scheme_profile_set_json = " ".repeat(MAX_EMBEDDED_PROFILE_BYTES + 1);
        assert_eq!(
            validate_payload(&oversize_payload).unwrap_err(),
            KernelError::LengthOverflow
        );
        let mut missing_contactless_kernel = bundle.payload.clone();
        missing_contactless_kernel.kernel_registry[0].interface = "contact".to_string();
        assert_eq!(
            validate_payload(&missing_contactless_kernel).unwrap_err(),
            KernelError::InvalidProfile
        );
        let mut bad_artifact_payload = bundle.payload.clone();
        bad_artifact_payload.artifact_hashes[0].artifact_id = "bad/artifact".to_string();
        assert_eq!(
            validate_payload(&bad_artifact_payload).unwrap_err(),
            KernelError::InvalidProfile
        );

        assert_eq!(
            parse_payload(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_submission_scope(&unknown_object()).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_standards_target(&unknown_object()).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_terminal_profile(&unknown_object()).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_runtime_policy(&unknown_object()).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_callback_timeouts(&unknown_object()).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_kernel_registration(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_cvm_extension(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_test_case(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_artifact_hash(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_signature(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_trust_anchor(&JsonValue::Object(unknown_object())).unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut report = empty_report();
        report.mode = BuildMode::Production;
        report.coverage = payload_capability_coverage(&bundle);
        let markdown = certification_bundle_compile_report_markdown(&report);
        assert!(markdown.contains("Mode: `production`"));
        assert!(markdown.contains("payload.kernel_registry"));
    }

    #[test]
    fn workbench_contains_local_static_editor() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let html = certification_bundle_workbench_html(&bundle_json, &anchors_json);
        assert!(html.contains("Hyperion Data Bundle Workbench"));
        assert!(html.contains("textarea"));
        assert!(html.contains("never uploads"));
    }
}
