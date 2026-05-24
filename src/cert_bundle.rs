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
use std::collections::BTreeMap;

pub const CERTIFICATION_BUNDLE_SCHEMA_VERSION: &str = "hyperion-certification-bundle-1.0";
pub const CERTIFICATION_BUNDLE_SIGNATURE_ALGORITHM: &str = "hyperion-sha256-mac-v1";
pub const CERTIFICATION_BUNDLE_TEST_ALGORITHM: &str = "hyperion-sha256-test-attestation-v1";
pub const CERTIFICATION_BUNDLE_SIGNATURE_DOMAIN: &[u8] =
    b"Hyperion certification bundle signature v1";
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
    pub verification_secret_hex: String,
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
            "verification_secret_hex",
            &anchor.verification_secret_hex,
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
        .verification_secret_hex
        .unwrap_or("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
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
    let signing_key_fingerprint = to_hex(&sha256(secret.as_bytes()));
    let signature_hex = signature_mac_hex(
        input.signer_id,
        &signing_key_fingerprint,
        &payload_hash,
        secret,
    )?;
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
            signature_artifact_sha256: to_hex(&sha256(
                b"external-detached-signature-artifact-pending",
            )),
        },
    };
    let anchor = BundleTrustAnchor {
        signer_id: input.signer_id.to_string(),
        signing_key_fingerprint,
        verification_secret_hex: secret.to_string(),
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
    pub verification_secret_hex: Option<&'a str>,
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
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Hyperion Data Bundle Workbench</title><style>");
    out.push_str("body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;color:#20242a}header{background:#13202d;color:#fff;padding:18px 24px}main{display:grid;grid-template-columns:300px 1fr;gap:18px;padding:18px}.panel{background:#fff;border:1px solid #d9dde3;border-radius:6px;padding:14px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}label{font-weight:600;display:block;margin:8px 0 4px}input,textarea,select{width:100%;box-sizing:border-box;border:1px solid #bbc3cf;border-radius:4px;padding:8px;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}textarea{min-height:360px;resize:vertical}.status{display:grid;gap:8px}.ok{color:#0f6b3f}.warn{color:#8a4f00}.bad{color:#9b1c1c}button{border:1px solid #1b5a8f;background:#1f6aa5;color:#fff;border-radius:4px;padding:8px 10px;font-weight:700}code{background:#eef1f5;padding:1px 4px;border-radius:3px}@media(max-width:900px){main{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}</style></head><body>");
    out.push_str("<header><h1>Hyperion Data Bundle Workbench</h1><p>Create, inspect, and validate data-driven certification/testing bundles without changing kernel code.</p></header><main>");
    out.push_str("<section class=\"panel\"><h2>Provisioning Steps</h2><div class=\"status\"><div class=\"ok\">1. Edit bundle data.</div><div class=\"ok\">2. Protect trust-anchor data.</div><div class=\"warn\">3. Run <code>krn_certification_bundle --validate</code>.</div><div class=\"warn\">4. Attach external lab/scheme/device evidence.</div></div><p>This workbench is static and local. It never uploads profile, CAPK, vector, or evidence data.</p><button type=\"button\" onclick=\"validatePanels()\">Check Required Fields</button><pre id=\"result\"></pre></section>");
    out.push_str(
        "<section class=\"grid\"><div class=\"panel\"><h2>Bundle JSON</h2><textarea id=\"bundle\">",
    );
    push_html_text(&mut out, bundle_json);
    out.push_str(
        "</textarea></div><div class=\"panel\"><h2>Trust Anchors JSON</h2><textarea id=\"trust\">",
    );
    push_html_text(&mut out, trust_anchors_json);
    out.push_str("</textarea></div></section></main><script>");
    out.push_str("function validatePanels(){let r=[];for(const id of ['bundle','trust']){try{const j=JSON.parse(document.getElementById(id).value);r.push(id+': valid JSON');if(id==='bundle'){for(const k of ['schema_version','bundle_id','payload','signature']){if(!(k in j))r.push(id+': missing '+k)}}if(id==='trust'&&!Array.isArray(j.trust_anchors))r.push('trust: missing trust_anchors array')}catch(e){r.push(id+': '+e.message)}}document.getElementById('result').textContent=r.join('\n')}validatePanels();</script></body></html>\n");
    out
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
    if let Some(not_after) = anchor.not_after {
        if not_after < policy.evaluation_date {
            return Err(KernelError::InvalidProfile);
        }
    }
    if anchor.allowed_payload_sha256 != to_hex(payload_sha256) {
        return Err(KernelError::InvalidProfile);
    }
    let expected = signature_mac_hex(
        &bundle.signature.signer_id,
        &bundle.signature.signing_key_fingerprint,
        payload_sha256,
        &anchor.verification_secret_hex,
    )?;
    if expected != bundle.signature.signature_hex {
        return Err(KernelError::InvalidProfile);
    }
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
    let signature_hex = required_clean_string(object, "signature_hex")?.to_string();
    validate_hex_len(&signature_hex, 32)?;
    let artifact_sha = required_clean_string(object, "signature_artifact_sha256")?.to_string();
    validate_hex_len(&artifact_sha, 32)?;
    Ok(BundleSignature {
        algorithm: required_clean_string(object, "algorithm")?.to_string(),
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
            "verification_secret_hex",
            "allowed_payload_sha256",
            "not_after",
        ],
    )?;
    let secret = required_clean_string(object, "verification_secret_hex")?.to_string();
    validate_hex_len(&secret, 32)?;
    let allowed = required_clean_string(object, "allowed_payload_sha256")?.to_string();
    validate_hex_len(&allowed, 32)?;
    Ok(BundleTrustAnchor {
        signer_id: required_clean_string(object, "signer_id")?.to_string(),
        signing_key_fingerprint: required_clean_string(object, "signing_key_fingerprint")?
            .to_string(),
        verification_secret_hex: secret,
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

fn signature_mac_hex(
    signer_id: &str,
    fingerprint: &str,
    payload_sha256: &[u8; 32],
    secret_hex: &str,
) -> KernelResult<String> {
    let secret = decode_hex(secret_hex)?;
    if secret.len() != 32 {
        return Err(KernelError::InvalidProfile);
    }
    let mut material = Vec::with_capacity(
        CERTIFICATION_BUNDLE_SIGNATURE_DOMAIN.len()
            + signer_id.len()
            + fingerprint.len()
            + payload_sha256.len()
            + secret.len()
            + 8,
    );
    material.extend_from_slice(CERTIFICATION_BUNDLE_SIGNATURE_DOMAIN);
    material.push(0);
    material.extend_from_slice(signer_id.as_bytes());
    material.push(0);
    material.extend_from_slice(fingerprint.as_bytes());
    material.push(0);
    material.extend_from_slice(payload_sha256);
    material.push(0);
    material.extend_from_slice(&secret);
    Ok(to_hex(&sha256(&material)))
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
            verification_secret_hex: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
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

    #[test]
    fn workbench_contains_local_static_editor() {
        let (bundle_json, anchors_json) = create_bundle_from_inputs(input()).unwrap();
        let html = certification_bundle_workbench_html(&bundle_json, &anchors_json);
        assert!(html.contains("Hyperion Data Bundle Workbench"));
        assert!(html.contains("textarea"));
        assert!(html.contains("never uploads"));
    }
}
