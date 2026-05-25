//! Guided certification workspace wizard.
//!
//! The wizard prepares a user to build a certifiable Hyperion-based kernel by
//! collecting the submission scope, generating the signed data-bundle scaffold,
//! creating artifact intake directories, and writing the commands needed to
//! validate, lint, import, freeze, and report the package. It deliberately does
//! not claim certification: external authorities still provide approval, lab,
//! device, PCI/PED, CAPK, vector, and trace evidence.

use core::fmt::Write;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::artifact_import::ARTIFACT_ADAPTER_SPECS;
use crate::cert_bundle::{
    certification_bundle_compile_report, certification_bundle_compile_report_json,
    certification_bundle_compile_report_markdown, certification_bundle_workbench_html,
    create_bundle_from_inputs, parse_trust_anchors, BundleClass, BundleLoadPolicy,
    BundleProvisioningInput, CallbackTimeoutProfile,
};
use crate::config::BuildMode;
use crate::evidence::certification_evidence_requirements;
use crate::integration_import::{
    CERTIFICATION_INTEGRATION_MANIFEST_FILE, CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
};
use crate::provenance::{sha256, to_hex};
use crate::restrictions::EmvDate;

pub const DEFAULT_CERTIFICATION_WIZARD_ROOT: &str = "target/hyperion-certification-wizard";

const DEFAULT_PROFILE: &str = include_str!("../docs/scheme_profiles.cert.json");
const DEFAULT_VECTORS: &str = include_str!("../docs/oda_test_vectors.json");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationWizardInput {
    pub bundle_id: String,
    pub product_name: String,
    pub product_version: String,
    pub certification_target: String,
    pub interfaces: String,
    pub schemes: String,
    pub authorities: String,
    pub terminal_type: String,
    pub device_model: String,
    pub firmware_version: String,
    pub l1_approval_reference: String,
    pub pci_pts_reference: String,
    pub emv_contact_version: String,
    pub emv_contactless_kernel: String,
    pub bulletins_included: String,
    pub bulletins_excluded: String,
    pub kernel_profile_id: String,
    pub kernel_interface: String,
    pub kernel_algorithm: String,
    pub c8_package: String,
    pub vector_class: String,
    pub signer_id: String,
    pub signing_private_key_hex: String,
    pub bundle_version: u64,
    pub rollback_counter: u64,
    pub installed_rollback_counter: u64,
    pub created: EmvDate,
    pub trust_not_after: EmvDate,
}

impl Default for CertificationWizardInput {
    fn default() -> Self {
        Self {
            bundle_id: "hyperion-certification-candidate".to_string(),
            product_name: "Hyperion EMV Kernel".to_string(),
            product_version: env!("CARGO_PKG_VERSION").to_string(),
            certification_target: "contact-and-c8-contactless-candidate".to_string(),
            interfaces: "contact,contactless".to_string(),
            schemes: "scheme-a-pending,scheme-b-pending".to_string(),
            authorities: "recognized-lab-pending,scheme-authority-pending,acquirer-pending"
                .to_string(),
            terminal_type: "attended-online-pos".to_string(),
            device_model: "target-device-model-pending".to_string(),
            firmware_version: "submitted-firmware-version-pending".to_string(),
            l1_approval_reference: "external-l1-evidence-required".to_string(),
            pci_pts_reference: "external-pci-pts-evidence-required".to_string(),
            emv_contact_version: "EMV 4.3".to_string(),
            emv_contactless_kernel: "EMV Contactless Kernel C-8".to_string(),
            bulletins_included: "public-standards-watch-2026-05-25".to_string(),
            bulletins_excluded: "none".to_string(),
            kernel_profile_id: "c8-contactless-data-profile".to_string(),
            kernel_interface: "contactless".to_string(),
            kernel_algorithm: "hyperion-rust-c8-module".to_string(),
            c8_package: "c8-lab-package-pending".to_string(),
            vector_class: "PRELAB_FIXTURE_PENDING_CERTIFICATION_VECTORS".to_string(),
            signer_id: "hyperion-local-wizard-authority".to_string(),
            signing_private_key_hex:
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            bundle_version: 2,
            rollback_counter: 2,
            installed_rollback_counter: 1,
            created: EmvDate {
                year: 26,
                month: 5,
                day: 26,
            },
            trust_not_after: EmvDate {
                year: 28,
                month: 1,
                day: 1,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationWizardOutput {
    pub root: PathBuf,
    pub bundle_path: PathBuf,
    pub trust_anchors_path: PathBuf,
    pub workbench_path: PathBuf,
    pub plan_json_path: PathBuf,
    pub plan_markdown_path: PathBuf,
    pub commands_path: PathBuf,
    pub next_steps_path: PathBuf,
    pub artifact_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationWizardStep {
    pub id: &'static str,
    pub title: &'static str,
    pub purpose: &'static str,
    pub generated_artifacts: &'static [&'static str],
    pub user_action: &'static str,
}

pub const CERTIFICATION_WIZARD_STEPS: &[CertificationWizardStep] = &[
    CertificationWizardStep {
        id: "SCOPE",
        title: "Declare the candidate scope",
        purpose: "name the product, interfaces, schemes, device boundary, and authorities before generating data",
        generated_artifacts: &["wizard_plan.json", "wizard_plan.md"],
        user_action: "confirm that the claimed scope matches the intended certification submission",
    },
    CertificationWizardStep {
        id: "BUNDLE",
        title: "Create the signed data-bundle scaffold",
        purpose: "move certification choices into signed data rather than Rust source edits",
        generated_artifacts: &[
            "bundle/certification_bundle.json",
            "bundle/trust_anchors.json",
            "bundle/index.html",
            "bundle/certification_bundle_lint.json",
        ],
        user_action: "replace fixture or pending values with authority-supplied profile, CAPK, vector, and device data",
    },
    CertificationWizardStep {
        id: "ARTIFACTS",
        title: "Stage real authority artifacts",
        purpose: "prepare fail-closed intake directories for lab, scheme, CAPK, vector, device, and report evidence",
        generated_artifacts: &[
            "artifacts/lab",
            "artifacts/scheme",
            "artifacts/capk",
            "artifacts/vectors",
            "artifacts/device",
            "artifacts/reports",
            "artifacts/integration_manifest.template.json",
        ],
        user_action: "place reviewed external files into the matching lane and fill out a manifest when a format needs explicit mapping",
    },
    CertificationWizardStep {
        id: "VERIFY",
        title: "Validate, lint, and import",
        purpose: "run repository-controlled checks before any lab-facing freeze",
        generated_artifacts: &["commands.md"],
        user_action: "run the listed commands and fix every fail or unsafe warning before submission",
    },
    CertificationWizardStep {
        id: "FREEZE",
        title: "Freeze the submission package",
        purpose: "bind the submitted binary, bundle, profile, trace, coverage, static/fuzz, and approval hashes",
        generated_artifacts: &["next_steps.md"],
        user_action: "only freeze after external evidence and official vectors are present and scoped to the exact submitted build",
    },
];

pub fn write_certification_wizard_workspace(
    dir: &Path,
    input: &CertificationWizardInput,
) -> io::Result<CertificationWizardOutput> {
    fs::create_dir_all(dir)?;
    let vector_bundle = default_vector_bundle(input);
    let (bundle, anchors) = create_bundle_from_inputs(BundleProvisioningInput {
        bundle_id: &input.bundle_id,
        bundle_version: input.bundle_version,
        rollback_counter: input.rollback_counter,
        bundle_class: BundleClass::Certification,
        created: input.created,
        product_name: &input.product_name,
        product_version: &input.product_version,
        certification_target: &input.certification_target,
        interfaces: &input.interfaces,
        authorities: &input.authorities,
        emv_contact_version: &input.emv_contact_version,
        emv_contactless_kernel: &input.emv_contactless_kernel,
        bulletins_included: &input.bulletins_included,
        bulletins_excluded: &input.bulletins_excluded,
        terminal_type: &input.terminal_type,
        device_model: &input.device_model,
        firmware_version: &input.firmware_version,
        l1_approval_reference: &input.l1_approval_reference,
        pci_pts_reference: &input.pci_pts_reference,
        kernel_profile_id: &input.kernel_profile_id,
        kernel_interface: &input.kernel_interface,
        kernel_algorithm: &input.kernel_algorithm,
        c8_package: &input.c8_package,
        scheme_scope: &input.schemes,
        vector_class: &input.vector_class,
        signer_id: &input.signer_id,
        signing_private_key_hex: Some(&input.signing_private_key_hex),
        trust_not_after: Some(input.trust_not_after),
        callback_timeouts: Some(CallbackTimeoutProfile::defaults()),
        scheme_profile_set_json: DEFAULT_PROFILE,
        vector_bundle_json: &vector_bundle,
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    let bundle_dir = dir.join("bundle");
    let artifact_dir = dir.join("artifacts");
    fs::create_dir_all(&bundle_dir)?;
    fs::create_dir_all(&artifact_dir)?;
    for spec in ARTIFACT_ADAPTER_SPECS {
        let lane = artifact_dir.join(spec.input_dir);
        fs::create_dir_all(&lane)?;
        fs::write(
            lane.join("README.md"),
            artifact_lane_readme(spec.id, spec.title),
        )?;
    }

    let trust_anchors = parse_trust_anchors(anchors.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let compile_report = certification_bundle_compile_report(
        bundle.as_bytes(),
        anchors.as_bytes(),
        &BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter: input.installed_rollback_counter,
            evaluation_date: input.created,
            trust_anchors,
        },
    );

    let bundle_path = bundle_dir.join("certification_bundle.json");
    let trust_anchors_path = bundle_dir.join("trust_anchors.json");
    let workbench_path = bundle_dir.join("index.html");
    let plan_json_path = dir.join("wizard_plan.json");
    let plan_markdown_path = dir.join("wizard_plan.md");
    let commands_path = dir.join("commands.md");
    let next_steps_path = dir.join("next_steps.md");

    fs::write(&bundle_path, &bundle)?;
    fs::write(&trust_anchors_path, &anchors)?;
    fs::write(
        &workbench_path,
        certification_bundle_workbench_html(&bundle, &anchors),
    )?;
    fs::write(
        bundle_dir.join("certification_bundle_lint.json"),
        certification_bundle_compile_report_json(&compile_report),
    )?;
    fs::write(
        bundle_dir.join("certification_bundle_lint.md"),
        certification_bundle_compile_report_markdown(&compile_report),
    )?;
    fs::write(
        artifact_dir.join("integration_manifest.template.json"),
        integration_manifest_template(input),
    )?;
    fs::write(&plan_json_path, certification_wizard_plan_json(input))?;
    fs::write(
        &plan_markdown_path,
        certification_wizard_plan_markdown(input),
    )?;
    fs::write(&commands_path, certification_wizard_commands_markdown(dir))?;
    fs::write(
        &next_steps_path,
        certification_wizard_next_steps_markdown(input),
    )?;
    fs::write(dir.join("README.md"), certification_wizard_readme(input))?;

    Ok(CertificationWizardOutput {
        root: dir.to_path_buf(),
        bundle_path,
        trust_anchors_path,
        workbench_path,
        plan_json_path,
        plan_markdown_path,
        commands_path,
        next_steps_path,
        artifact_root: artifact_dir,
    })
}

pub fn certification_wizard_plan_json(input: &CertificationWizardInput) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "hyperion-certification-wizard-plan");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_str(&mut out, "bundle_id", &input.bundle_id);
    out.push(',');
    push_json_str(&mut out, "product_name", &input.product_name);
    out.push(',');
    push_json_str(&mut out, "product_version", &input.product_version);
    out.push(',');
    push_json_str(
        &mut out,
        "certification_target",
        &input.certification_target,
    );
    out.push_str(",\"interfaces\":[");
    push_csv_json_array(&mut out, &input.interfaces);
    out.push_str("],\"schemes\":[");
    push_csv_json_array(&mut out, &input.schemes);
    out.push_str("],\"authorities\":[");
    push_csv_json_array(&mut out, &input.authorities);
    out.push(']');
    out.push(',');
    push_json_str(&mut out, "device_model", &input.device_model);
    out.push(',');
    push_json_str(&mut out, "firmware_version", &input.firmware_version);
    out.push(',');
    push_json_str(
        &mut out,
        "integration_manifest_schema",
        CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION,
    );
    out.push_str(",\"steps\":[");
    for (idx, step) in CERTIFICATION_WIZARD_STEPS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", step.id);
        out.push(',');
        push_json_str(&mut out, "title", step.title);
        out.push(',');
        push_json_str(&mut out, "purpose", step.purpose);
        out.push(',');
        push_json_str(&mut out, "user_action", step.user_action);
        out.push_str(",\"generated_artifacts\":[");
        for (artifact_idx, artifact) in step.generated_artifacts.iter().enumerate() {
            if artifact_idx > 0 {
                out.push(',');
            }
            push_json_string(&mut out, artifact);
        }
        out.push_str("]}");
    }
    out.push_str("],\"external_open_issues\":[");
    for (idx, requirement) in certification_evidence_requirements().iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", requirement.open_issue);
        out.push(',');
        push_json_str(&mut out, "area", requirement.area);
        out.push(',');
        push_json_str(
            &mut out,
            "required_attachment",
            requirement.required_attachment,
        );
        out.push('}');
    }
    out.push_str("],\"boundary\":");
    push_json_string(
        &mut out,
        "wizard creates a candidate workspace and data bundle; external authorities still decide certification acceptance",
    );
    out.push_str("}\n");
    out
}

pub fn certification_wizard_plan_markdown(input: &CertificationWizardInput) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Wizard Plan");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Product: {} {}",
        input.product_name, input.product_version
    );
    let _ = writeln!(out, "- Target: {}", input.certification_target);
    let _ = writeln!(out, "- Interfaces: {}", input.interfaces);
    let _ = writeln!(out, "- Schemes: {}", input.schemes);
    let _ = writeln!(
        out,
        "- Device: {} / {}",
        input.device_model, input.firmware_version
    );
    let _ = writeln!(
        out,
        "- Manifest schema: `{}`",
        CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "This wizard prepares a certifiable-kernel candidate workspace. It does not grant EMVCo, scheme, acquirer, device, PCI/PED, or lab approval.");
    let _ = writeln!(out);
    let _ = writeln!(out, "## Wizard Steps");
    let _ = writeln!(
        out,
        "| Step | Purpose | Generated Artifacts | User Action |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for step in CERTIFICATION_WIZARD_STEPS {
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | {} |",
            step.title,
            step.purpose,
            step.generated_artifacts.join("`, `"),
            step.user_action
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## External Evidence Still Required");
    let _ = writeln!(out, "| Gate | Area | Required Attachment |");
    let _ = writeln!(out, "| --- | --- | --- |");
    for requirement in certification_evidence_requirements() {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} |",
            requirement.open_issue, requirement.area, requirement.required_attachment
        );
    }
    out
}

fn certification_wizard_commands_markdown(dir: &Path) -> String {
    let root = path_for_markdown(dir);
    let bundle = format!("{root}/bundle/certification_bundle.json");
    let anchors = format!("{root}/bundle/trust_anchors.json");
    let artifacts = format!("{root}/artifacts");
    format!(
        "# Hyperion Certification Wizard Commands\n\nRun these after reviewing `wizard_plan.md` and replacing pending fixture values with authority data.\n\n```sh\ncargo test\ncargo test --examples\ncargo clippy --all-targets --all-features -- -D warnings\nscripts/coverage_100.sh\ncargo run --quiet --example krn_certification_bundle -- --validate --bundle {bundle} --trust-anchors {anchors} --mode certification\ncargo run --quiet --example krn_certification_bundle -- --lint --bundle {bundle} --trust-anchors {anchors} --mode certification\ncargo run --quiet --example krn_certification_artifact_import -- --root {artifacts}\ncargo run --quiet --example krn_certification_artifact_import -- --integration-root {artifacts}\ncargo run --quiet --example krn_certification_artifact_import -- --release-freeze-root {artifacts}\ncargo run --quiet --example krn_certification_workspace -- --out {root}/report-workspace\n```\n\nTreat every failure, rejected file, placeholder, empty vector set, and pending external gate as blocking for certification-facing release.\n"
    )
}

fn certification_wizard_next_steps_markdown(input: &CertificationWizardInput) -> String {
    format!(
        "# Hyperion Certification Wizard Next Steps\n\n1. Review the generated bundle for `{}` and confirm the claimed interfaces `{}`.\n2. Replace pending scheme profile, CAPK, vector, C-8, device/L1, PCI/PED, and approval references with accepted authority data.\n3. Place real files under `artifacts/lab`, `artifacts/scheme`, `artifacts/capk`, `artifacts/vectors`, `artifacts/device`, and `artifacts/reports`.\n4. Fill `artifacts/integration_manifest.template.json` and save reviewed copies as `{}` files when the importer needs explicit field mappings.\n5. Run every command in `commands.md`.\n6. Freeze only the exact binary, bundle, profile, trace, coverage, static/fuzz, and approval hashes that will be submitted.\n7. Keep `CERT-OPEN-*` gates open until external acceptance artifacts are attached and independently reviewed.\n",
        input.certification_target,
        input.interfaces,
        CERTIFICATION_INTEGRATION_MANIFEST_FILE
    )
}

fn certification_wizard_readme(input: &CertificationWizardInput) -> String {
    format!(
        "# Hyperion Certification Wizard Workspace\n\nThis workspace prepares `{}` for a certifiable Hyperion EMV kernel candidate.\n\nOpen `wizard_plan.md` first, then `bundle/index.html`. Stage external artifacts under `artifacts/`, run the commands in `commands.md`, and use `next_steps.md` before any submission freeze.\n\nBoundary: this wizard creates a candidate workspace and data bundle using Hyperion code. It does not create external approval, lab execution, scheme/acquirer acceptance, device/L1 approval, PCI/PED evidence, or a signed final conformance template.\n",
        input.product_name
    )
}

fn artifact_lane_readme(adapter_id: &str, title: &str) -> String {
    format!(
        "# {title}\n\nAdapter lane: `{adapter_id}`.\n\nPlace only reviewed public certification artifacts here. Private keys, clear PIN material, unmasked PAN/track data, and unrelated production secrets do not belong in this workspace. If a real authority format does not match the default importer, describe its normalized mapping in `{}`.\n",
        CERTIFICATION_INTEGRATION_MANIFEST_FILE
    )
}

fn integration_manifest_template(input: &CertificationWizardInput) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(
        out,
        "  \"schema_version\": \"{}\",",
        CERTIFICATION_INTEGRATION_MANIFEST_SCHEMA_VERSION
    );
    let _ = writeln!(
        out,
        "  \"manifest_id\": \"{}.authority-mapping\",",
        sanitize_json_identifier(&input.bundle_id)
    );
    let _ = writeln!(
        out,
        "  \"authority\": \"{}\",",
        input.authorities.replace('"', "'")
    );
    out.push_str("  \"artifacts\": [\n");
    out.push_str("    {\n");
    out.push_str("      \"path\": \"scheme/profile.json\",\n");
    out.push_str("      \"adapter_id\": \"SCHEME-PROFILE\",\n");
    out.push_str("      \"artifact_id\": \"scheme_profile_set_json\",\n");
    out.push_str("      \"artifact_kind\": \"scheme-profile\",\n");
    out.push_str("      \"binds_open_issues\": [\"CERT-OPEN-002\", \"CERT-OPEN-005\"],\n");
    out.push_str("      \"bundle_field\": \"payload.scheme_profile_set_json\",\n");
    out.push_str("      \"freeze_artifact_id\": \"scheme_profile_hash\",\n");
    out.push_str("      \"expected_sha256_hex\": \"replace_with_64_hex_sha256_after_review\",\n");
    out.push_str("      \"metadata\": [\"authority\", \"retrieval_date\", \"profile_version\", \"signature_status\"]\n");
    out.push_str("    }\n");
    out.push_str(
        "  ]\n}
",
    );
    out
}

fn default_vector_bundle(input: &CertificationWizardInput) -> String {
    format!(
        "{{\"schema_version\":\"hyperion-vector-bundle-1.0\",\"vector_class\":\"{}\",\"source_artifacts\":[{{\"path\":\"docs/oda_test_vectors.json\",\"sha256\":\"{}\"}}],\"cases\":[]}}",
        input.vector_class,
        to_hex(&sha256(DEFAULT_VECTORS.as_bytes()))
    )
}

fn path_for_markdown(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn sanitize_json_identifier(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn push_csv_json_array(out: &mut String, csv: &str) {
    let mut wrote = false;
    for item in csv
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if wrote {
            out.push(',');
        }
        wrote = true;
        push_json_string(out, item);
    }
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
    fn wizard_writes_certification_candidate_workspace() {
        let root = temp_root("hyperion-cert-wizard");
        let _ = fs::remove_dir_all(&root);
        let input = CertificationWizardInput {
            product_name: "Merchant Kernel".to_string(),
            certification_target: "contactless-c8-pilot".to_string(),
            device_model: "reader-42".to_string(),
            firmware_version: "fw-7".to_string(),
            ..CertificationWizardInput::default()
        };
        let output = write_certification_wizard_workspace(&root, &input).unwrap();
        assert!(output.bundle_path.is_file());
        assert!(output.trust_anchors_path.is_file());
        assert!(output.workbench_path.is_file());
        assert!(output.artifact_root.join("scheme/README.md").is_file());
        assert!(output.artifact_root.join("reports/README.md").is_file());
        assert!(output
            .artifact_root
            .join("integration_manifest.template.json")
            .is_file());
        let bundle = fs::read_to_string(&output.bundle_path).unwrap();
        let anchors = fs::read_to_string(&output.trust_anchors_path).unwrap();
        let plan = fs::read_to_string(&output.plan_json_path).unwrap();
        let markdown = fs::read_to_string(&output.plan_markdown_path).unwrap();
        let commands = fs::read_to_string(&output.commands_path).unwrap();
        let next = fs::read_to_string(&output.next_steps_path).unwrap();
        assert!(bundle.contains("Merchant Kernel"));
        assert!(!bundle.contains(&input.signing_private_key_hex));
        assert!(!anchors.contains(&input.signing_private_key_hex));
        assert!(plan.contains("hyperion-certification-wizard-plan"));
        assert!(plan.contains("CERT-OPEN-001"));
        assert!(markdown.contains("Wizard Steps"));
        assert!(commands.contains("--release-freeze-root"));
        assert!(next.contains(CERTIFICATION_INTEGRATION_MANIFEST_FILE));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wizard_serializers_escape_and_cover_empty_csv() {
        let input = CertificationWizardInput {
            bundle_id: "bundle with spaces".to_string(),
            product_name: "Kernel \"A\"".to_string(),
            interfaces: String::new(),
            ..CertificationWizardInput::default()
        };
        let json = certification_wizard_plan_json(&input);
        let markdown = certification_wizard_plan_markdown(&input);
        let template = integration_manifest_template(&input);
        assert!(json.contains("Kernel \\\"A\\\""));
        assert!(json.contains("\"interfaces\":[]"));
        assert!(markdown.contains("Kernel \"A\""));
        assert!(template.contains("bundle-with-spaces.authority-mapping"));
        let mut escaped = String::new();
        push_json_string(&mut escaped, "line\ncarriage\r\ttab\\slash\u{00ff}");
        assert_eq!(
            escaped,
            "\"line\\ncarriage\\r\\ttab\\\\slash\\u00c3\\u00bf\""
        );
    }

    #[test]
    fn wizard_reports_workspace_write_failures() {
        let blockers = [
            format!(
                "artifacts/{}/README.md",
                ARTIFACT_ADAPTER_SPECS[0].input_dir
            ),
            "bundle/index.html".to_string(),
            "bundle/certification_bundle_lint.json".to_string(),
            "bundle/certification_bundle_lint.md".to_string(),
            "artifacts/integration_manifest.template.json".to_string(),
            "wizard_plan.md".to_string(),
            "next_steps.md".to_string(),
        ];
        for (idx, blocker) in blockers.iter().enumerate() {
            let root = temp_root(&format!("hyperion-cert-wizard-blocked-{idx}"));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join(blocker)).unwrap();
            let err =
                write_certification_wizard_workspace(&root, &CertificationWizardInput::default())
                    .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::IsADirectory);
            fs::remove_dir_all(&root).unwrap();
        }
    }

    fn temp_root(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!("{prefix}-{}", process::id()))
    }
}
