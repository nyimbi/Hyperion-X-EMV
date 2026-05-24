//! Device, Level 1, and PED evidence plan generation.
//!
//! The generated plan is an attachment-control surface for `CERT-OPEN-006`
//! and `CERT-OPEN-007`, with contactless device evidence also linked to
//! `CERT-OPEN-005`. It records what must be supplied by device vendors,
//! Level 1 laboratories, PCI PTS/PED authorities, and integrators before a
//! submitted kernel/profile/device combination can be reviewed.

use core::fmt::Write;

pub struct DeviceEvidenceRequirement {
    pub id: &'static str,
    pub area: &'static str,
    pub open_issues: &'static [&'static str],
    pub authority: &'static str,
    pub required_attachment: &'static str,
    pub required_metadata: &'static [&'static str],
    pub repository_support: &'static [&'static str],
    pub acceptance_gate: &'static str,
}

pub struct DeviceEvidenceMetadata {
    pub field: &'static str,
    pub requirement: &'static str,
}

const DEVICE_EVIDENCE_METADATA: &[DeviceEvidenceMetadata] = &[
    DeviceEvidenceMetadata {
        field: "submitted_binary_hash",
        requirement: "SHA-256 of the exact kernel binary installed on the device",
    },
    DeviceEvidenceMetadata {
        field: "profile_bundle_hash",
        requirement: "SHA-256 of the signed profile, CAPK, and configuration bundle",
    },
    DeviceEvidenceMetadata {
        field: "device_model",
        requirement: "terminal model, hardware revision, serial scope, OS image, and deployment configuration",
    },
    DeviceEvidenceMetadata {
        field: "firmware_version",
        requirement: "terminal firmware, reader firmware, OS image, and PED firmware versions in the submitted scope",
    },
    DeviceEvidenceMetadata {
        field: "l1_approval_reference",
        requirement: "contact and contactless Level 1 approval or accepted vendor/lab evidence reference",
    },
    DeviceEvidenceMetadata {
        field: "pts_listing_or_assessment",
        requirement: "PCI PTS POI listing, PCI-recognized assessment reference, or assessor-accepted equivalent",
    },
    DeviceEvidenceMetadata {
        field: "interface_scope",
        requirement: "claimed contact, contactless, fallback, and excluded interfaces with reason codes",
    },
    DeviceEvidenceMetadata {
        field: "trace_identity",
        requirement: "ABI version, profile version, profile SHA-256, trace-pack hash, device scope, and submitted build scope",
    },
];

const DEVICE_EVIDENCE_REQUIREMENTS: &[DeviceEvidenceRequirement] = &[
    DeviceEvidenceRequirement {
        id: "DEVICE-TARGET-SCOPE",
        area: "target terminal identity",
        open_issues: &["CERT-OPEN-006"],
        authority: "device vendor, integrator, acquirer, and laboratory",
        required_attachment:
            "target terminal bill of materials, firmware inventory, OS image, and deployment configuration statement",
        required_metadata: &[
            "device_model",
            "submitted_binary_hash",
            "profile_bundle_hash",
            "firmware_version",
            "configuration_version",
        ],
        repository_support: &[
            "docs/certification_freeze_manifest.json",
            "examples/krn_build_manifest.rs",
            "krn_get_profile_sha256",
        ],
        acceptance_gate:
            "device identity and firmware scope must match the submitted binary, profile bundle, and lab manifest",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-CONTACT-L1",
        area: "contact interface Level 1 evidence",
        open_issues: &["CERT-OPEN-006"],
        authority: "EMVCo Level 1 laboratory, device vendor, and integrator",
        required_attachment:
            "contact reader L1 approval or accepted vendor/lab evidence tied to firmware and hardware revision",
        required_metadata: &[
            "device_model",
            "l1_approval_reference",
            "firmware_version",
            "validity_dates",
        ],
        repository_support: &[
            "apdu::tests::builds_exact_contact_pse_and_contactless_ppse_selects",
            "ffi::tests::runtime_core_flow_resolves_gpo_record_and_gac_followups",
            "examples/krn_cabi_script_adapter.rs",
        ],
        acceptance_gate:
            "contact reader evidence must name the same device, firmware, binary, and contact interface scope as the submission",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-CONTACTLESS-L1",
        area: "contactless reader and C-8 device evidence",
        open_issues: &["CERT-OPEN-005", "CERT-OPEN-006"],
        authority: "EMVCo contactless approval path, Level 1 laboratory, device vendor, and scheme/acquirer as applicable",
        required_attachment:
            "contactless reader/L1 approval, selected C-8 contactless approval package, NFC firmware, and bulletin reconciliation",
        required_metadata: &[
            "device_model",
            "l1_approval_reference",
            "c8_package_version",
            "bulletin_set",
            "firmware_version",
        ],
        repository_support: &[
            "src/c8.rs",
            "docs/public_standards_watch.json",
            "docs/prelab_apdu_trace_pack.jsonl",
        ],
        acceptance_gate:
            "contactless evidence must match the selected C-8 package, device firmware, reader scope, and masked outcome traces",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-PED-PTS",
        area: "PCI PTS/PED approval evidence",
        open_issues: &["CERT-OPEN-007"],
        authority: "PCI SSC, PCI-recognized laboratory, PED vendor, and security assessor",
        required_attachment:
            "PCI PTS POI listing or accepted assessment evidence plus PED firmware and integration statement",
        required_metadata: &[
            "device_model",
            "pts_listing_or_assessment",
            "firmware_version",
            "pin_entry_mode",
        ],
        repository_support: &[
            "cvm::tests::offline_pin_requires_ped_owned_opaque_handle",
            "trace::tests::replay_rejects_pin_verify_payload_custody",
            "docs/certification_security_assessment_plan.json",
        ],
        acceptance_gate:
            "PED evidence must prove PIN capture and PIN-block custody remain inside the approved PED boundary",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-PIN-CUSTODY",
        area: "opaque PIN handle integration",
        open_issues: &["CERT-OPEN-007"],
        authority: "PED vendor, PCI assessor, and product security reviewer",
        required_attachment:
            "integration review showing offline VERIFY status and online PIN handoff use opaque handles only",
        required_metadata: &[
            "device_model",
            "pin_handle_policy",
            "verify_status_path",
            "online_pin_boundary",
            "trace_redaction_policy",
        ],
        repository_support: &[
            "src/cvm.rs",
            "src/ffi.rs",
            "cvm::tests::offline_pin_debug_redacts_ped_handle_values",
            "traceability_foundation::krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles",
        ],
        acceptance_gate:
            "kernel APIs and traces may expose only opaque handles, VERIFY status words, and CVM results, never clear PIN data",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-INTERFACE-SCOPE",
        area: "interface and fallback scope",
        open_issues: &["CERT-OPEN-005", "CERT-OPEN-006"],
        authority: "laboratory, scheme/acquirer, and integrator",
        required_attachment:
            "claimed interface matrix naming contact, contactless, alternate-interface, fallback, and excluded paths",
        required_metadata: &[
            "interface_scope",
            "aid_set",
            "kernel_mapping",
            "alternate_interface_policy",
            "excluded_interface_reason",
        ],
        repository_support: &[
            "config::tests::rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces",
            "ffi::tests::selected_kernel_mapping_is_interface_specific",
            "c8::tests::outcome_model_bounds_records_and_alternate_interface_instruction",
        ],
        acceptance_gate:
            "claimed interfaces must match signed profile mappings and no excluded interface may be reachable at runtime",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-BUILD-BINDING",
        area: "device-bound trace identity",
        open_issues: &["CERT-OPEN-006", "CERT-OPEN-012"],
        authority: "laboratory, acquirer, and submission owner",
        required_attachment:
            "masked trace pack metadata tying device, firmware, ABI version, profile hash, and submitted binary hash together",
        required_metadata: &[
            "device_model",
            "submitted_binary_hash",
            "profile_bundle_hash",
            "trace_identity",
            "firmware_version",
        ],
        repository_support: &[
            "docs/prelab_apdu_trace_pack.jsonl",
            "trace::tests::replay_trace_identity_records_profile_version_and_hash_without_unmasking_data",
            "ffi::tests::ffi_reports_loaded_profile_version_and_hash_for_log_identity",
        ],
        acceptance_gate:
            "lab traces must be replayable, masked, and bound to the same submitted binary, profile, device, and firmware scope",
    },
    DeviceEvidenceRequirement {
        id: "DEVICE-REPORT-PACKAGE",
        area: "device evidence report package",
        open_issues: &["CERT-OPEN-006", "CERT-OPEN-007"],
        authority: "laboratory, acquirer, device vendor, PED vendor, and submission owner",
        required_attachment:
            "accepted device, L1, PCI/PED, and integration reports tied to the certification freeze manifest",
        required_metadata: &[
            "device_model",
            "firmware_version",
            "submitted_binary_hash",
            "profile_bundle_hash",
            "trace_identity",
        ],
        repository_support: &[
            "docs/certification_report_pack.json",
            "docs/certification_freeze_manifest.json",
            "docs/lab_submission_manifest.md",
        ],
        acceptance_gate:
            "report package must agree with freeze-manifest hashes and leave no unresolved device, L1, or PED evidence mismatch",
    },
];

pub fn certification_device_evidence_plan_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-device-evidence-plan");
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
        "device, Level 1, and PED evidence plan for certification package assembly",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_array_values(
        &mut out,
        &["CERT-OPEN-005", "CERT-OPEN-006", "CERT-OPEN-007"],
    );
    out.push_str("],\"required_metadata\":[");
    for (idx, metadata) in DEVICE_EVIDENCE_METADATA.iter().enumerate() {
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
    for (idx, requirement) in DEVICE_EVIDENCE_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_requirement_json(&mut out, requirement);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_device_evidence_plan_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Device, L1, and PED Evidence Plan");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-24");
    let _ = writeln!(
        out,
        "- Scope: device, Level 1, and PED evidence plan for certification package assembly"
    );
    let _ = writeln!(
        out,
        "- Boundary: this plan does not close `CERT-OPEN-005`, `CERT-OPEN-006`, or `CERT-OPEN-007`; pending external device, L1, and PCI/PED evidence is still required."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Metadata");
    let _ = writeln!(out, "| Field | Requirement |");
    let _ = writeln!(out, "| --- | --- |");
    for metadata in DEVICE_EVIDENCE_METADATA {
        let _ = writeln!(out, "| {} | {} |", metadata.field, metadata.requirement);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence Requirements");
    let _ = writeln!(
        out,
        "| ID | Area | Open Issues | Authority | Required Attachment | Required Metadata | Repository Support | Acceptance Gate |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for requirement in DEVICE_EVIDENCE_REQUIREMENTS {
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

fn push_requirement_json(out: &mut String, requirement: &DeviceEvidenceRequirement) {
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
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_evidence_plan_tracks_device_l1_and_ped_boundaries_without_closure_claims() {
        let json = certification_device_evidence_plan_json(2);
        let markdown = certification_device_evidence_plan_markdown(2);

        assert!(json.contains("\"type\":\"certification-device-evidence-plan\""));
        assert!(json.contains("\"DEVICE-TARGET-SCOPE\""));
        assert!(json.contains("\"DEVICE-CONTACT-L1\""));
        assert!(json.contains("\"DEVICE-CONTACTLESS-L1\""));
        assert!(json.contains("\"DEVICE-PED-PTS\""));
        assert!(json.contains("\"DEVICE-PIN-CUSTODY\""));
        assert!(json.contains("\"DEVICE-BUILD-BINDING\""));
        assert!(json.contains("\"DEVICE-REPORT-PACKAGE\""));
        assert!(json.contains("\"submitted_binary_hash\""));
        assert!(json.contains("\"device_model\""));
        assert!(json.contains("\"l1_approval_reference\""));
        assert!(json.contains("\"pts_listing_or_assessment\""));
        assert!(json.contains("\"CERT-OPEN-006\""));
        assert!(json.contains("\"CERT-OPEN-007\""));
        assert!(json.contains("does_not_close"));
        assert!(!json.contains("\"certified\":true"));
        assert!(markdown.contains("# Hyperion Device, L1, and PED Evidence Plan"));
        assert!(markdown
            .contains("pending external device, L1, and PCI/PED evidence is still required"));
    }
}
