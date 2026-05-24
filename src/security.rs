//! Third-party security assessment plan generation.
//!
//! The generated plan is an assessor-facing checklist for `CERT-OPEN-008`.
//! It binds repository-controlled security controls to the external penetration
//! test and architecture review evidence that still must be attached before a
//! certification-facing release can claim the blocker is closed.

use core::fmt::Write;

pub struct SecurityAssessmentControl {
    pub id: &'static str,
    pub surface: &'static str,
    pub threat: &'static str,
    pub repository_evidence: &'static [&'static str],
    pub assessor_evidence_required: &'static str,
    pub acceptance_gate: &'static str,
}

pub struct SecurityAssessmentMetadata {
    pub field: &'static str,
    pub requirement: &'static str,
}

const ASSESSMENT_METADATA: &[SecurityAssessmentMetadata] = &[
    SecurityAssessmentMetadata {
        field: "source_commit",
        requirement: "exact git commit and build manifest hash under review",
    },
    SecurityAssessmentMetadata {
        field: "submitted_binary_hash",
        requirement: "SHA-256 of the assessed kernel binary",
    },
    SecurityAssessmentMetadata {
        field: "profile_bundle_hash",
        requirement: "SHA-256 of the signed profile and CAPK bundle used during testing",
    },
    SecurityAssessmentMetadata {
        field: "target_device_scope",
        requirement: "terminal model, firmware, reader interface, and PED boundary assessed",
    },
    SecurityAssessmentMetadata {
        field: "assessor_identity",
        requirement: "organization, reviewer, report date, and accepted assessment method",
    },
    SecurityAssessmentMetadata {
        field: "finding_disposition",
        requirement: "critical/high findings remediated or formally accepted with retest evidence",
    },
];

const SECURITY_CONTROLS: &[SecurityAssessmentControl] = &[
    SecurityAssessmentControl {
        id: "SEC-ASSESS-APDU-INJECTION",
        surface: "APDU replay and command construction",
        threat: "malformed or out-of-sequence APDUs bypass transaction state or parser bounds",
        repository_evidence: &[
            "trace::tests::replay_rejects_structurally_invalid_command_apdus",
            "trace::tests::replay_rejects_apdu_payloads_above_max_bytes",
            "ffi::tests::transmit_apdu_followups_rejects_chains_above_limit",
            "traceability_foundation::krn_cert_004_penetration_rejects_apdu_injection_and_state_bypass",
        ],
        assessor_evidence_required:
            "penetration-test cases for malformed CLA/INS/P1/P2/Lc/Le, chained follow-up loops, and replay-order manipulation",
        acceptance_gate:
            "no APDU injection path may skip mandatory state transitions, expose sensitive values, or panic",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-FSM-BYPASS",
        surface: "transaction finite-state machine",
        threat: "host, card, or callback behavior forces issuer auth, scripts, final GAC, or outcome handling out of order",
        repository_evidence: &[
            "fsm::tests::rejects_state_machine_annex_schema_and_semantic_drift",
            "fsm::tests::asynchronous_failures_are_explicit_error_transitions",
            "ffi::tests::krn_api_004_rejects_reentrant_mutating_entrypoints",
            "traceability_foundation::rtm_promotes_fsm_annex_replay_and_error_transition_evidence",
        ],
        assessor_evidence_required:
            "architecture review and negative tests for illegal callback ordering, reentrancy, timeout, retry, and host-response sequencing",
        acceptance_gate:
            "all invalid state transitions must fail closed with stable errors and no partial outcome claim",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-TRACE-LEAKAGE",
        surface: "trace, debug, and report output",
        threat: "PAN, Track 2, issuer scripts, cryptograms, PIN handles, or recovered key material leak through logs",
        repository_evidence: &[
            "trace::tests::production_policy_never_emits_full_apdu_data_even_if_misconfigured",
            "trace::tests::production_suppresses_transaction_cryptograms",
            "trace::tests::production_suppresses_issuer_script_command_data",
            "record::tests::summarizes_track2_equivalent_data_without_exposing_pan",
            "oda::tests::oda_debug_redacts_recovered_authentication_material",
        ],
        assessor_evidence_required:
            "log-scraping review across success, decline, parser-failure, issuer-script, ODA, and crash-safety paths",
        acceptance_gate:
            "production traces and debug output must contain only masked or structural values for sensitive data",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-PROFILE-TAMPERING",
        surface: "signed profile and CAPK loading",
        threat: "rollback, unsigned profile, expired CAPK, checksum drift, or placeholder data enters certification mode",
        repository_evidence: &[
            "config::tests::rejects_unsigned_certification_profile_rollback_and_replay",
            "config::tests::rejects_certification_capk_checksum_mismatch_or_metadata_drift",
            "config::tests::rejects_example_profile_in_certification_or_production_mode",
            "traceability_foundation::profile_loader_rejects_rollback_placeholders_and_expired_capks",
        ],
        assessor_evidence_required:
            "tamper tests for profile signature status, rollback counter, CAPK checksum, expiry, material status, and RID/AID boundaries",
        acceptance_gate:
            "certification and production policies must reject tampered, stale, unsigned, placeholder, or out-of-scope profile material",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-PIN-CUSTODY",
        surface: "CVM and PED boundary",
        threat: "kernel receives, stores, logs, or derives clear PIN material instead of opaque PED handles",
        repository_evidence: &[
            "cvm::tests::offline_pin_requires_ped_owned_opaque_handle",
            "cvm::tests::offline_pin_debug_redacts_ped_handle_values",
            "trace::tests::replay_rejects_pin_verify_payload_custody",
            "traceability_foundation::krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles",
        ],
        assessor_evidence_required:
            "PED integration review proving VERIFY and online PIN custody remain outside kernel memory and logs",
        acceptance_gate:
            "kernel interfaces may pass only opaque PIN handles and status words, never clear PIN blocks or PIN digits",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-ODA-MATERIAL",
        surface: "ODA certificate recovery and cryptographic material",
        threat: "recovered public-key material, SDAD content, or issuer authentication data is logged or accepted without profile provenance",
        repository_evidence: &[
            "oda::tests::capk_lookup_requires_verified_integrity_and_unexpired_key",
            "oda::tests::rejects_public_key_material_above_resource_limits",
            "ffi::tests::runtime_cda_failure_sets_tvr_without_falling_back_to_dda",
            "traceability_foundation::krn_sec_003_oda_002_capks_retain_signed_public_provenance",
        ],
        assessor_evidence_required:
            "review of ODA error handling, material redaction, CAPK provenance, and CDA fail-closed behavior",
        acceptance_gate:
            "ODA failures must set TVR/TSI evidence without exposing recovered material or silently weakening authentication method",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-ISSUER-SCRIPTS",
        surface: "issuer authentication and issuer script processing",
        threat: "issuer scripts execute across the wrong phase, hide failed critical commands, or leak script command payloads",
        repository_evidence: &[
            "issuer::tests::rejects_malformed_issuer_script_command_apdus",
            "ffi::tests::critical_issuer_script_failure_stops_remaining_commands",
            "ffi::tests::issuer_script_result_metadata_api_reports_phase_position_and_identifier",
            "trace::tests::production_suppresses_issuer_script_command_data",
        ],
        assessor_evidence_required:
            "negative tests for tag 71/tag 72 phase separation, critical command failure, retry status handling, and redacted result reporting",
        acceptance_gate:
            "script execution order and result reporting must be phase-aware, bounded, redacted, and fail closed on critical command failure",
    },
    SecurityAssessmentControl {
        id: "SEC-ASSESS-REPORT-INTEGRITY",
        surface: "certification evidence and report workbench",
        threat: "repository-generated evidence is mistaken for external approval or attached to the wrong submitted build",
        repository_evidence: &[
            "reporting::tests::report_pack_json_lists_artifacts_reports_and_tools_without_approval_claims",
            "freeze::tests::freeze_manifest_tracks_hash_slots_without_certification_claims",
            "traceability_foundation::certification_freeze_manifest_is_reproducible_and_scoped",
            "traceability_foundation::certification_report_workbench_is_reproducible_and_scoped",
        ],
        assessor_evidence_required:
            "report-package review proving submitted-build hashes, finding disposition, and external approval attachments align",
        acceptance_gate:
            "repository artifacts may support assessment but must not claim certification, approval, or closure of external gates",
    },
];

pub fn certification_security_assessment_plan_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-security-assessment-plan");
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
        "third-party security assessment plan for CERT-OPEN-008",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_string(&mut out, "CERT-OPEN-008");
    out.push(']');
    out.push_str(",\"required_report_metadata\":[");
    for (idx, metadata) in ASSESSMENT_METADATA.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "field", metadata.field);
        out.push(',');
        push_json_str(&mut out, "requirement", metadata.requirement);
        out.push('}');
    }
    out.push_str("],\"controls\":[");
    for (idx, control) in SECURITY_CONTROLS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_control_json(&mut out, control);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_security_assessment_plan_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Security Assessment Plan");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-23");
    let _ = writeln!(
        out,
        "- Scope: third-party security assessment plan for `CERT-OPEN-008`"
    );
    let _ = writeln!(
        out,
        "- Boundary: this plan does not close `CERT-OPEN-008`; an accepted external assessment report is still required."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Report Metadata");
    let _ = writeln!(out, "| Field | Requirement |");
    let _ = writeln!(out, "| --- | --- |");
    for metadata in ASSESSMENT_METADATA {
        let _ = writeln!(out, "| {} | {} |", metadata.field, metadata.requirement);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Assessment Controls");
    let _ = writeln!(
        out,
        "| ID | Surface | Threat | Repository Evidence | Assessor Evidence Required | Acceptance Gate |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
    for control in SECURITY_CONTROLS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            control.id,
            control.surface,
            control.threat,
            control.repository_evidence.join(", "),
            control.assessor_evidence_required,
            control.acceptance_gate,
        );
    }
    out
}

fn push_control_json(out: &mut String, control: &SecurityAssessmentControl) {
    out.push('{');
    push_json_str(out, "id", control.id);
    out.push(',');
    push_json_str(out, "surface", control.surface);
    out.push(',');
    push_json_str(out, "threat", control.threat);
    out.push_str(",\"repository_evidence\":[");
    push_json_array_values(out, control.repository_evidence);
    out.push_str("],");
    push_json_str(
        out,
        "assessor_evidence_required",
        control.assessor_evidence_required,
    );
    out.push(',');
    push_json_str(out, "acceptance_gate", control.acceptance_gate);
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
    fn security_assessment_plan_tracks_controls_without_closure_claims() {
        let json = certification_security_assessment_plan_json(2);
        let markdown = certification_security_assessment_plan_markdown(2);

        assert!(json.contains("\"type\":\"certification-security-assessment-plan\""));
        assert!(json.contains("\"SEC-ASSESS-APDU-INJECTION\""));
        assert!(json.contains("\"SEC-ASSESS-FSM-BYPASS\""));
        assert!(json.contains("\"SEC-ASSESS-TRACE-LEAKAGE\""));
        assert!(json.contains("\"SEC-ASSESS-PROFILE-TAMPERING\""));
        assert!(json.contains("\"source_commit\""));
        assert!(json.contains("\"CERT-OPEN-008\""));
        assert!(json.contains("does_not_close"));
        assert!(!json.contains("\"certified\":true"));
        assert!(markdown.contains("# Hyperion Certification Security Assessment Plan"));
        assert!(markdown.contains("accepted external assessment report is still required"));
    }
}
