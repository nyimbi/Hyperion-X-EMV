pub const CONFORMANCE_STATUS: &str = "engineering-baseline-pending-licensed-review";
pub const NORMATIVE_HIERARCHY: &str = "licensed_external_standards_prevail";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormativeReference {
    pub id: &'static str,
    pub title: &'static str,
    pub role: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityReadiness {
    pub id: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    pub rationale: &'static str,
    pub open_issues: &'static [&'static str],
    pub repository_evidence: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceStatement {
    pub kernel_name: &'static str,
    pub kernel_version: &'static str,
    pub abi_version: u32,
    pub status: &'static str,
    pub normative_hierarchy: &'static str,
    pub generated_from: &'static [&'static str],
    pub references: &'static [NormativeReference],
    pub capability_readiness: &'static [CapabilityReadiness],
    pub certification_conditions: &'static [&'static str],
}

pub const BASELINE_REFERENCES: &[NormativeReference] = &[
    NormativeReference {
        id: "EMV-B1",
        title: "EMV Contact Chip Specification Book 1",
        role: "contact interface baseline",
    },
    NormativeReference {
        id: "EMV-B2",
        title: "EMV Contact Chip Specification Book 2",
        role: "security and key management baseline",
    },
    NormativeReference {
        id: "EMV-B3",
        title: "EMV Contact Chip Specification Book 3",
        role: "transaction lifecycle baseline",
    },
    NormativeReference {
        id: "EMV-B4",
        title: "EMV Contact Chip Specification Book 4",
        role: "terminal and acquirer interface baseline",
    },
    NormativeReference {
        id: "EMV-C8",
        title: "EMV Contactless Kernel Specification Book C-8",
        role: "contactless kernel baseline",
    },
    NormativeReference {
        id: "PCI-PTS-POI",
        title: "PCI PTS POI",
        role: "PED-owned PIN and device security boundary",
    },
    NormativeReference {
        id: "SIGNED-SCHEME-PROFILES",
        title: "Signed scheme and acquirer profile bundle",
        role: "AID, CAPK, TAC, IAC, CVM, and limit inputs",
    },
    NormativeReference {
        id: "LAB-TEST-PLANS",
        title: "EMVCo, scheme, acquirer, and laboratory test plans",
        role: "certification acceptance criteria",
    },
];

pub const CAPABILITY_READINESS: &[CapabilityReadiness] = &[
    CapabilityReadiness {
        id: "CAP-CVM-PIN",
        title: "CVM evaluation and PED-owned PIN paths",
        status: "implemented-standard-validation-pending",
        rationale: "CVM list evaluation, offline PIN VERIFY handling, online PIN no-custody behavior, and CVM Results are implemented and tested, but final certification depends on licensed EMV Book 3, PCI/PED, scheme profile, and device evidence reconciliation.",
        open_issues: &["CERT-OPEN-007", "CERT-OPEN-009"],
        repository_evidence: &[
            "cvm::tests::offline_pin_requires_ped_owned_opaque_handle",
            "cvm::tests::parses_cvm_list_amounts_and_certified_method_codes",
            "traceability_foundation::krn_cvm_001_002_003_and_sec_004_use_cvm_table_without_clear_pin",
        ],
    },
    CapabilityReadiness {
        id: "CAP-TRM-TAA",
        title: "Terminal risk management and terminal action analysis",
        status: "implemented-standard-validation-pending",
        rationale: "Floor-limit, random-selection, velocity, TAC/IAC, and deterministic fallback logic are implemented from signed profile inputs, but final behavior must be reconciled against accepted scheme/acquirer profiles and lab cases.",
        open_issues: &["CERT-OPEN-002", "CERT-OPEN-009"],
        repository_evidence: &[
            "trm::tests::random_selection_requires_external_sample_when_profile_enables_it",
            "taa::tests::iac_values_participate_in_denial_online_and_default_decisions",
            "traceability_foundation::krn_taa_001_002_003_004_005_006_007_uses_iac_tac_order_and_profile_fallbacks",
        ],
    },
    CapabilityReadiness {
        id: "CAP-ODA-CDA",
        title: "Offline data authentication including SDA, DDA, and CDA",
        status: "implemented-standard-validation-pending",
        rationale: "ODA certificate recovery, SDA, DDA, and CDA verification paths are implemented with structural vectors and profile-gated controls, but final certification requires accepted CAPKs, signed profiles, and lab-supplied ODA vectors.",
        open_issues: &[
            "CERT-OPEN-003",
            "CERT-OPEN-004",
            "CERT-OPEN-009",
            "CERT-OPEN-012",
        ],
        repository_evidence: &[
            "oda::tests::recovers_parses_and_verifies_public_key_certificates",
            "oda::tests::recovers_parses_and_verifies_signed_application_data",
            "traceability_foundation::krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode",
        ],
    },
    CapabilityReadiness {
        id: "CAP-ISSUER-SCRIPTS",
        title: "Issuer authentication and issuer script processing",
        status: "implemented-standard-validation-pending",
        rationale: "Issuer authentication data, script template parsing, phase-specific execution, status-word capture, and result reporting are implemented, but accepted integration reports and full masked APDU trace packs remain external.",
        open_issues: &["CERT-OPEN-009", "CERT-OPEN-012"],
        repository_evidence: &[
            "issuer::tests::parses_arpc_arc_and_issuer_scripts",
            "ffi::tests::critical_issuer_script_failure_before_final_sets_before_final_tvr_and_stops",
            "traceability_foundation::rtm_promotes_issuer_script_evidence",
        ],
    },
    CapabilityReadiness {
        id: "CAP-C8-CONTACTLESS",
        title: "Contactless C-8 outcome, limits, CDCVM, and relay-resistance controls",
        status: "implemented-standard-validation-pending",
        rationale: "Contactless entry, C-8 outcome records, CTQ/CDCVM handling, profile-defined limits, and relay-resistance controls are implemented as profile-driven behavior, but final claims require the lab-selected C-8 version, bulletin set, device/L1 evidence, and trace package.",
        open_issues: &[
            "CERT-OPEN-005",
            "CERT-OPEN-006",
            "CERT-OPEN-009",
            "CERT-OPEN-012",
        ],
        repository_evidence: &[
            "c8::tests::outcome_model_preserves_structured_records_for_callback",
            "ffi::tests::contactless_limit_processing_uses_profile_limits_and_ctq_cdcvm",
            "traceability_foundation::krn_c8_001_002_003_uses_structured_contactless_only_outcomes",
        ],
    },
];

const GENERATED_FROM: &[&str] = &[
    "docs/spec.md",
    "docs/requirements_traceability.csv",
    "docs/requirements-traceability-matrix.csv",
    "docs/lab_submission_manifest.md",
    "docs/certification_open_issues.md",
    "docs/standards_watch.md",
    "docs/tlv_catalogue.csv",
    "docs/state_machine.csv",
    "docs/bitmap_catalogue.csv",
    "docs/performance_profile.csv",
    "docs/scheme_profiles.cert.json",
    "docs/scheme_profile_dictionary.md",
    "docs/oda_test_vectors.json",
    "docs/prelab_apdu_trace_pack.jsonl",
    "docs/prelab_quality_gates.json",
    "docs/prelab_no_crash_smoke.json",
    "docs/prelab_static_fuzz_plan.json",
    "docs/prelab_fuzz_seed_corpus.json",
    "docs/public_standards_watch.json",
    "docs/certification_evidence_checklist.json",
    "docs/certification_evidence_checklist.md",
    "docs/certification_evidence_intake.json",
    "docs/certification_evidence_intake.md",
    "docs/certification_freeze_manifest.json",
    "docs/certification_freeze_manifest.md",
    "docs/certification_security_assessment_plan.json",
    "docs/certification_security_assessment_plan.md",
    "docs/certification_device_evidence_plan.json",
    "docs/certification_device_evidence_plan.md",
    "docs/certification_integration_report_plan.json",
    "docs/certification_integration_report_plan.md",
    "docs/certification_report_pack.json",
    "docs/certification_report_pack.md",
    "docs/certification_report_ui.html",
];

const CERTIFICATION_CONDITIONS: &[&str] = &[
    "This artifact is not a substitute for licensed EMVCo, scheme, acquirer, PCI PTS, or laboratory documents.",
    "Licensed external standards prevail over docs/spec.md and annexes on conflict.",
    "docs/oda_test_vectors.json is a structural fixture annex unless vector_class is CERTIFICATION.",
    "docs/certification_open_issues.md remains the controlling register for external blockers.",
    "docs/standards_watch.md records public standards drift but does not replace licensed review.",
    "Capability readiness entries marked implemented-standard-validation-pending are executable repository behavior, not final certification approval.",
    "Repository ABI JSON does not close CERT-OPEN-011 signed EMVCo/lab conformance template requirement.",
    "Production certification requires signed configuration, scheme profiles, CAPKs, traces, and lab approval.",
];

pub fn baseline_conformance_statement(abi_version: u32) -> ConformanceStatement {
    ConformanceStatement {
        kernel_name: "Hyperion EMV Level 2 Kernel",
        kernel_version: env!("CARGO_PKG_VERSION"),
        abi_version,
        status: CONFORMANCE_STATUS,
        normative_hierarchy: NORMATIVE_HIERARCHY,
        generated_from: GENERATED_FROM,
        references: BASELINE_REFERENCES,
        capability_readiness: CAPABILITY_READINESS,
        certification_conditions: CERTIFICATION_CONDITIONS,
    }
}

impl ConformanceStatement {
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        out.push('{');
        push_json_str(&mut out, "type", "conformance-statement");
        out.push(',');
        push_json_str(&mut out, "kernel_name", self.kernel_name);
        out.push(',');
        push_json_str(&mut out, "kernel_version", self.kernel_version);
        out.push(',');
        push_json_u32(&mut out, "abi_version", self.abi_version);
        out.push(',');
        push_json_str(&mut out, "status", self.status);
        out.push(',');
        push_json_str(&mut out, "normative_hierarchy", self.normative_hierarchy);
        out.push(',');
        push_json_str_array(&mut out, "generated_from", self.generated_from);
        out.push(',');
        push_references(&mut out, self.references);
        out.push(',');
        push_capability_readiness(&mut out, self.capability_readiness);
        out.push(',');
        push_json_str_array(
            &mut out,
            "certification_conditions",
            self.certification_conditions,
        );
        out.push('}');
        out
    }
}

fn push_references(out: &mut String, references: &[NormativeReference]) {
    push_json_key(out, "references");
    out.push('[');
    for (index, reference) in references.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(out, "id", reference.id);
        out.push(',');
        push_json_str(out, "title", reference.title);
        out.push(',');
        push_json_str(out, "role", reference.role);
        out.push('}');
    }
    out.push(']');
}

fn push_capability_readiness(out: &mut String, capabilities: &[CapabilityReadiness]) {
    push_json_key(out, "capability_readiness");
    out.push('[');
    for (index, capability) in capabilities.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(out, "id", capability.id);
        out.push(',');
        push_json_str(out, "title", capability.title);
        out.push(',');
        push_json_str(out, "status", capability.status);
        out.push(',');
        push_json_str(out, "rationale", capability.rationale);
        out.push(',');
        push_json_str_array(out, "open_issues", capability.open_issues);
        out.push(',');
        push_json_str_array(out, "repository_evidence", capability.repository_evidence);
        out.push('}');
    }
    out.push(']');
}

fn push_json_str_array(out: &mut String, key: &str, values: &[&str]) {
    push_json_key(out, key);
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(out, value);
    }
    out.push(']');
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_u32(out: &mut String, key: &str, value: u32) {
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
    fn conformance_statement_json_is_deterministic_and_scoped() {
        let statement = baseline_conformance_statement(7);
        let first = statement.canonical_json();
        let second = statement.canonical_json();

        assert_eq!(first, second);
        assert!(first.contains("\"type\":\"conformance-statement\""));
        assert!(first.contains("\"abi_version\":7"));
        assert!(first.contains("\"status\":\"engineering-baseline-pending-licensed-review\""));
        assert!(first.contains("\"normative_hierarchy\":\"licensed_external_standards_prevail\""));
        assert!(first.contains("\"capability_readiness\""));
        assert!(first.contains("implemented-standard-validation-pending"));
        assert!(first.contains("CAP-CVM-PIN"));
        assert!(first.contains("CAP-TRM-TAA"));
        assert!(first.contains("CAP-ODA-CDA"));
        assert!(first.contains("CAP-ISSUER-SCRIPTS"));
        assert!(first.contains("CAP-C8-CONTACTLESS"));
        assert!(first.contains(
            "Capability readiness entries marked implemented-standard-validation-pending"
        ));
        assert!(!first.contains("\"certified\":true"));
        for reference in [
            "EMV-B1",
            "EMV-B2",
            "EMV-B3",
            "EMV-B4",
            "EMV-C8",
            "PCI-PTS-POI",
            "SIGNED-SCHEME-PROFILES",
            "LAB-TEST-PLANS",
        ] {
            assert!(first.contains(reference), "missing reference {reference}");
        }
    }
}
