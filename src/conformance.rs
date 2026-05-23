pub const CONFORMANCE_STATUS: &str = "engineering-baseline-pending-licensed-review";
pub const NORMATIVE_HIERARCHY: &str = "licensed_external_standards_prevail";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormativeReference {
    pub id: &'static str,
    pub title: &'static str,
    pub role: &'static str,
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
];

const CERTIFICATION_CONDITIONS: &[&str] = &[
    "This artifact is not a substitute for licensed EMVCo, scheme, acquirer, PCI PTS, or laboratory documents.",
    "Licensed external standards prevail over docs/spec.md and annexes on conflict.",
    "docs/oda_test_vectors.json is a structural fixture annex unless vector_class is CERTIFICATION.",
    "docs/certification_open_issues.md remains the controlling register for external blockers.",
    "docs/standards_watch.md records public standards drift but does not replace licensed review.",
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
