use core::fmt::Write;

struct QualityGate {
    id: &'static str,
    command: &'static str,
    purpose: &'static str,
}

struct FreezeHashRequirement {
    id: &'static str,
    artifact: &'static str,
    evidence_source: &'static str,
}

const QUALITY_GATES: &[QualityGate] = &[
    QualityGate {
        id: "PRELAB-CONFORMANCE",
        command: "cargo run --quiet --example krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json -",
        purpose: "regenerate and compare the ABI conformance statement artifact",
    },
    QualityGate {
        id: "PRELAB-TRACEPACK",
        command: "cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -",
        purpose: "regenerate and compare the masked pre-lab APDU trace fixture",
    },
    QualityGate {
        id: "PRELAB-SCHEME-DICTIONARY",
        command: "cargo run --quiet --example krn_scheme_profile_dictionary | diff -u docs/scheme_profile_dictionary.md -",
        purpose: "regenerate and compare the human-readable scheme profile dictionary",
    },
    QualityGate {
        id: "PRELAB-QUALITY-GATES",
        command: "cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -",
        purpose: "regenerate and compare this pre-lab quality gate manifest",
    },
    QualityGate {
        id: "PRELAB-BUILD-PROVENANCE",
        command: "cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/scheme_profile_dictionary.md docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json docs/certification_open_issues.md docs/standards_watch.md docs/open_source.md examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_cabi_script_adapter.rs examples/krn_scheme_profile_dictionary.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs examples/krn_emv_decode.rs",
        purpose: "emit canonical build provenance for source, controlled annexes, and evidence generators",
    },
    QualityGate {
        id: "PRELAB-UNIT-INTEGRATION",
        command: "cargo test",
        purpose: "run repository unit and integration tests",
    },
    QualityGate {
        id: "PRELAB-EXAMPLES",
        command: "cargo test --examples",
        purpose: "compile and execute example evidence generators",
    },
    QualityGate {
        id: "PRELAB-FORMAT",
        command: "cargo fmt --check",
        purpose: "verify Rust formatting is stable",
    },
    QualityGate {
        id: "PRELAB-STATIC",
        command: "cargo clippy --all-targets --all-features -- -D warnings",
        purpose: "run the repository static-analysis lint gate with warnings as failures",
    },
    QualityGate {
        id: "PRELAB-DIFF",
        command: "git diff --check",
        purpose: "reject whitespace errors in the working tree diff",
    },
];

const EXTERNAL_REPORTS_PENDING: &[&str] = &[
    "Unit coverage report >=95%",
    "Full EMV test-plan integration report",
    "Static-analysis report accepted for the submission context",
    "Fuzzing/no-crash report with tool versions and corpus",
];

const FREEZE_HASH_REQUIREMENTS: &[FreezeHashRequirement] = &[
    FreezeHashRequirement {
        id: "kernel_binary_hash",
        artifact: "submitted kernel binary",
        evidence_source: "release build pipeline artifact digest accepted for the lab submission",
    },
    FreezeHashRequirement {
        id: "config_bundle_hash",
        artifact: "signed runtime configuration bundle",
        evidence_source: "signed configuration package digest tied to the submitted binary",
    },
    FreezeHashRequirement {
        id: "capk_bundle_hash",
        artifact: "scheme/acquirer-approved CAPK bundle",
        evidence_source: "accepted CAPK package digest with signed provenance",
    },
    FreezeHashRequirement {
        id: "scheme_profile_hash",
        artifact: "scheme/acquirer-approved profile bundle",
        evidence_source: "accepted scheme profile package digest with profile authority evidence",
    },
    FreezeHashRequirement {
        id: "test_vector_hash",
        artifact: "lab-supplied ODA and APDU test-vector bundle",
        evidence_source: "recognized-lab vector and trace-pack digest",
    },
    FreezeHashRequirement {
        id: "traceability_matrix_hash",
        artifact: "final RTM and lab/tool crosswalk",
        evidence_source: "final RTM digest after lab test-case ID reconciliation",
    },
];

pub fn prelab_quality_gates_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "prelab-quality-gates");
    out.push(',');
    push_json_str(&mut out, "kernel_name", env!("CARGO_PKG_NAME"));
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "repository-controlled engineering gates only",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_string(&mut out, "CERT-OPEN-009");
    out.push(',');
    push_json_string(&mut out, "CERT-OPEN-010");
    out.push(']');
    out.push_str(",\"commands\":[");
    for (idx, gate) in QUALITY_GATES.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", gate.id);
        out.push(',');
        push_json_str(&mut out, "command", gate.command);
        out.push(',');
        push_json_str(&mut out, "purpose", gate.purpose);
        out.push('}');
    }
    out.push_str("],\"external_reports_pending\":[");
    for (idx, report) in EXTERNAL_REPORTS_PENDING.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, report);
    }
    out.push_str("],\"certification_freeze_hashes_required\":[");
    for (idx, requirement) in FREEZE_HASH_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", requirement.id);
        out.push(',');
        push_json_str(&mut out, "artifact", requirement.artifact);
        out.push(',');
        push_json_str(&mut out, "evidence_source", requirement.evidence_source);
        out.push(',');
        push_json_str(&mut out, "status", "pending external certification freeze");
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    let _ = write!(out, "{value}");
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
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
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
