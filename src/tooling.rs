//! Tooling completeness audit for certification preparation.
//!
//! This module answers a narrow question: whether the repository-controlled
//! tooling and verification mechanisms needed for pre-lab work are present,
//! reproducible, and wired into evidence production. It intentionally does not
//! claim that external certification evidence has been obtained.

use crate::evidence::{certification_evidence_requirements, EvidenceRequirement};
use core::fmt::Write;

pub struct VerificationMechanism {
    pub id: &'static str,
    pub area: &'static str,
    pub purpose: &'static str,
    pub repository_artifacts: &'static [&'static str],
    pub commands: &'static [&'static str],
    pub ci_gate: &'static str,
    pub status: &'static str,
    pub external_closure_gate: &'static str,
}

const DOES_NOT_CLOSE: &[&str] = &[
    "CERT-OPEN-001",
    "CERT-OPEN-002",
    "CERT-OPEN-003",
    "CERT-OPEN-004",
    "CERT-OPEN-005",
    "CERT-OPEN-006",
    "CERT-OPEN-007",
    "CERT-OPEN-008",
    "CERT-OPEN-009",
    "CERT-OPEN-010",
    "CERT-OPEN-011",
    "CERT-OPEN-012",
];

const MECHANISMS: &[VerificationMechanism] = &[
    VerificationMechanism {
        id: "TOOL-UNIT-INTEGRATION",
        area: "runtime behavior",
        purpose: "unit and integration tests for kernel state, APDU, TLV, ODA, CVM, TRM, TAA, issuer, C-8, and FFI behavior",
        repository_artifacts: &["tests/traceability_foundation.rs", ".github/workflows/prelab.yml"],
        commands: &["cargo test"],
        ci_gate: "Unit and integration tests",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-009",
    },
    VerificationMechanism {
        id: "TOOL-EXAMPLE-EVIDENCE",
        area: "evidence generators",
        purpose: "compile and execute deterministic evidence generators and user-facing integration examples",
        repository_artifacts: &["examples/", ".github/workflows/prelab.yml"],
        commands: &["cargo test --examples"],
        ci_gate: "Example evidence generators",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-009",
    },
    VerificationMechanism {
        id: "TOOL-FORMAT-STATIC",
        area: "static quality",
        purpose: "enforce stable formatting, warnings-as-failures static linting, and whitespace cleanliness",
        repository_artifacts: &[".github/workflows/prelab.yml", "docs/prelab_quality_gates.json"],
        commands: &[
            "cargo fmt --check",
            "cargo clippy --all-targets --all-features -- -D warnings",
            "git diff --check",
        ],
        ci_gate: "Format; Static analysis; Whitespace",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-010",
    },
    VerificationMechanism {
        id: "TOOL-COVERAGE",
        area: "coverage",
        purpose: "prepare and audit a 100% coverage package with metadata before external report acceptance",
        repository_artifacts: &[
            "docs/coverage.md",
            "scripts/coverage_100.sh",
            "examples/krn_coverage_package_audit.rs",
        ],
        commands: &[
            "scripts/coverage_100.sh",
            "cargo run --quiet --example krn_coverage_package_audit -- --root target/coverage",
        ],
        ci_gate: "Rust coverage report preparation; Certification coverage package audit smoke",
        status: "repo-prepared-external-acceptance-pending",
        external_closure_gate: "CERT-OPEN-009",
    },
    VerificationMechanism {
        id: "TOOL-TRACE-PACK",
        area: "trace evidence",
        purpose: "generate and audit masked APDU trace fixtures with sensitive tag suppression and replay metadata",
        repository_artifacts: &[
            "docs/prelab_apdu_trace_pack.jsonl",
            "docs/prelab_trace_pack_audit.json",
            "docs/prelab_trace_pack_audit.md",
            "examples/krn_prelab_trace_pack.rs",
            "examples/krn_trace_pack_audit.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -",
            "cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl --require-prelab-fixture | diff -u docs/prelab_trace_pack_audit.json -",
            "cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl --markdown | diff -u docs/prelab_trace_pack_audit.md -",
        ],
        ci_gate: "Pre-lab trace pack drift; Pre-lab trace pack audit drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-012",
    },
    VerificationMechanism {
        id: "TOOL-FUZZ-STATIC-PLAN",
        area: "fuzzing and no-crash",
        purpose: "define static-analysis gates, fuzz surfaces, deterministic seed corpus, and parser/APDU no-crash smoke evidence",
        repository_artifacts: &[
            "docs/prelab_static_fuzz_plan.json",
            "docs/prelab_fuzz_seed_corpus.json",
            "docs/prelab_no_crash_smoke.json",
            "examples/krn_prelab_static_fuzz_plan.rs",
            "examples/krn_prelab_fuzz_seed_corpus.rs",
            "examples/krn_prelab_no_crash_smoke.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_prelab_static_fuzz_plan | diff -u docs/prelab_static_fuzz_plan.json -",
            "cargo run --quiet --example krn_prelab_fuzz_seed_corpus | diff -u docs/prelab_fuzz_seed_corpus.json -",
            "cargo run --quiet --example krn_prelab_no_crash_smoke | diff -u docs/prelab_no_crash_smoke.json -",
        ],
        ci_gate: "Static and fuzz plan drift; Fuzz seed corpus drift; No-crash smoke artifact drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-010",
    },
    VerificationMechanism {
        id: "TOOL-CONFORMANCE-ABI",
        area: "conformance boundary",
        purpose: "emit ABI conformance and capability-readiness records without replacing signed lab templates",
        repository_artifacts: &[
            "docs/abi_conformance_statement.json",
            "examples/krn_abi_conformance_statement.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json -",
        ],
        ci_gate: "ABI conformance statement drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-011",
    },
    VerificationMechanism {
        id: "TOOL-PROFILE-DATA-BOUNDARY",
        area: "configuration provenance",
        purpose: "keep scheme, profile, CAPK, TAC/IAC, and other variable certification data outside compiled kernel code",
        repository_artifacts: &[
            "docs/scheme_profiles.cert.json",
            "docs/scheme_profile_dictionary.md",
            "examples/krn_scheme_profile_dictionary.rs",
            "examples/krn_variable_data_boundary_audit.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_scheme_profile_dictionary | diff -u docs/scheme_profile_dictionary.md -",
            "cargo run --quiet --example krn_variable_data_boundary_audit -- src",
        ],
        ci_gate: "Scheme profile dictionary drift; Variable data boundary audit",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-002; CERT-OPEN-003",
    },

    VerificationMechanism {
        id: "TOOL-DATA-DRIVEN-BUNDLES",
        area: "data-driven certification configuration",
        purpose: "create, validate, fingerprint, and locally provision certification/testing data bundles so certification scope changes are represented as input data rather than Rust source edits",
        repository_artifacts: &[
            "src/cert_bundle.rs",
            "docs/certification_data_bundle.json",
            "docs/certification_data_bundle_trust_anchors.json",
            "docs/certification_data_bundle.md",
            "docs/certification_data_bundle_workbench.html",
            "docs/certification_data_bundle_fingerprints.json",
            "examples/krn_certification_bundle.rs",
            "examples/krn_certification_bundle_tui.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle",
            "cargo run --quiet --example krn_certification_bundle -- --validate --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json",
            "cargo run --quiet --example krn_certification_bundle_tui -- --out target/hyperion-cert-bundle-tui",
        ],
        ci_gate: "Data-driven certification bundle tests and example compile",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-002; CERT-OPEN-003; CERT-OPEN-004; CERT-OPEN-005; CERT-OPEN-009; CERT-OPEN-012",
    },
    VerificationMechanism {
        id: "TOOL-STANDARDS-DRIFT",
        area: "standards drift",
        purpose: "record public standards-watch signals and require licensed/lab evidence before changing certification scope",
        repository_artifacts: &[
            "docs/standards_watch.md",
            "docs/public_standards_watch.json",
            "examples/krn_public_standards_watch.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_public_standards_watch | diff -u docs/public_standards_watch.json -",
        ],
        ci_gate: "Public standards watch drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-001; CERT-OPEN-005; CERT-OPEN-006; CERT-OPEN-007; CERT-OPEN-009; CERT-OPEN-011; CERT-OPEN-012",
    },
    VerificationMechanism {
        id: "TOOL-EVIDENCE-INTAKE",
        area: "crowdsourced evidence intake",
        purpose: "generate attachment checklists, intake ledgers, attachment hash audits, and supersession controls for external evidence",
        repository_artifacts: &[
            "docs/certification_evidence_checklist.json",
            "docs/certification_evidence_checklist.md",
            "docs/certification_evidence_intake.json",
            "docs/certification_evidence_intake.md",
            "examples/krn_certification_evidence_checklist.rs",
            "examples/krn_certification_evidence_intake.rs",
            "examples/krn_certification_attachment_audit.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_certification_evidence_checklist -- --json | diff -u docs/certification_evidence_checklist.json -",
            "cargo run --quiet --example krn_certification_evidence_checklist -- --markdown | diff -u docs/certification_evidence_checklist.md -",
            "cargo run --quiet --example krn_certification_evidence_intake -- --json | diff -u docs/certification_evidence_intake.json -",
            "cargo run --quiet --example krn_certification_evidence_intake -- --markdown | diff -u docs/certification_evidence_intake.md -",
            "cargo run --quiet --example krn_certification_attachment_audit -- --root target/hyperion-cert-attachments",
        ],
        ci_gate: "Certification evidence checklist drift; Certification evidence intake drift; Certification attachment audit smoke",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-001 through CERT-OPEN-012",
    },
    VerificationMechanism {
        id: "TOOL-FREEZE-PROVENANCE",
        area: "submission freeze",
        purpose: "capture submitted-build hash slots and canonical source/evidence provenance commands",
        repository_artifacts: &[
            "docs/certification_freeze_manifest.json",
            "docs/certification_freeze_manifest.md",
            "examples/krn_certification_freeze_manifest.rs",
            "examples/krn_build_manifest.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_certification_freeze_manifest -- --json | diff -u docs/certification_freeze_manifest.json -",
            "cargo run --quiet --example krn_certification_freeze_manifest -- --markdown | diff -u docs/certification_freeze_manifest.md -",
            "cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml .github/workflows/prelab.yml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/scheme_profile_dictionary.md docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_trace_pack_audit.json docs/prelab_trace_pack_audit.md docs/prelab_quality_gates.json docs/prelab_no_crash_smoke.json docs/prelab_static_fuzz_plan.json docs/prelab_fuzz_seed_corpus.json docs/public_standards_watch.json docs/tooling_completeness_audit.json docs/tooling_completeness_audit.md docs/certification_evidence_checklist.json docs/certification_evidence_checklist.md docs/certification_evidence_intake.json docs/certification_evidence_intake.md docs/certification_freeze_manifest.json docs/certification_freeze_manifest.md docs/certification_security_assessment_plan.json docs/certification_security_assessment_plan.md docs/certification_device_evidence_plan.json docs/certification_device_evidence_plan.md docs/certification_integration_report_plan.json docs/certification_integration_report_plan.md docs/certification_report_pack.json docs/certification_report_pack.md docs/certification_report_ui.html docs/certification_open_issues.md docs/standards_watch.md docs/open_source.md docs/coverage.md scripts/coverage_100.sh examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_cabi_script_adapter.rs examples/krn_certification_attachment_audit.rs examples/krn_coverage_package_audit.rs examples/krn_trace_pack_audit.rs examples/krn_certification_evidence_checklist.rs examples/krn_certification_evidence_intake.rs examples/krn_certification_freeze_manifest.rs examples/krn_certification_security_assessment_plan.rs examples/krn_certification_device_evidence_plan.rs examples/krn_certification_integration_report_plan.rs examples/krn_certification_report_ui.rs examples/krn_certification_workspace.rs examples/krn_tooling_completeness_audit.rs examples/krn_basic_pos.rs examples/krn_callback_timeout_policy.rs examples/krn_variable_data_boundary_audit.rs examples/krn_scheme_profile_dictionary.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs examples/krn_prelab_no_crash_smoke.rs examples/krn_prelab_static_fuzz_plan.rs examples/krn_prelab_fuzz_seed_corpus.rs examples/krn_public_standards_watch.rs examples/krn_emv_decode.rs",
        ],
        ci_gate: "Pre-lab quality gate manifest drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-001; CERT-OPEN-009; CERT-OPEN-011",
    },
    VerificationMechanism {
        id: "TOOL-SECURITY-DEVICE-INTEGRATION-PLANS",
        area: "external report planning",
        purpose: "produce security assessment, device/L1/PED, and full integration-report control plans",
        repository_artifacts: &[
            "docs/certification_security_assessment_plan.json",
            "docs/certification_security_assessment_plan.md",
            "docs/certification_device_evidence_plan.json",
            "docs/certification_device_evidence_plan.md",
            "docs/certification_integration_report_plan.json",
            "docs/certification_integration_report_plan.md",
        ],
        commands: &[
            "cargo run --quiet --example krn_certification_security_assessment_plan -- --json | diff -u docs/certification_security_assessment_plan.json -",
            "cargo run --quiet --example krn_certification_device_evidence_plan -- --json | diff -u docs/certification_device_evidence_plan.json -",
            "cargo run --quiet --example krn_certification_integration_report_plan -- --json | diff -u docs/certification_integration_report_plan.json -",
        ],
        ci_gate: "Certification security/device/integration plan drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-006; CERT-OPEN-007; CERT-OPEN-008; CERT-OPEN-009; CERT-OPEN-010; CERT-OPEN-012",
    },
    VerificationMechanism {
        id: "TOOL-REPORT-WORKBENCH",
        area: "report production",
        purpose: "generate the static report workbench, JSON/Markdown report pack, and complete local certification workspace",
        repository_artifacts: &[
            "docs/certification_report_ui.html",
            "docs/certification_report_pack.json",
            "docs/certification_report_pack.md",
            "examples/krn_certification_report_ui.rs",
            "examples/krn_certification_workspace.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_certification_report_ui -- --html | diff -u docs/certification_report_ui.html -",
            "cargo run --quiet --example krn_certification_report_ui -- --json | diff -u docs/certification_report_pack.json -",
            "cargo run --quiet --example krn_certification_report_ui -- --markdown | diff -u docs/certification_report_pack.md -",
            "cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace",
        ],
        ci_gate: "Certification report drift; Certification workspace smoke",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-001 through CERT-OPEN-012",
    },
    VerificationMechanism {
        id: "TOOL-POS-INTEGRATION-SMOKE",
        area: "integration examples",
        purpose: "run a basic scripted PoS flow and expose callback timeout policy for terminal adapter evidence",
        repository_artifacts: &[
            "examples/krn_basic_pos.rs",
            "examples/krn_callback_timeout_policy.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_basic_pos",
            "cargo run --quiet --example krn_callback_timeout_policy",
        ],
        ci_gate: "Basic PoS integration smoke; Callback timeout policy smoke",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-006; CERT-OPEN-009",
    },
    VerificationMechanism {
        id: "TOOL-TOOLING-COMPLETENESS",
        area: "tooling completeness",
        purpose: "produce this audit so repository tooling gaps are machine-checkable and external blockers remain explicit",
        repository_artifacts: &[
            "docs/tooling_completeness_audit.json",
            "docs/tooling_completeness_audit.md",
            "examples/krn_tooling_completeness_audit.rs",
        ],
        commands: &[
            "cargo run --quiet --example krn_tooling_completeness_audit -- --json | diff -u docs/tooling_completeness_audit.json -",
            "cargo run --quiet --example krn_tooling_completeness_audit -- --markdown | diff -u docs/tooling_completeness_audit.md -",
        ],
        ci_gate: "Tooling completeness audit drift",
        status: "repo-controlled",
        external_closure_gate: "CERT-OPEN-001 through CERT-OPEN-012",
    },
];

pub fn tooling_completeness_audit_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "tooling-completeness-audit");
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
        "repository-controlled tooling and verification mechanisms only; external certification evidence remains required",
    );
    out.push(',');
    push_json_str(&mut out, "status", "repo-controlled-tools-complete");
    out.push(',');
    push_json_str(
        &mut out,
        "verdict",
        "all repository-controlled verification mechanisms are represented by deterministic artifacts, commands, CI gates, or documented external-evidence slots",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_string_array(&mut out, DOES_NOT_CLOSE);
    out.push_str("],\"mechanisms\":[");
    for (idx, mechanism) in MECHANISMS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_mechanism_json(&mut out, mechanism);
    }
    out.push_str("],\"external_evidence_still_required\":[");
    for (idx, requirement) in certification_evidence_requirements().iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_external_requirement_json(&mut out, requirement);
    }
    out.push_str("]}\n");
    out
}

pub fn tooling_completeness_audit_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Tooling Completeness Audit");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-24");
    let _ = writeln!(
        out,
        "- Status: repo-controlled-tools-complete for repository-controlled tooling only"
    );
    let _ = writeln!(
        out,
        "- Scope: repository-controlled tooling and verification mechanisms only; external certification evidence remains required"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "This audit answers whether Hyperion has the local tooling needed to produce, verify, package, and review repository-controlled evidence. It does not close lab, scheme, acquirer, device, PCI/PED, CAPK, profile, vector, integration-report, or approval gates."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Repository-Controlled Mechanisms");
    let _ = writeln!(
        out,
        "| ID | Area | Purpose | Artifacts | Commands | CI Gate | Status | External Closure Gate |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for mechanism in MECHANISMS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | `{}` | {} | {} | {} |",
            mechanism.id,
            mechanism.area,
            mechanism.purpose,
            mechanism.repository_artifacts.join("; "),
            mechanism.commands.join("; "),
            mechanism.ci_gate,
            mechanism.status,
            mechanism.external_closure_gate
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## External Evidence Still Required");
    let _ = writeln!(
        out,
        "| Open Issue | Area | Authority | Required Attachment | Acceptance Gate | Repository Support | Status |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |");
    for requirement in certification_evidence_requirements() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | `{}` | {} |",
            requirement.open_issue,
            requirement.area,
            requirement.authority,
            requirement.required_attachment,
            requirement.acceptance_gate,
            requirement.repository_support,
            requirement.status
        );
    }
    out
}

fn push_mechanism_json(out: &mut String, mechanism: &VerificationMechanism) {
    out.push('{');
    push_json_str(out, "id", mechanism.id);
    out.push(',');
    push_json_str(out, "area", mechanism.area);
    out.push(',');
    push_json_str(out, "purpose", mechanism.purpose);
    out.push_str(",\"repository_artifacts\":[");
    push_json_string_array(out, mechanism.repository_artifacts);
    out.push_str("],\"commands\":[");
    push_json_string_array(out, mechanism.commands);
    out.push_str("],");
    push_json_str(out, "ci_gate", mechanism.ci_gate);
    out.push(',');
    push_json_str(out, "status", mechanism.status);
    out.push(',');
    push_json_str(
        out,
        "external_closure_gate",
        mechanism.external_closure_gate,
    );
    out.push('}');
}

fn push_external_requirement_json(out: &mut String, requirement: &EvidenceRequirement) {
    out.push('{');
    push_json_str(out, "open_issue", requirement.open_issue);
    out.push(',');
    push_json_str(out, "area", requirement.area);
    out.push(',');
    push_json_str(out, "authority", requirement.authority);
    out.push(',');
    push_json_str(out, "required_attachment", requirement.required_attachment);
    out.push(',');
    push_json_str(out, "required_metadata", requirement.required_metadata);
    out.push(',');
    push_json_str(out, "acceptance_gate", requirement.acceptance_gate);
    out.push(',');
    push_json_str(out, "repository_support", requirement.repository_support);
    out.push(',');
    push_json_str(out, "status", requirement.status);
    out.push('}');
}

fn push_json_string_array(out: &mut String, values: &[&str]) {
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
    fn tooling_audit_is_complete_without_certification_claims() {
        let json = tooling_completeness_audit_json(2);

        assert!(json.contains("\"type\":\"tooling-completeness-audit\""));
        assert!(json.contains("\"status\":\"repo-controlled-tools-complete\""));
        assert!(json.contains("\"TOOL-TOOLING-COMPLETENESS\""));
        assert!(json.contains("docs/tooling_completeness_audit.json"));
        assert!(json.contains("examples/krn_tooling_completeness_audit.rs"));
        assert!(json.contains("\"external_evidence_still_required\""));
        assert!(json.contains("\"open_issue\":\"CERT-OPEN-001\""));
        assert!(json.contains("\"open_issue\":\"CERT-OPEN-012\""));
        assert!(!json.contains("certified\":true"));
    }

    #[test]
    fn tooling_audit_markdown_is_reviewable() {
        let markdown = tooling_completeness_audit_markdown(2);

        assert!(markdown.contains("# Hyperion Tooling Completeness Audit"));
        assert!(markdown.contains("Repository-Controlled Mechanisms"));
        assert!(markdown.contains("TOOL-REPORT-WORKBENCH"));
        assert!(markdown.contains("External Evidence Still Required"));
        assert!(markdown.contains("CERT-OPEN-009"));
    }
}
