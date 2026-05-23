//! Certification evidence checklist generation.
//!
//! This module records what must be attached before a certification-facing
//! claim can close each external gate. It is deliberately a checklist and
//! report-production aid, not an approval engine.

use core::fmt::Write;

pub struct EvidenceRequirement {
    pub open_issue: &'static str,
    pub area: &'static str,
    pub authority: &'static str,
    pub required_attachment: &'static str,
    pub required_metadata: &'static str,
    pub acceptance_gate: &'static str,
    pub repository_support: &'static str,
    pub status: &'static str,
}

pub const EVIDENCE_REQUIREMENTS: &[EvidenceRequirement] = &[
    EvidenceRequirement {
        open_issue: "CERT-OPEN-001",
        area: "EMV Level 2 approval",
        authority: "EMVCo, scheme, acquirer, and recognized laboratory",
        required_attachment: "final lab execution report plus signed approval or LoA-equivalent artifact for the claimed interface, kernel, and scheme scope",
        required_metadata: "submitted binary hash, profile hash, test-tool package, device model, firmware, and claimed interface list",
        acceptance_gate: "approval artifact agrees with the submitted binary, profile set, device scope, and RTM",
        repository_support: "docs/spec.md, docs/requirements_traceability.csv, docs/certification_report_pack.json",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-002",
        area: "Scheme profile authority",
        authority: "scheme, acquirer, or laboratory profile authority",
        required_attachment: "signed AID, TAC/IAC, limit, CVM, CDA-control, and kernel-selection profile bundle",
        required_metadata: "profile version, issuer authority, retrieval date, signature status, rollback policy, and SHA-256",
        acceptance_gate: "signed profile bundle is loaded through the verified profile path and matches trace identity",
        repository_support: "docs/scheme_profiles.cert.json, docs/scheme_profile_dictionary.md, krn_get_profile_sha256",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-003",
        area: "CAPK authority",
        authority: "scheme or acquirer CAPK authority",
        required_attachment: "approved CAPK set with RID, key index, modulus, exponent, expiry, checksum, and provenance",
        required_metadata: "CAPK source, retrieval date, expiry date, checksum, bundle hash, and approval reference",
        acceptance_gate: "CAPK bundle passes repository checksum gates and traces to accepted public-key material",
        repository_support: "src/oda.rs, docs/scheme_profiles.cert.json, docs/scheme_profile_dictionary.md",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-004",
        area: "ODA certification vectors",
        authority: "recognized laboratory or scheme test-vector authority",
        required_attachment: "complete lab-supplied SDA, DDA, and CDA cryptographic vectors with expected TVR/TSI and outcome data",
        required_metadata: "vector class, vector source, tool version, expected outputs, method coverage, and bundle hash",
        acceptance_gate: "docs/oda_test_vectors.json is replaced by vector_class CERTIFICATION and passes complete-vector validation",
        repository_support: "src/oda.rs, docs/oda_test_vectors.json, ODA parser and validation tests",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-005",
        area: "Contactless C-8 package",
        authority: "EMVCo contactless kernel/product approval path and scheme profile authority",
        required_attachment: "lab-selected C-8 version and bulletin reconciliation, profile data, contactless test-tool results, and outcome traces",
        required_metadata: "C-8 version, bulletin set, included/excluded adjacent books, test-tool version, terminal profile, TTQ source, and trace pack hash",
        acceptance_gate: "contactless claim is tied to the accepted C-8 package, profile set, device/L1 evidence, and masked outcome traces",
        repository_support: "src/c8.rs, docs/public_standards_watch.json, docs/standards_watch.md",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-006",
        area: "Device and L1 evidence",
        authority: "device vendor, L1 laboratory, scheme, and EMVCo process as applicable",
        required_attachment: "target terminal, contact interface, contactless reader, firmware, and L1/device certification evidence",
        required_metadata: "model, hardware revision, firmware, reader stack, L1 approval reference, and submitted binary/profile hash",
        acceptance_gate: "device evidence names the same target, firmware, binary, profile bundle, and interface scope as the submission",
        repository_support: "docs/lab_submission_manifest.md, trace identity metadata, C ABI integration examples",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-007",
        area: "PCI/PED security evidence",
        authority: "PCI SSC, PCI-recognized laboratory, PED vendor, and security assessor",
        required_attachment: "PCI PTS POI integration statement, PED-owned VERIFY evidence, and no-clear-PIN custody review",
        required_metadata: "PTS listing or assessment reference, PED model, firmware, PIN method, opaque-handle policy, and integration evidence",
        acceptance_gate: "PED evidence confirms the kernel only handles opaque PIN handles and cannot log or receive clear PIN data",
        repository_support: "src/cvm.rs, src/ffi.rs, docs/public_standards_watch.json",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-008",
        area: "Third-party security assessment",
        authority: "independent security assessor accepted for the product submission",
        required_attachment: "penetration test and architecture review report covering APDU injection, state-machine bypass, trace leakage, and profile tampering",
        required_metadata: "scope, commit hash, device/profile set, findings, remediations, residual-risk owner, and retest evidence",
        acceptance_gate: "all critical/high findings are remediated or formally accepted before final certification-facing release",
        repository_support: "src/fsm.rs, src/trace.rs, src/config.rs, docs/certification_open_issues.md",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-009",
        area: "Unit and integration reports",
        authority: "submission owner, laboratory, scheme, or acquirer acceptance path",
        required_attachment: "100% unit coverage report plus coverage metadata JSON and full EMV test-plan integration report for the submitted build",
        required_metadata: "source commit, Cargo version, Rust compiler version, target triple, feature set, cargo-llvm-cov version, threshold, enforcement mode, profile hash, CAPK hash, test-tool version, report hash, and deviations",
        acceptance_gate: "coverage and integration reports match the submitted binary, profiles, CAPKs, vectors, and annex hashes",
        repository_support: "scripts/coverage_100.sh, docs/coverage.md, .github/workflows/prelab.yml",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-010",
        area: "Static analysis and fuzzing",
        authority: "submission owner, laboratory, scheme, or acquirer acceptance path",
        required_attachment: "accepted static-analysis report and fuzzing/no-crash report with findings and dispositions",
        required_metadata: "tool versions, commands, sanitizer set, corpus hashes, run budget, crashes, remediations, and accepted residual risks",
        acceptance_gate: "reports show no unresolved unacceptable findings for the submitted source, binary, and parser surfaces",
        repository_support: "docs/prelab_static_fuzz_plan.json, docs/prelab_fuzz_seed_corpus.json, docs/prelab_no_crash_smoke.json",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-011",
        area: "Signed conformance template",
        authority: "EMVCo, recognized laboratory, scheme, or acquirer as applicable",
        required_attachment: "signed conformance statement template or approval package tied to the claimed scope",
        required_metadata: "template version, signer, signature date, submitted binary hash, ABI version, RTM version, and device/profile scope",
        acceptance_gate: "signed template agrees with the ABI JSON statement, RTM, lab manifest, and approval artifact",
        repository_support: "docs/abi_conformance_statement.json, src/conformance.rs, src/ffi.rs",
        status: "pending external attachment",
    },
    EvidenceRequirement {
        open_issue: "CERT-OPEN-012",
        area: "APDU trace pack",
        authority: "recognized laboratory, scheme, acquirer, or accepted test-tool owner",
        required_attachment: "full masked APDU traces for every applicable lab/test-tool case",
        required_metadata: "case IDs, ordering, SW1/SW2, expected and actual outcomes, trace identity, profile SHA-256, ABI version, and masking policy",
        acceptance_gate: "trace pack is replayable, masked, complete for the claimed test plan, and tied to the submitted binary/profile set",
        repository_support: "docs/prelab_apdu_trace_pack.jsonl, src/trace.rs, examples/krn_prelab_trace_pack.rs",
        status: "pending external attachment",
    },
];

pub fn certification_evidence_requirements() -> &'static [EvidenceRequirement] {
    EVIDENCE_REQUIREMENTS
}

pub fn certification_evidence_intake_ledger_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-evidence-intake-ledger");
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
        "attachment intake slots for crowdsourced certification testing and lab package assembly",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "source_of_truth",
        "docs/certification_open_issues.md",
    );
    out.push_str(",\"does_not_close\":[");
    for (idx, requirement) in EVIDENCE_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, requirement.open_issue);
    }
    out.push_str("],\"intake_policy\":[");
    for (idx, policy) in [
        "every attachment slot starts pending until an accepted authority, signer or reviewer, artifact path, SHA-256, date, and submitted-build scope are recorded",
        "repository-controlled fixtures, generated reports, and crowdsourced findings can support review but cannot close external certification gates",
        "superseded evidence must retain the prior artifact hash and replacement reason so lab-package history remains auditable",
        "sensitive card, PIN, issuer-script, cryptogram, private-key, and scheme-confidential data must remain masked, external, or access-controlled according to the trace policy",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, policy);
    }
    out.push_str("],\"attachment_slots\":[");
    for (idx, requirement) in EVIDENCE_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_intake_slot_json(&mut out, requirement);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_evidence_intake_ledger_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Evidence Intake Ledger");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-23");
    let _ = writeln!(
        out,
        "- Scope: attachment intake slots for crowdsourced certification testing and lab package assembly"
    );
    let _ = writeln!(
        out,
        "- Source of truth: `docs/certification_open_issues.md`"
    );
    let _ = writeln!(
        out,
        "- Boundary: this ledger does not close any `CERT-OPEN-*` issue."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Intake Policy");
    for policy in [
        "Every attachment slot starts pending until an accepted authority, signer or reviewer, artifact path, SHA-256, date, and submitted-build scope are recorded.",
        "Repository-controlled fixtures, generated reports, and crowdsourced findings can support review but cannot close external certification gates.",
        "Superseded evidence must retain the prior artifact hash and replacement reason so lab-package history remains auditable.",
        "Sensitive card, PIN, issuer-script, cryptogram, private-key, and scheme-confidential data must remain masked, external, or access-controlled according to the trace policy.",
    ] {
        let _ = writeln!(out, "- {policy}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Attachment Slots");
    let _ = writeln!(
        out,
        "| Slot | Open Issue | Area | Required Attachment | Required Metadata | Required Hash | Review Fields | Closure Rule | Status |"
    );
    let _ = writeln!(
        out,
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    );
    for requirement in EVIDENCE_REQUIREMENTS {
        let _ = writeln!(
            out,
            "| {}-ATTACHMENT | {} | {} | {} | {} | SHA-256 required before review | authority, signer_or_reviewer, artifact_path, artifact_sha256, artifact_date, submitted_build_scope, disposition, supersedes | Must satisfy the acceptance gate before closing {}: {} | {} |",
            requirement.open_issue,
            requirement.open_issue,
            requirement.area,
            requirement.required_attachment,
            requirement.required_metadata,
            requirement.open_issue,
            requirement.acceptance_gate,
            requirement.status
        );
    }
    out
}

pub fn certification_evidence_checklist_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-evidence-checklist");
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
        "external evidence attachment checklist for certification package assembly",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "source_of_truth",
        "docs/certification_open_issues.md",
    );
    out.push_str(",\"does_not_close\":[");
    for (idx, requirement) in EVIDENCE_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, requirement.open_issue);
    }
    out.push_str("],\"research_basis\":[");
    for (idx, basis) in [
        "EMVCo public process pages frame kernel and product approval as compliance attestation, not repository self-certification.",
        "EMVCo public contactless-kernel testing material describes accredited laboratory testing, qualified tools, test-plan execution, and Letter of Approval issuance.",
        "PCI SSC public PTS POI material frames POI security around protecting PINs, account data, and sensitive payment data at the point of interaction.",
        "PCI SSC public approved-device material ties PTS conformance to PCI-recognized laboratory validation and published approved-device listings.",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, basis);
    }
    out.push_str("],\"requirements\":[");
    for (idx, requirement) in EVIDENCE_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_requirement_json(&mut out, requirement);
    }
    out.push_str("],\"acceptance_rules\":[");
    for (idx, rule) in [
        "every closure claim must name an authority, signer or lab, artifact path, hash, date, and submitted-build scope",
        "repository-controlled fixtures can support review but cannot replace signed external reports or approval artifacts",
        "sensitive PAN, PIN, cryptogram, issuer-script, and private-key material must remain masked or external according to the trace policy",
        "if a required attachment is superseded, retain the previous hash and record the replacement authority and reason",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, rule);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_evidence_checklist_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Evidence Checklist");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(out, "- Checked on: 2026-05-23");
    let _ = writeln!(
        out,
        "- Scope: external evidence attachment checklist for certification package assembly"
    );
    let _ = writeln!(
        out,
        "- Source of truth: `docs/certification_open_issues.md`"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Requirements");
    let _ = writeln!(
        out,
        "| Open Issue | Area | Authority | Required Attachment | Metadata | Acceptance Gate | Repository Support | Status |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for requirement in EVIDENCE_REQUIREMENTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | `{}` | {} |",
            requirement.open_issue,
            requirement.area,
            requirement.authority,
            requirement.required_attachment,
            requirement.required_metadata,
            requirement.acceptance_gate,
            requirement.repository_support,
            requirement.status
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Acceptance Rules");
    for rule in [
        "Every closure claim must name an authority, signer or lab, artifact path, hash, date, and submitted-build scope.",
        "Repository-controlled fixtures can support review but cannot replace signed external reports or approval artifacts.",
        "Sensitive PAN, PIN, cryptogram, issuer-script, and private-key material must remain masked or external according to the trace policy.",
        "If a required attachment is superseded, retain the previous hash and record the replacement authority and reason.",
    ] {
        let _ = writeln!(out, "- {rule}");
    }
    out
}

fn push_requirement_json(out: &mut String, requirement: &EvidenceRequirement) {
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

fn push_intake_slot_json(out: &mut String, requirement: &EvidenceRequirement) {
    out.push('{');
    push_json_str(
        out,
        "slot_id",
        &format!("{}-ATTACHMENT", requirement.open_issue),
    );
    out.push(',');
    push_json_str(out, "open_issue", requirement.open_issue);
    out.push(',');
    push_json_str(out, "area", requirement.area);
    out.push(',');
    push_json_str(out, "status", requirement.status);
    out.push(',');
    push_json_str(out, "required_attachment", requirement.required_attachment);
    out.push(',');
    push_json_str(out, "required_metadata", requirement.required_metadata);
    out.push(',');
    push_json_str(out, "required_hash", "SHA-256 required before review");
    out.push_str(",\"review_fields\":[");
    for (idx, field) in [
        "authority",
        "signer_or_reviewer",
        "artifact_path",
        "artifact_sha256",
        "artifact_date",
        "submitted_build_scope",
        "disposition",
        "supersedes",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(out, field);
    }
    out.push_str("],");
    push_json_str(
        out,
        "closure_rule",
        &format!(
            "Must satisfy the acceptance gate before closing {}: {}",
            requirement.open_issue, requirement.acceptance_gate
        ),
    );
    out.push('}');
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
    fn evidence_checklist_json_tracks_all_open_issues_without_closure_claims() {
        let json = certification_evidence_checklist_json(2);

        assert!(json.contains("\"type\":\"certification-evidence-checklist\""));
        assert!(json.contains("\"abi_version\":2"));
        for requirement in EVIDENCE_REQUIREMENTS {
            assert!(
                json.contains(requirement.open_issue),
                "missing {}",
                requirement.open_issue
            );
        }
        assert!(json.contains("pending external attachment"));
        assert!(json.contains("Letter of Approval"));
        assert!(json.contains("PCI-recognized laboratory validation"));
        assert!(!json.contains("certified\":true"));
    }

    #[test]
    fn evidence_checklist_markdown_is_reviewable() {
        let markdown = certification_evidence_checklist_markdown(2);

        assert!(markdown.contains("# Hyperion Certification Evidence Checklist"));
        assert!(markdown.contains("| Open Issue | Area | Authority | Required Attachment | Metadata | Acceptance Gate | Repository Support | Status |"));
        assert!(markdown.contains("CERT-OPEN-012"));
        assert!(markdown.contains("Every closure claim must name an authority"));
    }

    #[test]
    fn evidence_intake_ledger_tracks_attachment_slots_without_closure_claims() {
        let json = certification_evidence_intake_ledger_json(2);
        let markdown = certification_evidence_intake_ledger_markdown(2);

        assert!(json.contains("\"type\":\"certification-evidence-intake-ledger\""));
        assert!(json.contains("\"slot_id\":\"CERT-OPEN-001-ATTACHMENT\""));
        assert!(json.contains("\"artifact_sha256\""));
        assert!(json.contains("\"supersedes\""));
        assert!(json.contains("does_not_close"));
        assert!(!json.contains("\"certified\":true"));
        assert!(markdown.contains("# Hyperion Certification Evidence Intake Ledger"));
        assert!(markdown.contains("SHA-256 required before review"));
        assert!(markdown.contains("submitted_build_scope"));
        assert!(markdown.contains("does not close any `CERT-OPEN-*` issue"));
    }
}
