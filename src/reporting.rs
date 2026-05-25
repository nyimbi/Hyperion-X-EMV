//! Certification report-pack and static workbench generation.
//!
//! The UI generated here is deliberately static and dependency-free. It is an
//! inspection and report-production surface for repository-controlled evidence;
//! it does not close external lab, scheme, device, PCI, or approval gates.

use crate::evidence::{certification_evidence_requirements, EvidenceRequirement};
use crate::provenance::{sha256, to_hex};
use core::fmt::Write;

pub struct RequirementTrace {
    pub id: String,
    pub text: String,
    pub unit_test_id: String,
    pub integration_test_id: String,
    pub emvco_ref: String,
    pub evidence_artifact: String,
}

pub struct ReportArtifact {
    pub id: &'static str,
    pub title: &'static str,
    pub path: &'static str,
    pub category: &'static str,
    pub generator: &'static str,
    pub status: &'static str,
    pub boundary: &'static str,
}

pub struct RequiredReport {
    pub id: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    pub required_evidence: &'static str,
    pub closure_gate: &'static str,
}

pub struct ToolCommand {
    pub id: &'static str,
    pub title: &'static str,
    pub command: &'static str,
    pub output: &'static str,
}

pub struct ControlledReportFile {
    pub id: &'static str,
    pub title: &'static str,
    pub path: &'static str,
    pub category: &'static str,
    pub contents: &'static [u8],
}

pub struct ReportFileExclusion {
    pub id: &'static str,
    pub path: &'static str,
    pub reason: &'static str,
}

const REQUIREMENTS_TRACEABILITY: &str = include_str!("../docs/requirements_traceability.csv");

const CONTROLLED_REPORT_FILES: &[ControlledReportFile] = &[
    ControlledReportFile {
        id: "SPEC",
        title: "Kernel specification",
        path: "docs/spec.md",
        category: "requirements",
        contents: include_bytes!("../docs/spec.md"),
    },
    ControlledReportFile {
        id: "LAB-MANIFEST",
        title: "Lab submission manifest",
        path: "docs/lab_submission_manifest.md",
        category: "submission",
        contents: include_bytes!("../docs/lab_submission_manifest.md"),
    },
    ControlledReportFile {
        id: "RTM-PRIMARY",
        title: "Primary requirements traceability matrix",
        path: "docs/requirements_traceability.csv",
        category: "requirements",
        contents: include_bytes!("../docs/requirements_traceability.csv"),
    },
    ControlledReportFile {
        id: "RTM-COMPAT",
        title: "Compatibility requirements traceability matrix",
        path: "docs/requirements-traceability-matrix.csv",
        category: "requirements",
        contents: include_bytes!("../docs/requirements-traceability-matrix.csv"),
    },
    ControlledReportFile {
        id: "OPEN-ISSUES",
        title: "Certification open issues register",
        path: "docs/certification_open_issues.md",
        category: "submission",
        contents: include_bytes!("../docs/certification_open_issues.md"),
    },
    ControlledReportFile {
        id: "ABI",
        title: "ABI conformance statement",
        path: "docs/abi_conformance_statement.json",
        category: "conformance",
        contents: include_bytes!("../docs/abi_conformance_statement.json"),
    },
    ControlledReportFile {
        id: "PROFILE-BUNDLE",
        title: "Certification profile scaffold",
        path: "docs/scheme_profiles.cert.json",
        category: "configuration",
        contents: include_bytes!("../docs/scheme_profiles.cert.json"),
    },
    ControlledReportFile {
        id: "PROFILE-DICTIONARY",
        title: "Scheme profile dictionary",
        path: "docs/scheme_profile_dictionary.md",
        category: "configuration",
        contents: include_bytes!("../docs/scheme_profile_dictionary.md"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-JSON",
        title: "Data-driven certification bundle fixture",
        path: "docs/certification_data_bundle.json",
        category: "configuration",
        contents: include_bytes!("../docs/certification_data_bundle.json"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-TRUST",
        title: "Data-driven bundle trust-anchor fixture",
        path: "docs/certification_data_bundle_trust_anchors.json",
        category: "configuration",
        contents: include_bytes!("../docs/certification_data_bundle_trust_anchors.json"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-REPORT",
        title: "Data-driven certification bundle report",
        path: "docs/certification_data_bundle.md",
        category: "configuration",
        contents: include_bytes!("../docs/certification_data_bundle.md"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-WORKBENCH",
        title: "Data-driven certification bundle workbench",
        path: "docs/certification_data_bundle_workbench.html",
        category: "workbench",
        contents: include_bytes!("../docs/certification_data_bundle_workbench.html"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-FINGERPRINTS",
        title: "Data-driven certification bundle fingerprints",
        path: "docs/certification_data_bundle_fingerprints.json",
        category: "configuration",
        contents: include_bytes!("../docs/certification_data_bundle_fingerprints.json"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-LINT-JSON",
        title: "Data-driven certification bundle lint report",
        path: "docs/certification_data_bundle_lint.json",
        category: "quality",
        contents: include_bytes!("../docs/certification_data_bundle_lint.json"),
    },
    ControlledReportFile {
        id: "DATA-BUNDLE-LINT-MD",
        title: "Data-driven certification bundle lint report Markdown",
        path: "docs/certification_data_bundle_lint.md",
        category: "quality",
        contents: include_bytes!("../docs/certification_data_bundle_lint.md"),
    },
    ControlledReportFile {
        id: "ODA-VECTORS",
        title: "ODA structural vector annex",
        path: "docs/oda_test_vectors.json",
        category: "configuration",
        contents: include_bytes!("../docs/oda_test_vectors.json"),
    },
    ControlledReportFile {
        id: "TLV-CATALOGUE",
        title: "TLV catalogue",
        path: "docs/tlv_catalogue.csv",
        category: "annex",
        contents: include_bytes!("../docs/tlv_catalogue.csv"),
    },
    ControlledReportFile {
        id: "STATE-MACHINE",
        title: "State machine annex",
        path: "docs/state_machine.csv",
        category: "annex",
        contents: include_bytes!("../docs/state_machine.csv"),
    },
    ControlledReportFile {
        id: "BITMAP-CATALOGUE",
        title: "Bitmap catalogue",
        path: "docs/bitmap_catalogue.csv",
        category: "annex",
        contents: include_bytes!("../docs/bitmap_catalogue.csv"),
    },
    ControlledReportFile {
        id: "PERFORMANCE-PROFILE",
        title: "Performance profile",
        path: "docs/performance_profile.csv",
        category: "annex",
        contents: include_bytes!("../docs/performance_profile.csv"),
    },
    ControlledReportFile {
        id: "TRACE-PACK",
        title: "Masked pre-lab APDU trace fixture",
        path: "docs/prelab_apdu_trace_pack.jsonl",
        category: "trace",
        contents: include_bytes!("../docs/prelab_apdu_trace_pack.jsonl"),
    },
    ControlledReportFile {
        id: "TRACE-AUDIT-JSON",
        title: "Trace-pack audit JSON",
        path: "docs/prelab_trace_pack_audit.json",
        category: "trace",
        contents: include_bytes!("../docs/prelab_trace_pack_audit.json"),
    },
    ControlledReportFile {
        id: "TRACE-AUDIT-MD",
        title: "Trace-pack audit Markdown",
        path: "docs/prelab_trace_pack_audit.md",
        category: "trace",
        contents: include_bytes!("../docs/prelab_trace_pack_audit.md"),
    },
    ControlledReportFile {
        id: "QUALITY-GATES",
        title: "Pre-lab quality gate manifest",
        path: "docs/prelab_quality_gates.json",
        category: "quality",
        contents: include_bytes!("../docs/prelab_quality_gates.json"),
    },
    ControlledReportFile {
        id: "NO-CRASH",
        title: "Parser/APDU no-crash smoke artifact",
        path: "docs/prelab_no_crash_smoke.json",
        category: "quality",
        contents: include_bytes!("../docs/prelab_no_crash_smoke.json"),
    },
    ControlledReportFile {
        id: "STATIC-FUZZ-PLAN",
        title: "Static and fuzz evidence plan",
        path: "docs/prelab_static_fuzz_plan.json",
        category: "quality",
        contents: include_bytes!("../docs/prelab_static_fuzz_plan.json"),
    },
    ControlledReportFile {
        id: "FUZZ-SEEDS",
        title: "Fuzz seed corpus manifest",
        path: "docs/prelab_fuzz_seed_corpus.json",
        category: "quality",
        contents: include_bytes!("../docs/prelab_fuzz_seed_corpus.json"),
    },
    ControlledReportFile {
        id: "PUBLIC-STANDARDS-JSON",
        title: "Public standards watch JSON",
        path: "docs/public_standards_watch.json",
        category: "drift",
        contents: include_bytes!("../docs/public_standards_watch.json"),
    },
    ControlledReportFile {
        id: "PUBLIC-STANDARDS-MD",
        title: "Public standards watch Markdown",
        path: "docs/standards_watch.md",
        category: "drift",
        contents: include_bytes!("../docs/standards_watch.md"),
    },
    ControlledReportFile {
        id: "TOOLING-COMPLETENESS-JSON",
        title: "Tooling completeness audit JSON",
        path: "docs/tooling_completeness_audit.json",
        category: "quality",
        contents: include_bytes!("../docs/tooling_completeness_audit.json"),
    },
    ControlledReportFile {
        id: "TOOLING-COMPLETENESS-MD",
        title: "Tooling completeness audit Markdown",
        path: "docs/tooling_completeness_audit.md",
        category: "quality",
        contents: include_bytes!("../docs/tooling_completeness_audit.md"),
    },
    ControlledReportFile {
        id: "ARTIFACT-IMPORT-JSON",
        title: "Certification artifact import plan JSON",
        path: "docs/certification_artifact_import_plan.json",
        category: "submission",
        contents: include_bytes!("../docs/certification_artifact_import_plan.json"),
    },
    ControlledReportFile {
        id: "ARTIFACT-IMPORT-MD",
        title: "Certification artifact import plan Markdown",
        path: "docs/certification_artifact_import_plan.md",
        category: "submission",
        contents: include_bytes!("../docs/certification_artifact_import_plan.md"),
    },
    ControlledReportFile {
        id: "EVIDENCE-CHECKLIST-JSON",
        title: "Certification evidence checklist JSON",
        path: "docs/certification_evidence_checklist.json",
        category: "submission",
        contents: include_bytes!("../docs/certification_evidence_checklist.json"),
    },
    ControlledReportFile {
        id: "EVIDENCE-CHECKLIST-MD",
        title: "Certification evidence checklist Markdown",
        path: "docs/certification_evidence_checklist.md",
        category: "submission",
        contents: include_bytes!("../docs/certification_evidence_checklist.md"),
    },
    ControlledReportFile {
        id: "EVIDENCE-INTAKE-JSON",
        title: "Certification evidence intake JSON",
        path: "docs/certification_evidence_intake.json",
        category: "submission",
        contents: include_bytes!("../docs/certification_evidence_intake.json"),
    },
    ControlledReportFile {
        id: "EVIDENCE-INTAKE-MD",
        title: "Certification evidence intake Markdown",
        path: "docs/certification_evidence_intake.md",
        category: "submission",
        contents: include_bytes!("../docs/certification_evidence_intake.md"),
    },
    ControlledReportFile {
        id: "FREEZE-JSON",
        title: "Certification freeze manifest JSON",
        path: "docs/certification_freeze_manifest.json",
        category: "submission",
        contents: include_bytes!("../docs/certification_freeze_manifest.json"),
    },
    ControlledReportFile {
        id: "FREEZE-MD",
        title: "Certification freeze manifest Markdown",
        path: "docs/certification_freeze_manifest.md",
        category: "submission",
        contents: include_bytes!("../docs/certification_freeze_manifest.md"),
    },
    ControlledReportFile {
        id: "SECURITY-PLAN-JSON",
        title: "Security assessment plan JSON",
        path: "docs/certification_security_assessment_plan.json",
        category: "security",
        contents: include_bytes!("../docs/certification_security_assessment_plan.json"),
    },
    ControlledReportFile {
        id: "SECURITY-PLAN-MD",
        title: "Security assessment plan Markdown",
        path: "docs/certification_security_assessment_plan.md",
        category: "security",
        contents: include_bytes!("../docs/certification_security_assessment_plan.md"),
    },
    ControlledReportFile {
        id: "DEVICE-PLAN-JSON",
        title: "Device evidence plan JSON",
        path: "docs/certification_device_evidence_plan.json",
        category: "device",
        contents: include_bytes!("../docs/certification_device_evidence_plan.json"),
    },
    ControlledReportFile {
        id: "DEVICE-PLAN-MD",
        title: "Device evidence plan Markdown",
        path: "docs/certification_device_evidence_plan.md",
        category: "device",
        contents: include_bytes!("../docs/certification_device_evidence_plan.md"),
    },
    ControlledReportFile {
        id: "INTEGRATION-PLAN-JSON",
        title: "Integration report plan JSON",
        path: "docs/certification_integration_report_plan.json",
        category: "integration",
        contents: include_bytes!("../docs/certification_integration_report_plan.json"),
    },
    ControlledReportFile {
        id: "INTEGRATION-PLAN-MD",
        title: "Integration report plan Markdown",
        path: "docs/certification_integration_report_plan.md",
        category: "integration",
        contents: include_bytes!("../docs/certification_integration_report_plan.md"),
    },
    ControlledReportFile {
        id: "OPEN-SOURCE-REVIEW",
        title: "Open-source reference review",
        path: "docs/open_source.md",
        category: "provenance",
        contents: include_bytes!("../docs/open_source.md"),
    },
    ControlledReportFile {
        id: "COVERAGE-DOCS",
        title: "Coverage workflow documentation",
        path: "docs/coverage.md",
        category: "quality",
        contents: include_bytes!("../docs/coverage.md"),
    },
    ControlledReportFile {
        id: "COVERAGE-SCRIPT",
        title: "Coverage workflow script",
        path: "scripts/coverage_100.sh",
        category: "quality",
        contents: include_bytes!("../scripts/coverage_100.sh"),
    },
    ControlledReportFile {
        id: "TUTORIAL-INDEX",
        title: "Tutorial index",
        path: "docs/tutorial/README.md",
        category: "education",
        contents: include_bytes!("../docs/tutorial/README.md"),
    },
    ControlledReportFile {
        id: "TUTORIAL-DATA-BUNDLES",
        title: "Data bundles and tooling tutorial",
        path: "docs/tutorial/08-data-bundles-and-tools.md",
        category: "education",
        contents: include_bytes!("../docs/tutorial/08-data-bundles-and-tools.md"),
    },
    ControlledReportFile {
        id: "TUTORIAL-GLOSSARY",
        title: "Tutorial glossary",
        path: "docs/tutorial/glossary.md",
        category: "education",
        contents: include_bytes!("../docs/tutorial/glossary.md"),
    },
];

const REPORT_FILE_EXCLUSIONS: &[ReportFileExclusion] = &[
    ReportFileExclusion {
        id: "REPORT-PACK-JSON",
        path: "docs/certification_report_pack.json",
        reason:
            "excluded from checked-in report file inventory to avoid self-referential hash churn",
    },
    ReportFileExclusion {
        id: "REPORT-PACK-MD",
        path: "docs/certification_report_pack.md",
        reason:
            "excluded from checked-in report file inventory to avoid self-referential hash churn",
    },
    ReportFileExclusion {
        id: "REPORT-UI",
        path: "docs/certification_report_ui.html",
        reason:
            "excluded from checked-in report file inventory to avoid self-referential hash churn",
    },
];

const REPORT_ARTIFACTS: &[ReportArtifact] = &[
    ReportArtifact {
        id: "SPEC",
        title: "Kernel specification",
        path: "docs/spec.md",
        category: "requirements",
        generator: "human-controlled annex",
        status: "repository-controlled",
        boundary: "licensed standards prevail on conflict",
    },
    ReportArtifact {
        id: "RTM",
        title: "Requirement traceability matrices",
        path: "docs/requirements_traceability.csv; docs/requirements-traceability-matrix.csv",
        category: "requirements",
        generator: "traceability tests",
        status: "repository-controlled",
        boundary: "lab test-case crosswalk remains external",
    },
    ReportArtifact {
        id: "MANIFEST",
        title: "Lab submission manifest",
        path: "docs/lab_submission_manifest.md",
        category: "submission",
        generator: "human-controlled annex",
        status: "repository-controlled template",
        boundary: "unattached report rows remain open",
    },
    ReportArtifact {
        id: "OPEN-ISSUES",
        title: "Certification open issues",
        path: "docs/certification_open_issues.md",
        category: "submission",
        generator: "human-controlled register",
        status: "repository-controlled",
        boundary: "controls external blockers",
    },
    ReportArtifact {
        id: "ABI",
        title: "ABI conformance statement",
        path: "docs/abi_conformance_statement.json",
        category: "conformance",
        generator: "cargo run --quiet --example krn_abi_conformance_statement",
        status: "generated",
        boundary: "not a signed lab conformance template",
    },
    ReportArtifact {
        id: "PROFILE-DICTIONARY",
        title: "Scheme profile dictionary",
        path: "docs/scheme_profile_dictionary.md",
        category: "configuration",
        generator: "cargo run --quiet --example krn_scheme_profile_dictionary",
        status: "generated",
        boundary: "does not disclose raw CAPK modulus material",
    },

    ReportArtifact {
        id: "DATA-BUNDLE",
        title: "Data-driven certification bundle",
        path: "docs/certification_data_bundle.json; docs/certification_data_bundle_trust_anchors.json; docs/certification_data_bundle.md; docs/certification_data_bundle_workbench.html; docs/certification_data_bundle_lint.json; docs/certification_data_bundle_lint.md",
        category: "configuration",
        generator: "cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle",
        status: "generated",
        boundary: "hash-pinned local bundle fixture; external authority signatures and lab acceptance remain required",
    },
    ReportArtifact {
        id: "TRACE-PACK",
        title: "Masked pre-lab APDU trace fixture",
        path: "docs/prelab_apdu_trace_pack.jsonl",
        category: "trace",
        generator: "cargo run --quiet --example krn_prelab_trace_pack",
        status: "generated",
        boundary: "full lab trace pack remains external",
    },
    ReportArtifact {
        id: "TRACE-PACK-AUDIT",
        title: "Masked pre-lab APDU trace-pack audit",
        path: "docs/prelab_trace_pack_audit.json; docs/prelab_trace_pack_audit.md",
        category: "trace",
        generator: "cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl",
        status: "generated",
        boundary: "fixture completeness and masking audit only; full lab trace-pack acceptance remains external",
    },
    ReportArtifact {
        id: "QUALITY-GATES",
        title: "Pre-lab quality gate manifest",
        path: "docs/prelab_quality_gates.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_quality_gates",
        status: "generated",
        boundary: "coverage and formal reports remain external",
    },
    ReportArtifact {
        id: "NO-CRASH",
        title: "Parser/APDU no-crash smoke artifact",
        path: "docs/prelab_no_crash_smoke.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_no_crash_smoke",
        status: "generated",
        boundary: "not a fuzzing report",
    },
    ReportArtifact {
        id: "STATIC-FUZZ-PLAN",
        title: "Static and fuzz evidence plan",
        path: "docs/prelab_static_fuzz_plan.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_static_fuzz_plan",
        status: "generated",
        boundary: "plan only; accepted reports remain external",
    },
    ReportArtifact {
        id: "FUZZ-SEEDS",
        title: "Fuzz seed corpus manifest",
        path: "docs/prelab_fuzz_seed_corpus.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_fuzz_seed_corpus",
        status: "generated",
        boundary: "hash-only synthetic seed evidence",
    },
    ReportArtifact {
        id: "STANDARDS-WATCH",
        title: "Public standards watch",
        path: "docs/public_standards_watch.json",
        category: "drift",
        generator: "cargo run --quiet --example krn_public_standards_watch",
        status: "generated",
        boundary: "public drift signal only",
    },
    ReportArtifact {
        id: "TOOLING-COMPLETENESS",
        title: "Tooling completeness audit",
        path: "docs/tooling_completeness_audit.json; docs/tooling_completeness_audit.md",
        category: "quality",
        generator: "cargo run --quiet --example krn_tooling_completeness_audit",
        status: "generated",
        boundary: "repository-controlled tooling audit only; external certification evidence remains required",
    },
    ReportArtifact {
        id: "EVIDENCE-CHECKLIST",
        title: "Certification evidence attachment checklist",
        path:
            "docs/certification_evidence_checklist.json; docs/certification_evidence_checklist.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_evidence_checklist",
        status: "generated",
        boundary: "attachment checklist only; does not close external gates",
    },
    ReportArtifact {
        id: "EVIDENCE-INTAKE",
        title: "Certification evidence intake ledger",
        path: "docs/certification_evidence_intake.json; docs/certification_evidence_intake.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_evidence_intake",
        status: "generated",
        boundary: "attachment slots only; accepted external evidence remains required",
    },
    ReportArtifact {
        id: "ARTIFACT-IMPORT",
        title: "Certification artifact import adapters",
        path: "docs/certification_artifact_import_plan.json; docs/certification_artifact_import_plan.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_artifact_import",
        status: "generated",
        boundary: "adapter plan, normalized integration bindings, and hash inventory only; accepted external evidence remains required",
    },
    ReportArtifact {
        id: "ATTACHMENT-SLOTS",
        title: "Certification attachment slot workspace",
        path: "target/hyperion-cert-workspace/attachments/CERT-OPEN-*; target/hyperion-cert-workspace/attachment_slot_guide.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace",
        status: "workspace-generated",
        boundary: "empty slots and operator guide only; attached files still require external review",
    },
    ReportArtifact {
        id: "ATTACHMENT-AUDIT",
        title: "Certification attachment hash audit",
        path: "target/hyperion-cert-workspace/attachment_audit.html; target/hyperion-cert-workspace/certification_attachment_audit.json; target/hyperion-cert-workspace/certification_attachment_audit.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace",
        status: "workspace-generated",
        boundary: "UI and hash inventory only; accepted external evidence remains required",
    },
    ReportArtifact {
        id: "WORKSPACE-INVENTORY",
        title: "Certification workspace file inventory",
        path: "target/hyperion-cert-workspace/workspace_inventory.json; target/hyperion-cert-workspace/workspace_inventory.md",
        category: "reporting",
        generator: "cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace",
        status: "workspace-generated",
        boundary: "hash inventory for generated local workspace files only; external evidence acceptance remains required",
    },
    ReportArtifact {
        id: "FREEZE-MANIFEST",
        title: "Certification freeze manifest",
        path: "docs/certification_freeze_manifest.json; docs/certification_freeze_manifest.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_freeze_manifest",
        status: "generated",
        boundary: "submitted-build hash slots only; external acceptance remains required",
    },
    ReportArtifact {
        id: "SECURITY-ASSESSMENT",
        title: "Certification security assessment plan",
        path: "docs/certification_security_assessment_plan.json; docs/certification_security_assessment_plan.md",
        category: "security",
        generator: "cargo run --quiet --example krn_certification_security_assessment_plan",
        status: "generated",
        boundary: "assessment plan only; external assessor report remains required",
    },
    ReportArtifact {
        id: "DEVICE-EVIDENCE",
        title: "Certification device evidence plan",
        path: "docs/certification_device_evidence_plan.json; docs/certification_device_evidence_plan.md",
        category: "device",
        generator: "cargo run --quiet --example krn_certification_device_evidence_plan",
        status: "generated",
        boundary: "device/L1/PED plan only; external approvals remain required",
    },
    ReportArtifact {
        id: "INTEGRATION-REPORT-PLAN",
        title: "Certification integration report plan",
        path: "docs/certification_integration_report_plan.json; docs/certification_integration_report_plan.md",
        category: "integration",
        generator: "cargo run --quiet --example krn_certification_integration_report_plan",
        status: "generated",
        boundary: "integration report plan only; full reports and trace packs remain external",
    },
    ReportArtifact {
        id: "REPORT-PACK",
        title: "Certification report pack",
        path: "docs/certification_report_pack.json; docs/certification_report_pack.md",
        category: "reporting",
        generator: "cargo run --quiet --example krn_certification_report_ui",
        status: "generated",
        boundary: "index only; external report attachments remain required",
    },
    ReportArtifact {
        id: "REPORT-UI",
        title: "Certification report workbench",
        path: "docs/certification_report_ui.html",
        category: "reporting",
        generator: "cargo run --quiet --example krn_certification_report_ui -- --html",
        status: "generated",
        boundary: "static local UI; not a lab portal or approval system",
    },
    ReportArtifact {
        id: "COVERAGE-WORKFLOW",
        title: "100% coverage workflow",
        path: "docs/coverage.md; scripts/coverage_100.sh; target/coverage/coverage_audit.json",
        category: "quality",
        generator: "scripts/coverage_100.sh; cargo run --quiet --example krn_coverage_package_audit",
        status: "prepared",
        boundary: "coverage package audit only; accepted submitted-build report remains external",
    },
    ReportArtifact {
        id: "TUTORIALS",
        title: "Tutorial and glossary learning path",
        path: "docs/tutorial/",
        category: "education",
        generator: "human-controlled docs",
        status: "repository-controlled",
        boundary: "education only; not approval evidence",
    },
];

const REQUIRED_REPORTS: &[RequiredReport] = &[
    RequiredReport {
        id: "CERT-REPORT-COVERAGE",
        title: "100% unit coverage report",
        status: "pending external attachment",
        required_evidence: "submitted commit, tool versions, target, feature set, coverage metadata JSON, and HTML/XML or lab-accepted report",
        closure_gate: "CERT-OPEN-009",
    },
    RequiredReport {
        id: "CERT-REPORT-INTEGRATION",
        title: "Full EMV integration report",
        status: "pending external attachment",
        required_evidence: "test-tool version, profile set, device firmware, APDU traces, outcomes, deviations, and disposition",
        closure_gate: "CERT-OPEN-009",
    },
    RequiredReport {
        id: "CERT-REPORT-STATIC",
        title: "Static-analysis report",
        status: "pending external attachment",
        required_evidence: "accepted tool version, command lines, findings, remediations, and residual-risk acceptance",
        closure_gate: "CERT-OPEN-010",
    },
    RequiredReport {
        id: "CERT-REPORT-FUZZ",
        title: "Fuzzing/no-crash report",
        status: "pending external attachment",
        required_evidence: "engine versions, corpus hashes, run budgets, coverage/path metrics, crashes, and dispositions",
        closure_gate: "CERT-OPEN-010",
    },
    RequiredReport {
        id: "CERT-REPORT-CONFORMANCE",
        title: "Signed conformance template and approval artifact",
        status: "pending external attachment",
        required_evidence: "recognized lab or authority-signed template tied to submitted binary, profile, and device scope",
        closure_gate: "CERT-OPEN-011",
    },
    RequiredReport {
        id: "CERT-REPORT-DEVICE",
        title: "Device, L1, and PCI/PED evidence",
        status: "pending external attachment",
        required_evidence: "target device approval, reader/L1 evidence, and PCI PTS/PED integration statement",
        closure_gate: "CERT-OPEN-006; CERT-OPEN-007",
    },
];

const TOOL_COMMANDS: &[ToolCommand] = &[
    ToolCommand {
        id: "UI",
        title: "Generate certification workbench UI",
        command: "cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui",
        output: "target/hyperion-cert-ui/index.html",
    },
    ToolCommand {
        id: "WORKSPACE",
        title: "Generate complete certification workspace",
        command: "cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace",
        output: "target/hyperion-cert-workspace/index.html, workspace_inventory.json, and workspace_manifest.json",
    },
    ToolCommand {
        id: "REPORT-JSON",
        title: "Emit report-pack JSON",
        command: "cargo run --quiet --example krn_certification_report_ui -- --json",
        output: "stdout JSON",
    },
    ToolCommand {
        id: "REPORT-MD",
        title: "Emit report-pack Markdown",
        command: "cargo run --quiet --example krn_certification_report_ui -- --markdown",
        output: "stdout Markdown",
    },
    ToolCommand {
        id: "EVIDENCE",
        title: "Emit certification evidence checklist",
        command: "cargo run --quiet --example krn_certification_evidence_checklist -- --out docs",
        output: "docs/certification_evidence_checklist.json and .md",
    },
    ToolCommand {
        id: "INTAKE",
        title: "Emit certification evidence intake ledger",
        command: "cargo run --quiet --example krn_certification_evidence_intake -- --out docs",
        output: "docs/certification_evidence_intake.json and .md",
    },
    ToolCommand {
        id: "ATTACHMENT-AUDIT",
        title: "Audit local certification evidence attachments",
        command: "cargo run --quiet --example krn_certification_attachment_audit -- --root target/hyperion-cert-attachments",
        output: "stdout JSON attachment hash inventory",
    },
    ToolCommand {
        id: "ARTIFACT-IMPORT",
        title: "Import and classify real certification artifacts",
        command: "cargo run --quiet --example krn_certification_artifact_import -- --root target/hyperion-cert-artifact-import",
        output: "stdout JSON artifact import inventory",
    },
    ToolCommand {
        id: "INTEGRATION-IMPORT",
        title: "Normalize external artifacts into bundle/report/freeze bindings",
        command: "cargo run --quiet --example krn_certification_artifact_import -- --integration-root target/hyperion-cert-artifact-import",
        output: "stdout JSON integration import report",
    },
    ToolCommand {
        id: "RELEASE-FREEZE",
        title: "Build repeatable release freeze bindings from staged artifacts",
        command: "cargo run --quiet --example krn_certification_artifact_import -- --release-freeze-root target/hyperion-cert-artifact-import",
        output: "stdout JSON release freeze binding report",
    },
    ToolCommand {
        id: "COVERAGE-AUDIT",
        title: "Audit staged coverage report package",
        command: "cargo run --quiet --example krn_coverage_package_audit -- --root target/coverage",
        output: "stdout JSON coverage package audit",
    },
    ToolCommand {
        id: "TRACE-AUDIT",
        title: "Audit masked APDU trace pack",
        command: "cargo run --quiet --example krn_trace_pack_audit -- --path docs/prelab_apdu_trace_pack.jsonl",
        output: "stdout JSON trace-pack audit",
    },

    ToolCommand {
        id: "DATA-BUNDLE",
        title: "Generate data-driven certification bundle and workbench",
        command: "cargo run --quiet --example krn_certification_bundle -- --out target/hyperion-cert-bundle",
        output: "target/hyperion-cert-bundle/certification_bundle.json, trust_anchors.json, index.html, bundle_fingerprints.json, and certification_bundle_lint.json",
    },
    ToolCommand {
        id: "DATA-BUNDLE-TUI",
        title: "Interactive TUI provisioner for certification bundle data",
        command: "cargo run --quiet --example krn_certification_bundle_tui -- --out target/hyperion-cert-bundle-tui",
        output: "target/hyperion-cert-bundle-tui/certification_bundle.json, trust_anchors.json, and index.html",
    },
    ToolCommand {
        id: "FREEZE",
        title: "Emit certification freeze manifest",
        command: "cargo run --quiet --example krn_certification_freeze_manifest -- --out docs",
        output: "docs/certification_freeze_manifest.json and .md",
    },
    ToolCommand {
        id: "SECURITY",
        title: "Emit certification security assessment plan",
        command: "cargo run --quiet --example krn_certification_security_assessment_plan -- --out docs",
        output: "docs/certification_security_assessment_plan.json and .md",
    },
    ToolCommand {
        id: "DEVICE",
        title: "Emit certification device evidence plan",
        command: "cargo run --quiet --example krn_certification_device_evidence_plan -- --out docs",
        output: "docs/certification_device_evidence_plan.json and .md",
    },
    ToolCommand {
        id: "INTEGRATION",
        title: "Emit certification integration report plan",
        command: "cargo run --quiet --example krn_certification_integration_report_plan -- --out docs",
        output: "docs/certification_integration_report_plan.json and .md",
    },
    ToolCommand {
        id: "POS",
        title: "Run basic scripted PoS integration",
        command: "cargo run --quiet --example krn_basic_pos",
        output: "stdout JSON transaction summary",
    },
    ToolCommand {
        id: "SOFTPOS",
        title: "Run basic mobile NFC SoftPoS integration",
        command: "cargo run --quiet --example krn_basic_softpos",
        output: "stdout JSON contactless transaction summary",
    },
    ToolCommand {
        id: "TIMEOUT-POLICY",
        title: "Emit ABI callback timeout policy",
        command: "cargo run --quiet --example krn_callback_timeout_policy",
        output: "stdout JSON timeout policy",
    },
    ToolCommand {
        id: "VARIABLE-DATA-BOUNDARY",
        title: "Audit production source variable-data boundary",
        command: "cargo run --quiet --example krn_variable_data_boundary_audit -- src",
        output: "stdout JSON boundary audit",
    },
    ToolCommand {
        id: "TOOLING-COMPLETENESS",
        title: "Emit tooling completeness audit",
        command: "cargo run --quiet --example krn_tooling_completeness_audit -- --out docs",
        output: "docs/tooling_completeness_audit.json and .md",
    },
];

pub fn certification_report_pack_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-report-pack");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "repository-controlled report production and certification preparation",
    );
    out.push_str(",\"does_not_close\":[");
    for (idx, issue) in [
        "CERT-OPEN-001",
        "CERT-OPEN-005",
        "CERT-OPEN-006",
        "CERT-OPEN-007",
        "CERT-OPEN-008",
        "CERT-OPEN-009",
        "CERT-OPEN-010",
        "CERT-OPEN-011",
        "CERT-OPEN-012",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, issue);
    }
    out.push_str("],\"requirements\":[");
    for (idx, requirement) in requirement_trace_rows().iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_requirement_trace_json(&mut out, requirement);
    }
    out.push_str("],\"artifacts\":[");
    for (idx, artifact) in REPORT_ARTIFACTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_report_artifact_json(&mut out, artifact);
    }
    out.push_str("],\"artifact_files\":[");
    for (idx, file) in CONTROLLED_REPORT_FILES.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_controlled_report_file_json(&mut out, file);
    }
    out.push_str("],\"artifact_file_exclusions\":[");
    for (idx, exclusion) in REPORT_FILE_EXCLUSIONS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_report_file_exclusion_json(&mut out, exclusion);
    }
    out.push_str("],\"required_reports\":[");
    for (idx, report) in REQUIRED_REPORTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_required_report_json(&mut out, report);
    }
    out.push_str("],\"open_gates\":[");
    for (idx, gate) in certification_evidence_requirements().iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_evidence_requirement_json(&mut out, gate);
    }
    out.push_str("],\"evidence_requirements\":[");
    for (idx, requirement) in certification_evidence_requirements().iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_evidence_requirement_json(&mut out, requirement);
    }
    out.push_str("],\"tool_commands\":[");
    for (idx, tool) in TOOL_COMMANDS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_tool_command_json(&mut out, tool);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_report_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Report Pack");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(
        out,
        "- Scope: repository-controlled report production and certification preparation"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Requirement Traceability");
    let _ = writeln!(
        out,
        "| Requirement | Text | Unit Test ID | Integration Test ID | EMVCo Ref | Evidence Artifact |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
    for requirement in requirement_trace_rows() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            requirement.id,
            requirement.text,
            requirement.unit_test_id,
            requirement.integration_test_id,
            requirement.emvco_ref,
            requirement.evidence_artifact
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Repository Artifacts");
    let _ = writeln!(
        out,
        "| ID | Title | Category | Path | Status | Generator | Boundary |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |");
    for artifact in REPORT_ARTIFACTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | {} | `{}` | {} |",
            artifact.id,
            artifact.title,
            artifact.category,
            artifact.path,
            artifact.status,
            artifact.generator,
            artifact.boundary
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Artifact File Integrity");
    let _ = writeln!(
        out,
        "| ID | Title | Category | Path | Size Bytes | SHA-256 |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
    for file in CONTROLLED_REPORT_FILES {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | {} | `{}` |",
            file.id,
            file.title,
            file.category,
            file.path,
            file.contents.len(),
            to_hex(&sha256(file.contents))
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "### Artifact File Inventory Exclusions");
    let _ = writeln!(out);
    let _ = writeln!(out, "| ID | Path | Reason |");
    let _ = writeln!(out, "| --- | --- | --- |");
    for exclusion in REPORT_FILE_EXCLUSIONS {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} |",
            exclusion.id, exclusion.path, exclusion.reason
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required External Reports");
    let _ = writeln!(
        out,
        "| ID | Title | Status | Required Evidence | Closure Gate |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for report in REQUIRED_REPORTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            report.id, report.title, report.status, report.required_evidence, report.closure_gate
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Open Certification Gates");
    let _ = writeln!(
        out,
        "| Gate | Area | Status | Required Attachment | Acceptance Gate | Repository Support |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
    for gate in certification_evidence_requirements() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | `{}` |",
            gate.open_issue,
            gate.area,
            gate.status,
            gate.required_attachment,
            gate.acceptance_gate,
            gate.repository_support
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence Attachment Checklist");
    let _ = writeln!(
        out,
        "| Open Issue | Area | Authority | Required Attachment | Metadata | Acceptance Gate | Repository Support | Status |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for requirement in certification_evidence_requirements() {
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
    let _ = writeln!(out, "## Tool Commands");
    let _ = writeln!(out, "| ID | Title | Command | Output |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for tool in TOOL_COMMANDS {
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | `{}` |",
            tool.id, tool.title, tool.command, tool.output
        );
    }
    out
}

pub fn certification_report_ui_html(abi_version: u32) -> String {
    let data = certification_report_pack_json(abi_version);
    let markdown = certification_report_markdown(abi_version);
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>Hyperion Certification Workbench</title>");
    out.push_str("<style>");
    out.push_str("*,*::before,*::after{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;color:#1b1f24;background:#f7f8fa;line-height:1.45}header{background:#0f1720;color:#f8fafc;padding:20px 24px;border-bottom:4px solid #1f9d8a}main{padding:18px 24px 28px;max-width:1480px;margin:0 auto}.topbar{display:flex;gap:16px;align-items:flex-end;justify-content:space-between;flex-wrap:wrap}.title{margin:0;font-size:26px;font-weight:720;letter-spacing:0}.meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;color:#cbd5df;font-size:13px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.toolbar button,.toolbar input{height:36px;border:1px solid #ccd3dc;background:#fff;color:#1b1f24;padding:0 10px;border-radius:6px;font:inherit}.toolbar button{cursor:pointer}.toolbar button[aria-pressed=\"true\"]{background:#1f9d8a;color:#fff;border-color:#1f9d8a}.toolbar input{min-width:260px}.summary{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:12px;margin:18px 0}.metric{background:#fff;border:1px solid #d9dee6;border-radius:8px;padding:14px}.metric strong{display:block;font-size:24px}.metric span{color:#52606d;font-size:13px}section{margin-top:18px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;border-bottom:1px solid #d9dee6;padding-bottom:8px}h2{font-size:17px;margin:0}.table-wrap{overflow:auto;background:#fff;border:1px solid #d9dee6;border-radius:8px}table{border-collapse:collapse;width:100%;min-width:920px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #edf0f4;padding:10px 12px;font-size:13px}th{position:sticky;top:0;background:#edf3f7;color:#23313f;font-size:12px;text-transform:uppercase}tr:last-child td{border-bottom:0}.status{font-weight:700;color:#8a4b00}.ok{color:#0b6e4f}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}.hidden{display:none}@media(max-width:1180px){.summary{grid-template-columns:repeat(3,minmax(130px,1fr))}}@media(max-width:780px){header,main{padding-left:14px;padding-right:14px}.title{font-size:22px}.summary{grid-template-columns:repeat(2,minmax(130px,1fr))}.toolbar{width:100%}.toolbar input{min-width:0;width:100%}}");
    out.push_str("</style></head><body><header><div class=\"topbar\"><div><h1 class=\"title\">Hyperion Certification Workbench</h1><div class=\"meta\"><span id=\"kernel\"></span><span id=\"abi\"></span><span id=\"scope\"></span></div></div><div class=\"toolbar\" role=\"toolbar\" aria-label=\"Workbench views\"><button data-view=\"requirements\" aria-pressed=\"true\">Requirements</button><button data-view=\"artifacts\" aria-pressed=\"false\">Artifacts</button><button data-view=\"files\" aria-pressed=\"false\">Files</button><button data-view=\"reports\" aria-pressed=\"false\">Reports</button><button data-view=\"gates\" aria-pressed=\"false\">Gates</button><button data-view=\"evidence\" aria-pressed=\"false\">Evidence</button><button data-view=\"tools\" aria-pressed=\"false\">Tools</button><button id=\"download-json\">JSON</button><button id=\"download-md\">Markdown</button><input id=\"search\" type=\"search\" placeholder=\"Filter\" aria-label=\"Filter rows\"></div></div></header><main><div class=\"summary\"><div class=\"metric\"><strong id=\"requirement-count\">0</strong><span>kernel requirements</span></div><div class=\"metric\"><strong id=\"artifact-count\">0</strong><span>repository artifacts</span></div><div class=\"metric\"><strong id=\"file-count\">0</strong><span>hashed files</span></div><div class=\"metric\"><strong id=\"report-count\">0</strong><span>required reports</span></div><div class=\"metric\"><strong id=\"evidence-count\">0</strong><span>evidence attachments</span></div><div class=\"metric\"><strong id=\"tool-count\">0</strong><span>tool commands</span></div><div class=\"metric\"><strong id=\"open-count\">0</strong><span>open external gates</span></div></div>");
    out.push_str("<section id=\"requirements\"><div class=\"section-head\"><h2>Requirement Traceability</h2></div><div class=\"table-wrap\"><table><thead><tr><th>Requirement</th><th>Text</th><th>Unit Test ID</th><th>Integration Test ID</th><th>EMVCo Ref</th><th>Evidence Artifact</th></tr></thead><tbody id=\"requirement-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"artifacts\" class=\"hidden\"><div class=\"section-head\"><h2>Repository Artifacts</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Path</th><th>Status</th><th>Generator</th><th>Boundary</th></tr></thead><tbody id=\"artifact-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"files\" class=\"hidden\"><div class=\"section-head\"><h2>Artifact File Integrity</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Path</th><th>Size</th><th>SHA-256</th></tr></thead><tbody id=\"file-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"reports\" class=\"hidden\"><div class=\"section-head\"><h2>Required External Reports</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Required Evidence</th><th>Closure Gate</th></tr></thead><tbody id=\"report-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"gates\" class=\"hidden\"><div class=\"section-head\"><h2>Open Certification Gates</h2></div><div class=\"table-wrap\"><table><thead><tr><th>Gate</th><th>Area</th><th>Status</th><th>Required Attachment</th><th>Acceptance Gate</th><th>Repository Support</th></tr></thead><tbody id=\"gate-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"evidence\" class=\"hidden\"><div class=\"section-head\"><h2>Evidence Attachment Checklist</h2></div><div class=\"table-wrap\"><table><thead><tr><th>Open Issue</th><th>Area</th><th>Authority</th><th>Required Attachment</th><th>Metadata</th><th>Acceptance Gate</th><th>Repository Support</th><th>Status</th></tr></thead><tbody id=\"evidence-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"tools\" class=\"hidden\"><div class=\"section-head\"><h2>Tool Commands</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Command</th><th>Output</th></tr></thead><tbody id=\"tool-body\"></tbody></table></div></section>");
    out.push_str("</main><script id=\"report-data\" type=\"application/json\">");
    push_html_text(&mut out, &data);
    out.push_str("</script><script id=\"report-markdown\" type=\"text/plain\">");
    push_html_text(&mut out, &markdown);
    out.push_str("</script><script>");
    out.push_str("const data=JSON.parse(document.getElementById('report-data').textContent);const markdown=document.getElementById('report-markdown').textContent;const q=document.getElementById('search');const views=['requirements','artifacts','files','reports','gates','evidence','tools'];function esc(v){return String(v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}function cell(v,cls=''){return `<td class=\"${cls}\">${esc(v)}</td>`;}function render(){const term=q.value.toLowerCase();document.getElementById('kernel').textContent=`${data.kernel_name} ${data.kernel_version}`;document.getElementById('abi').textContent=`ABI ${data.abi_version}`;document.getElementById('scope').textContent=data.scope;document.getElementById('requirement-count').textContent=data.requirements.length;document.getElementById('artifact-count').textContent=data.artifacts.length;document.getElementById('file-count').textContent=data.artifact_files.length;document.getElementById('report-count').textContent=data.required_reports.length;document.getElementById('evidence-count').textContent=data.evidence_requirements.length;document.getElementById('tool-count').textContent=data.tool_commands.length;document.getElementById('open-count').textContent=data.open_gates.length;const match=o=>JSON.stringify(o).toLowerCase().includes(term);document.getElementById('requirement-body').innerHTML=data.requirements.filter(match).map(r=>`<tr>${cell(r.id,'mono')}${cell(r.text)}${cell(r.unit_test_id,'mono')}${cell(r.integration_test_id,'mono')}${cell(r.emvco_ref,'mono')}${cell(r.evidence_artifact,'mono')}</tr>`).join('');document.getElementById('artifact-body').innerHTML=data.artifacts.filter(match).map(a=>`<tr>${cell(a.id,'mono')}${cell(a.title)}${cell(a.category)}${cell(a.path,'mono')}${cell(a.status,a.status==='generated'?'ok':'')}${cell(a.generator,'mono')}${cell(a.boundary)}</tr>`).join('');document.getElementById('file-body').innerHTML=data.artifact_files.filter(match).map(f=>`<tr>${cell(f.id,'mono')}${cell(f.title)}${cell(f.category)}${cell(f.path,'mono')}${cell(f.size_bytes)}${cell(f.sha256,'mono')}</tr>`).join('');document.getElementById('report-body').innerHTML=data.required_reports.filter(match).map(r=>`<tr>${cell(r.id,'mono')}${cell(r.title)}${cell(r.status,'status')}${cell(r.required_evidence)}${cell(r.closure_gate,'mono')}</tr>`).join('');document.getElementById('gate-body').innerHTML=data.open_gates.filter(match).map(g=>`<tr>${cell(g.open_issue,'mono')}${cell(g.area)}${cell(g.status,'status')}${cell(g.required_attachment)}${cell(g.acceptance_gate)}${cell(g.repository_support,'mono')}</tr>`).join('');document.getElementById('evidence-body').innerHTML=data.evidence_requirements.filter(match).map(e=>`<tr>${cell(e.open_issue,'mono')}${cell(e.area)}${cell(e.authority)}${cell(e.required_attachment)}${cell(e.required_metadata)}${cell(e.acceptance_gate)}${cell(e.repository_support,'mono')}${cell(e.status,'status')}</tr>`).join('');document.getElementById('tool-body').innerHTML=data.tool_commands.filter(match).map(t=>`<tr>${cell(t.id,'mono')}${cell(t.title)}${cell(t.command,'mono')}${cell(t.output,'mono')}</tr>`).join('');}function show(view){views.forEach(v=>document.getElementById(v).classList.toggle('hidden',v!==view));document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.view===view)));}function download(name,type,text){const blob=new Blob([text],{type});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();URL.revokeObjectURL(a.href);}document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.view)));document.getElementById('download-json').addEventListener('click',()=>download('hyperion-certification-report-pack.json','application/json',JSON.stringify(data,null,2)));document.getElementById('download-md').addEventListener('click',()=>download('hyperion-certification-report-pack.md','text/markdown',markdown));q.addEventListener('input',render);render();");
    out.push_str("</script></body></html>\n");
    out
}

fn requirement_trace_rows() -> Vec<RequirementTrace> {
    REQUIREMENTS_TRACEABILITY
        .lines()
        .skip(1)
        .filter_map(requirement_trace_row)
        .collect()
}

fn requirement_trace_row(line: &str) -> Option<RequirementTrace> {
    let fields = parse_csv_line(line);
    if fields.len() != 6 || !fields[0].starts_with("KRN-") {
        return None;
    }
    Some(RequirementTrace {
        id: fields[0].clone(),
        text: fields[1].clone(),
        unit_test_id: fields[2].clone(),
        integration_test_id: fields[3].clone(),
        emvco_ref: fields[4].clone(),
        evidence_artifact: fields[5].clone(),
    })
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                field.push('"');
                let _ = chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(field.trim().to_string());
                field.clear();
            }
            _ => field.push(ch),
        }
    }

    fields.push(field.trim().to_string());
    fields
}

fn push_requirement_trace_json(out: &mut String, requirement: &RequirementTrace) {
    out.push('{');
    push_json_str(out, "id", &requirement.id);
    out.push(',');
    push_json_str(out, "text", &requirement.text);
    out.push(',');
    push_json_str(out, "unit_test_id", &requirement.unit_test_id);
    out.push(',');
    push_json_str(out, "integration_test_id", &requirement.integration_test_id);
    out.push(',');
    push_json_str(out, "emvco_ref", &requirement.emvco_ref);
    out.push(',');
    push_json_str(out, "evidence_artifact", &requirement.evidence_artifact);
    out.push('}');
}

fn push_report_artifact_json(out: &mut String, artifact: &ReportArtifact) {
    out.push('{');
    push_json_str(out, "id", artifact.id);
    out.push(',');
    push_json_str(out, "title", artifact.title);
    out.push(',');
    push_json_str(out, "path", artifact.path);
    out.push(',');
    push_json_str(out, "category", artifact.category);
    out.push(',');
    push_json_str(out, "generator", artifact.generator);
    out.push(',');
    push_json_str(out, "status", artifact.status);
    out.push(',');
    push_json_str(out, "boundary", artifact.boundary);
    out.push('}');
}

fn push_controlled_report_file_json(out: &mut String, file: &ControlledReportFile) {
    out.push('{');
    push_json_str(out, "id", file.id);
    out.push(',');
    push_json_str(out, "title", file.title);
    out.push(',');
    push_json_str(out, "path", file.path);
    out.push(',');
    push_json_str(out, "category", file.category);
    out.push(',');
    push_json_number(out, "size_bytes", file.contents.len() as u64);
    out.push(',');
    push_json_str(out, "sha256", &to_hex(&sha256(file.contents)));
    out.push('}');
}

fn push_report_file_exclusion_json(out: &mut String, exclusion: &ReportFileExclusion) {
    out.push('{');
    push_json_str(out, "id", exclusion.id);
    out.push(',');
    push_json_str(out, "path", exclusion.path);
    out.push(',');
    push_json_str(out, "reason", exclusion.reason);
    out.push('}');
}

fn push_required_report_json(out: &mut String, report: &RequiredReport) {
    out.push('{');
    push_json_str(out, "id", report.id);
    out.push(',');
    push_json_str(out, "title", report.title);
    out.push(',');
    push_json_str(out, "status", report.status);
    out.push(',');
    push_json_str(out, "required_evidence", report.required_evidence);
    out.push(',');
    push_json_str(out, "closure_gate", report.closure_gate);
    out.push('}');
}

fn push_evidence_requirement_json(out: &mut String, requirement: &EvidenceRequirement) {
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

fn push_tool_command_json(out: &mut String, tool: &ToolCommand) {
    out.push('{');
    push_json_str(out, "id", tool.id);
    out.push(',');
    push_json_str(out, "title", tool.title);
    out.push(',');
    push_json_str(out, "command", tool.command);
    out.push(',');
    push_json_str(out, "output", tool.output);
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

fn push_html_text(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
}

fn hex_nibble(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[usize::from(value & 0x0f)] as char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_pack_json_lists_artifacts_reports_and_tools_without_approval_claims() {
        let json = certification_report_pack_json(2);

        assert!(json.contains("\"type\":\"certification-report-pack\""));
        assert!(json.contains("\"abi_version\":2"));
        assert!(json.contains("\"requirements\""));
        assert!(json.contains("\"id\":\"KRN-SCR-006\""));
        assert!(json.contains(
            "critical_issuer_script_failure_before_final_sets_before_final_tvr_and_stops"
        ));
        assert!(json.contains("docs/prelab_quality_gates.json"));
        assert!(json.contains("CERT-REPORT-COVERAGE"));
        assert!(json.contains("\"artifact_files\""));
        assert!(json.contains("\"id\":\"SPEC\""));
        assert!(json.contains("\"path\":\"docs/spec.md\""));
        assert!(json.contains("\"sha256\""));
        assert!(json.contains("\"artifact_file_exclusions\""));
        assert!(json.contains("self-referential hash churn"));
        assert!(json.contains("\"open_gates\""));
        assert!(json.contains("\"open_issue\":\"CERT-OPEN-009\""));
        assert!(json.contains("krn_certification_report_ui"));
        assert!(json.contains("krn_basic_pos"));
        assert!(json.contains("krn_callback_timeout_policy"));
        assert!(json.contains("krn_variable_data_boundary_audit"));
        assert!(json.contains("CERT-OPEN-011"));
        assert!(!json.contains("certified\":true"));
    }

    #[test]
    fn report_ui_embeds_downloadable_json_and_markdown() {
        let html = certification_report_ui_html(2);

        assert!(html.contains("Hyperion Certification Workbench"));
        assert!(html.contains("Requirement Traceability"));
        assert!(html.contains("requirement-body"));
        assert!(html.contains("download-json"));
        assert!(html.contains("report-data"));
        assert!(html.contains("Repository Artifacts"));
        assert!(html.contains("Artifact File Integrity"));
        assert!(html.contains("file-body"));
        assert!(html.contains("Required External Reports"));
        assert!(html.contains("Open Certification Gates"));
        assert!(html.contains("gate-body"));
        assert!(html.contains("Tool Commands"));
        assert!(html.contains("docs/prelab_apdu_trace_pack.jsonl"));
    }

    #[test]
    fn report_markdown_is_table_shaped_and_scoped() {
        let markdown = certification_report_markdown(2);

        assert!(markdown.contains("# Hyperion Certification Report Pack"));
        assert!(markdown.contains("## Requirement Traceability"));
        assert!(markdown.contains("## Artifact File Integrity"));
        assert!(markdown.contains("### Artifact File Inventory Exclusions"));
        assert!(markdown.contains("## Open Certification Gates"));
        assert!(
            markdown.contains(
                "| Requirement | Text | Unit Test ID | Integration Test ID | EMVCo Ref | Evidence Artifact |"
            )
        );
        assert!(markdown.contains("| ID | Title | Category | Path | Size Bytes | SHA-256 |"));
        assert!(markdown.contains(
            "| Gate | Area | Status | Required Attachment | Acceptance Gate | Repository Support |"
        ));
        assert!(
            markdown.contains("| ID | Title | Category | Path | Status | Generator | Boundary |")
        );
        assert!(markdown.contains("pending external attachment"));
        assert!(markdown.contains("cargo run --quiet --example krn_basic_pos"));
        assert!(markdown.contains("cargo run --quiet --example krn_callback_timeout_policy"));
    }

    #[test]
    fn report_serializers_escape_json_html_and_reject_bad_trace_rows() {
        let mut json = String::new();
        push_json_string(
            &mut json,
            "quote\" slash\\ line\ncarriage\rtab\t high\x1f byte\u{00ff}",
        );
        assert_eq!(
            json,
            "\"quote\\\" slash\\\\ line\\ncarriage\\rtab\\t high\\u001f byte\\u00c3\\u00bf\""
        );

        let mut html = String::new();
        push_html_text(&mut html, "<tag attr='x'>&value</tag>");
        assert_eq!(html, "&lt;tag attr='x'&gt;&amp;value&lt;/tag&gt;");

        assert!(requirement_trace_row("not-a-krn,row").is_none());
        assert!(requirement_trace_row("KRN-X,too,few").is_none());
    }
}
