use hyperion_emv::conformance::baseline_conformance_statement;
use hyperion_emv::device::{
    certification_device_evidence_plan_json, certification_device_evidence_plan_markdown,
};
use hyperion_emv::evidence::{
    certification_evidence_checklist_json, certification_evidence_checklist_markdown,
    certification_evidence_intake_ledger_json, certification_evidence_intake_ledger_markdown,
};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::freeze::{
    certification_freeze_manifest_json, certification_freeze_manifest_markdown,
};
use hyperion_emv::integration::{
    certification_integration_report_plan_json, certification_integration_report_plan_markdown,
};
use hyperion_emv::quality::{
    prelab_fuzz_seed_corpus_json, prelab_no_crash_smoke_json, prelab_quality_gates_json,
    prelab_static_fuzz_plan_json, public_standards_watch_json,
};
use hyperion_emv::reporting::{
    certification_report_markdown, certification_report_pack_json, certification_report_ui_html,
};
use hyperion_emv::security::{
    certification_security_assessment_plan_json, certification_security_assessment_plan_markdown,
};
use hyperion_emv::KernelResult;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process;

struct WorkspaceFile {
    id: &'static str,
    path: &'static str,
    category: &'static str,
    description: &'static str,
}

const WORKSPACE_FILES: &[WorkspaceFile] = &[
    WorkspaceFile {
        id: "README",
        path: "README.txt",
        category: "operator-guide",
        description: "local instructions and certification boundary notice",
    },
    WorkspaceFile {
        id: "UI",
        path: "index.html",
        category: "workbench",
        description: "static certification report workbench",
    },
    WorkspaceFile {
        id: "REPORT-PACK-JSON",
        path: "report_pack.json",
        category: "reporting",
        description: "machine-readable report-pack index",
    },
    WorkspaceFile {
        id: "REPORT-PACK-MD",
        path: "report_pack.md",
        category: "reporting",
        description: "Markdown report-pack export",
    },
    WorkspaceFile {
        id: "ABI",
        path: "abi_conformance_statement.json",
        category: "conformance",
        description: "repository ABI conformance statement",
    },
    WorkspaceFile {
        id: "QUALITY-GATES",
        path: "prelab_quality_gates.json",
        category: "quality",
        description: "local pre-lab quality gate manifest",
    },
    WorkspaceFile {
        id: "NO-CRASH",
        path: "prelab_no_crash_smoke.json",
        category: "quality",
        description: "parser and APDU no-crash smoke artifact",
    },
    WorkspaceFile {
        id: "STATIC-FUZZ",
        path: "prelab_static_fuzz_plan.json",
        category: "quality",
        description: "static-analysis and fuzzing evidence plan",
    },
    WorkspaceFile {
        id: "FUZZ-SEEDS",
        path: "prelab_fuzz_seed_corpus.json",
        category: "quality",
        description: "hash-only fuzz seed corpus manifest",
    },
    WorkspaceFile {
        id: "STANDARDS-WATCH",
        path: "public_standards_watch.json",
        category: "drift",
        description: "public standards drift signal manifest",
    },
    WorkspaceFile {
        id: "EVIDENCE-CHECKLIST-JSON",
        path: "certification_evidence_checklist.json",
        category: "submission",
        description: "external evidence checklist JSON",
    },
    WorkspaceFile {
        id: "EVIDENCE-CHECKLIST-MD",
        path: "certification_evidence_checklist.md",
        category: "submission",
        description: "external evidence checklist Markdown",
    },
    WorkspaceFile {
        id: "EVIDENCE-INTAKE-JSON",
        path: "certification_evidence_intake.json",
        category: "submission",
        description: "crowdsourced evidence intake ledger JSON",
    },
    WorkspaceFile {
        id: "EVIDENCE-INTAKE-MD",
        path: "certification_evidence_intake.md",
        category: "submission",
        description: "crowdsourced evidence intake ledger Markdown",
    },
    WorkspaceFile {
        id: "FREEZE-JSON",
        path: "certification_freeze_manifest.json",
        category: "submission",
        description: "submitted-build freeze manifest JSON",
    },
    WorkspaceFile {
        id: "FREEZE-MD",
        path: "certification_freeze_manifest.md",
        category: "submission",
        description: "submitted-build freeze manifest Markdown",
    },
    WorkspaceFile {
        id: "SECURITY-JSON",
        path: "certification_security_assessment_plan.json",
        category: "security",
        description: "third-party security assessment plan JSON",
    },
    WorkspaceFile {
        id: "SECURITY-MD",
        path: "certification_security_assessment_plan.md",
        category: "security",
        description: "third-party security assessment plan Markdown",
    },
    WorkspaceFile {
        id: "DEVICE-JSON",
        path: "certification_device_evidence_plan.json",
        category: "device",
        description: "device, Level 1, and PCI/PED evidence plan JSON",
    },
    WorkspaceFile {
        id: "DEVICE-MD",
        path: "certification_device_evidence_plan.md",
        category: "device",
        description: "device, Level 1, and PCI/PED evidence plan Markdown",
    },
    WorkspaceFile {
        id: "INTEGRATION-JSON",
        path: "certification_integration_report_plan.json",
        category: "integration",
        description: "integration report and trace-pack control plan JSON",
    },
    WorkspaceFile {
        id: "INTEGRATION-MD",
        path: "certification_integration_report_plan.md",
        category: "integration",
        description: "integration report and trace-pack control plan Markdown",
    },
    WorkspaceFile {
        id: "WORKSPACE-MANIFEST",
        path: "workspace_manifest.json",
        category: "workbench",
        description: "manifest for files generated into this workspace",
    },
];

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => write_workspace(Path::new("target/hyperion-cert-workspace"), KRN_ABI_VERSION).map(
            |dir| {
                println!("{}", dir.join("index.html").display());
            },
        ),
        [flag] if flag == "--manifest" => {
            print!("{}", certification_workspace_manifest_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_workspace(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!("{}", dir.join("index.html").display());
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_workspace -- [--manifest|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification workspace: {err}");
        process::exit(1);
    }
}

fn write_workspace(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    write_file(dir, "README.txt", &workspace_readme())?;
    write_file(
        dir,
        "index.html",
        &certification_report_ui_html(abi_version),
    )?;
    write_file(
        dir,
        "report_pack.json",
        &certification_report_pack_json(abi_version),
    )?;
    write_file(
        dir,
        "report_pack.md",
        &certification_report_markdown(abi_version),
    )?;
    write_file(
        dir,
        "abi_conformance_statement.json",
        &baseline_conformance_statement(abi_version).canonical_json(),
    )?;
    write_file(
        dir,
        "prelab_quality_gates.json",
        &prelab_quality_gates_json(abi_version),
    )?;
    write_file(
        dir,
        "prelab_no_crash_smoke.json",
        &kernel_result(prelab_no_crash_smoke_json())?,
    )?;
    write_file(
        dir,
        "prelab_static_fuzz_plan.json",
        &prelab_static_fuzz_plan_json(),
    )?;
    write_file(
        dir,
        "prelab_fuzz_seed_corpus.json",
        &kernel_result(prelab_fuzz_seed_corpus_json())?,
    )?;
    write_file(
        dir,
        "public_standards_watch.json",
        &public_standards_watch_json(),
    )?;
    write_file(
        dir,
        "certification_evidence_checklist.json",
        &certification_evidence_checklist_json(abi_version),
    )?;
    write_file(
        dir,
        "certification_evidence_checklist.md",
        &certification_evidence_checklist_markdown(abi_version),
    )?;
    write_file(
        dir,
        "certification_evidence_intake.json",
        &certification_evidence_intake_ledger_json(abi_version),
    )?;
    write_file(
        dir,
        "certification_evidence_intake.md",
        &certification_evidence_intake_ledger_markdown(abi_version),
    )?;
    write_file(
        dir,
        "certification_freeze_manifest.json",
        &certification_freeze_manifest_json(abi_version),
    )?;
    write_file(
        dir,
        "certification_freeze_manifest.md",
        &certification_freeze_manifest_markdown(abi_version),
    )?;
    write_file(
        dir,
        "certification_security_assessment_plan.json",
        &certification_security_assessment_plan_json(abi_version),
    )?;
    write_file(
        dir,
        "certification_security_assessment_plan.md",
        &certification_security_assessment_plan_markdown(abi_version),
    )?;
    write_file(
        dir,
        "certification_device_evidence_plan.json",
        &certification_device_evidence_plan_json(abi_version),
    )?;
    write_file(
        dir,
        "certification_device_evidence_plan.md",
        &certification_device_evidence_plan_markdown(abi_version),
    )?;
    write_file(
        dir,
        "certification_integration_report_plan.json",
        &certification_integration_report_plan_json(abi_version),
    )?;
    write_file(
        dir,
        "certification_integration_report_plan.md",
        &certification_integration_report_plan_markdown(abi_version),
    )?;
    write_file(
        dir,
        "workspace_manifest.json",
        &certification_workspace_manifest_json(abi_version),
    )?;
    Ok(dir)
}

fn write_file(dir: &Path, name: &str, contents: &str) -> io::Result<()> {
    fs::write(dir.join(name), contents)
}

fn kernel_result(value: KernelResult<String>) -> io::Result<String> {
    value.map_err(|err| io::Error::new(io::ErrorKind::Other, err.name()))
}

fn workspace_readme() -> String {
    "Hyperion Certification Workspace\n\nOpen index.html to inspect repository-controlled reports and artifact status.\nThis directory is a local report-production workspace only. It does not close\nexternal lab, scheme, device, PCI/PED, acquirer, or approval gates.\n\nRegenerate with:\n  cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace\n\nAttach only reviewed artifacts to a certification package, and bind them to the\nsubmitted binary, profiles, CAPKs, vectors, traceability matrix, device scope,\nand accepted external reports.\n"
        .to_string()
}

fn certification_workspace_manifest_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-workspace-manifest");
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
        "local report-production workspace for repository-controlled certification artifacts",
    );
    out.push(',');
    push_json_str(&mut out, "entrypoint", "index.html");
    out.push(',');
    push_json_str(
        &mut out,
        "command",
        "cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace",
    );
    out.push_str(",\"does_not_close\":[");
    for (idx, issue) in [
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
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, issue);
    }
    out.push_str("],\"files\":[");
    for (idx, file) in WORKSPACE_FILES.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", file.id);
        out.push(',');
        push_json_str(&mut out, "path", file.path);
        out.push(',');
        push_json_str(&mut out, "category", file.category);
        out.push(',');
        push_json_str(&mut out, "description", file.description);
        out.push('}');
    }
    out.push_str("]}\n");
    out
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
    fn writes_complete_certification_workspace() {
        let dir = env::temp_dir().join(format!("hyperion-cert-workspace-test-{}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_workspace(&dir, 2).unwrap();

        for file in WORKSPACE_FILES {
            assert!(
                dir.join(file.path).exists(),
                "workspace should contain {}",
                file.path
            );
        }
        let manifest = fs::read_to_string(dir.join("workspace_manifest.json")).unwrap();
        let index = fs::read_to_string(dir.join("index.html")).unwrap();
        let report = fs::read_to_string(dir.join("report_pack.json")).unwrap();
        assert!(manifest.contains("\"type\":\"certification-workspace-manifest\""));
        assert!(manifest.contains("\"entrypoint\":\"index.html\""));
        assert!(manifest.contains("\"CERT-OPEN-009\""));
        assert!(index.contains("Hyperion Certification Workbench"));
        assert!(report.contains("\"type\":\"certification-report-pack\""));

        fs::remove_dir_all(&dir).unwrap();
    }
}
