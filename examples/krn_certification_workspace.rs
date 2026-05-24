use hyperion_emv::conformance::baseline_conformance_statement;
use hyperion_emv::device::{
    certification_device_evidence_plan_json, certification_device_evidence_plan_markdown,
};
use hyperion_emv::evidence::{
    audit_certification_attachments, certification_attachment_audit_json,
    certification_attachment_audit_markdown, certification_evidence_checklist_json,
    certification_evidence_checklist_markdown, certification_evidence_intake_ledger_json,
    certification_evidence_intake_ledger_markdown, certification_evidence_requirements,
    CertificationAttachmentAudit,
};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::freeze::{
    certification_freeze_manifest_json, certification_freeze_manifest_markdown,
};
use hyperion_emv::integration::{
    certification_integration_report_plan_json, certification_integration_report_plan_markdown,
};
use hyperion_emv::provenance::{sha256, to_hex};
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
use std::fmt::Write;
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

struct WorkspaceInventoryEntry {
    id: &'static str,
    path: &'static str,
    category: &'static str,
    description: &'static str,
    kind: &'static str,
    status: &'static str,
    size_bytes: u64,
    sha256: String,
}

const WORKSPACE_INVENTORY_EXCLUDED_PATHS: &[&str] = &[
    "workspace_inventory.json",
    "workspace_inventory.md",
    "workspace_manifest.json",
];

const PRELAB_APDU_TRACE_PACK: &str = include_str!("../docs/prelab_apdu_trace_pack.jsonl");
const PRELAB_TRACE_PACK_AUDIT_JSON: &str = include_str!("../docs/prelab_trace_pack_audit.json");
const PRELAB_TRACE_PACK_AUDIT_MARKDOWN: &str = include_str!("../docs/prelab_trace_pack_audit.md");

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
        id: "TRACE-PACK",
        path: "prelab_apdu_trace_pack.jsonl",
        category: "trace",
        description: "masked repository pre-lab APDU trace fixture",
    },
    WorkspaceFile {
        id: "TRACE-PACK-AUDIT-JSON",
        path: "prelab_trace_pack_audit.json",
        category: "trace",
        description: "machine-readable audit of the masked pre-lab APDU trace fixture",
    },
    WorkspaceFile {
        id: "TRACE-PACK-AUDIT-MD",
        path: "prelab_trace_pack_audit.md",
        category: "trace",
        description: "reviewable Markdown audit of the masked pre-lab APDU trace fixture",
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
        id: "ATTACHMENT-GUIDE",
        path: "attachment_slot_guide.md",
        category: "submission",
        description: "human instructions for placing external evidence into attachment slots",
    },
    WorkspaceFile {
        id: "ATTACHMENT-ROOT",
        path: "attachments",
        category: "submission",
        description:
            "empty CERT-OPEN-* directories where reviewed external artifacts can be staged",
    },
    WorkspaceFile {
        id: "ATTACHMENT-AUDIT-JSON",
        path: "certification_attachment_audit.json",
        category: "submission",
        description: "hash inventory of files staged under attachment slots",
    },
    WorkspaceFile {
        id: "ATTACHMENT-AUDIT-MD",
        path: "certification_attachment_audit.md",
        category: "submission",
        description: "Markdown hash inventory of files staged under attachment slots",
    },
    WorkspaceFile {
        id: "ATTACHMENT-AUDIT-UI",
        path: "attachment_audit.html",
        category: "workbench",
        description: "static UI for staged evidence slot status and attachment hashes",
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
        id: "WORKSPACE-INVENTORY-JSON",
        path: "workspace_inventory.json",
        category: "workbench",
        description: "machine-readable hash inventory for generated workspace files",
    },
    WorkspaceFile {
        id: "WORKSPACE-INVENTORY-MD",
        path: "workspace_inventory.md",
        category: "workbench",
        description: "Markdown hash inventory for generated workspace files",
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
    write_file(dir, "prelab_apdu_trace_pack.jsonl", PRELAB_APDU_TRACE_PACK)?;
    write_file(
        dir,
        "prelab_trace_pack_audit.json",
        PRELAB_TRACE_PACK_AUDIT_JSON,
    )?;
    write_file(
        dir,
        "prelab_trace_pack_audit.md",
        PRELAB_TRACE_PACK_AUDIT_MARKDOWN,
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
    let attachment_root = dir.join("attachments");
    write_attachment_slot_dirs(&attachment_root)?;
    write_file(dir, "attachment_slot_guide.md", &attachment_slot_guide())?;
    let attachment_audit = audit_certification_attachments(&attachment_root)?;
    write_file(
        dir,
        "certification_attachment_audit.json",
        &certification_attachment_audit_json(abi_version, &attachment_audit),
    )?;
    write_file(
        dir,
        "certification_attachment_audit.md",
        &certification_attachment_audit_markdown(abi_version, &attachment_audit),
    )?;
    write_file(
        dir,
        "attachment_audit.html",
        &attachment_audit_html(abi_version, &attachment_audit),
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
    let inventory_entries = workspace_inventory_entries(dir)?;
    write_file(
        dir,
        "workspace_inventory.json",
        &certification_workspace_inventory_json(abi_version, &inventory_entries),
    )?;
    write_file(
        dir,
        "workspace_inventory.md",
        &certification_workspace_inventory_markdown(abi_version, &inventory_entries),
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

fn workspace_inventory_entries(dir: &Path) -> io::Result<Vec<WorkspaceInventoryEntry>> {
    let mut entries = Vec::new();
    for file in WORKSPACE_FILES {
        if workspace_inventory_excludes(file.path) {
            continue;
        }

        let path = dir.join(file.path);
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            entries.push(WorkspaceInventoryEntry {
                id: file.id,
                path: file.path,
                category: file.category,
                description: file.description,
                kind: "directory",
                status: "present",
                size_bytes: 0,
                sha256: "not-applicable".to_string(),
            });
            continue;
        }

        let bytes = fs::read(&path)?;
        entries.push(WorkspaceInventoryEntry {
            id: file.id,
            path: file.path,
            category: file.category,
            description: file.description,
            kind: "file",
            status: "present",
            size_bytes: bytes.len() as u64,
            sha256: to_hex(&sha256(&bytes)),
        });
    }
    Ok(entries)
}

fn workspace_inventory_excludes(path: &str) -> bool {
    WORKSPACE_INVENTORY_EXCLUDED_PATHS.contains(&path)
}

fn kernel_result(value: KernelResult<String>) -> io::Result<String> {
    value.map_err(|err| io::Error::new(io::ErrorKind::Other, err.name()))
}

fn write_attachment_slot_dirs(root: &Path) -> io::Result<()> {
    fs::create_dir_all(root)?;
    for requirement in certification_evidence_requirements() {
        fs::create_dir_all(root.join(requirement.open_issue))?;
    }
    Ok(())
}

fn attachment_slot_guide() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Attachment Slots");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Place reviewed external evidence under `attachments/CERT-OPEN-*` only after confirming the artifact scope, authority, submitted-build hash, and sensitivity policy."
    );
    let _ = writeln!(
        out,
        "Regenerate `certification_attachment_audit.json` and `.md` after adding files so the package records SHA-256 values before review."
    );
    let _ = writeln!(
        out,
        "Empty directories are intentionally reported as `missing`; local files are only `present_unreviewed` until an accepted authority closes the matching gate."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Slot | Area | Required Attachment | Required Metadata |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for requirement in certification_evidence_requirements() {
        let _ = writeln!(
            out,
            "| `attachments/{}` | {} | {} | {} |",
            requirement.open_issue,
            requirement.area,
            requirement.required_attachment,
            requirement.required_metadata
        );
    }
    out
}

fn workspace_readme() -> String {
    "Hyperion Certification Workspace\n\nOpen index.html to inspect repository-controlled reports and artifact status.\nOpen attachment_audit.html to inspect staged evidence slot status and hashes.\nRead prelab_apdu_trace_pack.jsonl with prelab_trace_pack_audit.json or .md to\nreview the repository-controlled masked trace fixture before replacing it with\naccepted lab/test-tool traces.\nRead workspace_inventory.json or workspace_inventory.md for the generated\nworkspace file-size and SHA-256 inventory.\nThis directory is a local report-production workspace only. It does not close\nexternal lab, scheme, device, PCI/PED, acquirer, or approval gates.\n\nRegenerate with:\n  cargo run --quiet --example krn_certification_workspace -- --out target/hyperion-cert-workspace\n\nStage external artifacts under attachments/CERT-OPEN-* only after checking the\nartifact scope and sensitivity policy. Then regenerate or rerun the attachment\naudit so SHA-256 values are captured before review.\n\nAttach only reviewed artifacts to a certification package, and bind them to the\nsubmitted binary, profiles, CAPKs, vectors, traceability matrix, device scope,\nand accepted external reports.\n"
        .to_string()
}

fn attachment_audit_html(abi_version: u32, audit: &CertificationAttachmentAudit) -> String {
    let missing = audit
        .slots
        .iter()
        .filter(|slot| slot.status == "missing")
        .count();
    let present = audit
        .slots
        .iter()
        .filter(|slot| slot.status == "present_unreviewed")
        .count();
    let attachment_count = audit
        .slots
        .iter()
        .map(|slot| slot.attachments.len())
        .sum::<usize>()
        + audit.unmapped_attachments.len();
    let rejected_count = audit
        .slots
        .iter()
        .map(|slot| slot.rejected_attachments.len())
        .sum::<usize>()
        + audit.rejected_unmapped_attachments.len();

    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>Hyperion Attachment Audit</title>");
    out.push_str("<style>");
    out.push_str("*,*::before,*::after{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;color:#1b1f24;background:#f7f8fa;line-height:1.45}header{background:#0f1720;color:#f8fafc;padding:20px 24px;border-bottom:4px solid #1f9d8a}main{max-width:1480px;margin:0 auto;padding:18px 24px 28px}.title{margin:0;font-size:26px;font-weight:720;letter-spacing:0}.meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;color:#cbd5df;font-size:13px}.links{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.links a{display:inline-flex;align-items:center;height:34px;border:1px solid #ccd3dc;background:#fff;color:#1b1f24;text-decoration:none;padding:0 10px;border-radius:6px}.summary{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:12px;margin:18px 0}.metric{background:#fff;border:1px solid #d9dee6;border-radius:8px;padding:14px}.metric strong{display:block;font-size:24px}.metric span{color:#52606d;font-size:13px}.notice{background:#fff9e8;border:1px solid #f0d28a;border-radius:8px;padding:12px 14px;margin:16px 0}section{margin-top:18px}.table-wrap{overflow:auto;background:#fff;border:1px solid #d9dee6;border-radius:8px}table{border-collapse:collapse;width:100%;min-width:980px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #edf0f4;padding:10px 12px;font-size:13px}th{position:sticky;top:0;background:#edf3f7;color:#23313f;font-size:12px;text-transform:uppercase}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}.status{font-weight:700;color:#8a4b00}.ok{color:#0b6e4f}@media(max-width:780px){header,main{padding-left:14px;padding-right:14px}.title{font-size:22px}.summary{grid-template-columns:repeat(2,minmax(130px,1fr))}}");
    out.push_str("</style></head><body><header><h1 class=\"title\">Hyperion Attachment Audit</h1><div class=\"meta\"><span>Kernel ");
    push_html_text(&mut out, env!("CARGO_PKG_VERSION"));
    out.push_str("</span><span>ABI ");
    let _ = write!(out, "{abi_version}");
    out.push_str("</span><span>Root ");
    push_html_text(&mut out, &audit.root);
    out.push_str("</span></div><div class=\"links\"><a href=\"index.html\">Report Workbench</a><a href=\"attachment_slot_guide.md\">Slot Guide</a><a href=\"certification_attachment_audit.json\">Audit JSON</a><a href=\"certification_attachment_audit.md\">Audit Markdown</a></div></header><main>");
    out.push_str("<div class=\"summary\"><div class=\"metric\"><strong>");
    let _ = write!(out, "{}", audit.slots.len());
    out.push_str("</strong><span>attachment slots</span></div><div class=\"metric\"><strong>");
    let _ = write!(out, "{present}");
    out.push_str("</strong><span>present unreviewed</span></div><div class=\"metric\"><strong>");
    let _ = write!(out, "{missing}");
    out.push_str("</strong><span>missing slots</span></div><div class=\"metric\"><strong>");
    let _ = write!(out, "{attachment_count}");
    out.push_str("</strong><span>local files hashed</span></div><div class=\"metric\"><strong>");
    let _ = write!(out, "{rejected_count}");
    out.push_str("</strong><span>rejected entries</span></div></div>");
    out.push_str("<div class=\"notice\">Hash inventory only. Files shown here are not accepted certification evidence until the relevant external authority, signer, reviewer, submitted-build scope, and disposition are recorded. Rejected entries, including symlinks, must be replaced by reviewable regular files before package assembly.</div>");
    out.push_str("<section><h2>Attachment Slots</h2><div class=\"table-wrap\"><table><thead><tr><th>Open Issue</th><th>Area</th><th>Status</th><th>Attachments</th><th>Required Metadata</th><th>Acceptance Gate</th></tr></thead><tbody>");
    for slot in &audit.slots {
        out.push_str("<tr><td class=\"mono\">");
        push_html_text(&mut out, slot.open_issue);
        out.push_str("</td><td>");
        push_html_text(&mut out, slot.area);
        out.push_str("</td><td class=\"status\">");
        push_html_text(&mut out, slot.status);
        out.push_str("</td><td>");
        if slot.attachments.is_empty() && slot.rejected_attachments.is_empty() {
            out.push_str("none");
        } else {
            let mut wrote = false;
            for (idx, attachment) in slot.attachments.iter().enumerate() {
                if idx > 0 {
                    out.push_str("<br>");
                }
                wrote = true;
                out.push_str("<span class=\"mono\">");
                push_html_text(&mut out, &attachment.path);
                out.push_str("</span> ");
                let _ = write!(out, "({} bytes, ", attachment.size_bytes);
                out.push_str("<span class=\"mono\">");
                push_html_text(&mut out, &attachment.sha256);
                out.push_str("</span>)");
            }
            for rejection in &slot.rejected_attachments {
                if wrote {
                    out.push_str("<br>");
                }
                wrote = true;
                out.push_str("rejected <span class=\"mono\">");
                push_html_text(&mut out, &rejection.path);
                out.push_str("</span> (");
                push_html_text(&mut out, rejection.reason);
                out.push(')');
            }
        }
        out.push_str("</td><td>");
        push_html_text(&mut out, slot.required_metadata);
        out.push_str("</td><td>");
        push_html_text(&mut out, slot.acceptance_gate);
        out.push_str("</td></tr>");
    }
    out.push_str("</tbody></table></div></section>");
    if !audit.unmapped_attachments.is_empty() {
        out.push_str("<section><h2>Unmapped Attachments</h2><div class=\"table-wrap\"><table><thead><tr><th>Path</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>");
        for attachment in &audit.unmapped_attachments {
            out.push_str("<tr><td class=\"mono\">");
            push_html_text(&mut out, &attachment.path);
            out.push_str("</td><td>");
            let _ = write!(out, "{}", attachment.size_bytes);
            out.push_str("</td><td class=\"mono\">");
            push_html_text(&mut out, &attachment.sha256);
            out.push_str("</td></tr>");
        }
        out.push_str("</tbody></table></div></section>");
    }
    if !audit.rejected_unmapped_attachments.is_empty() {
        out.push_str("<section><h2>Rejected Unmapped Attachments</h2><div class=\"table-wrap\"><table><thead><tr><th>Path</th><th>Reason</th></tr></thead><tbody>");
        for rejection in &audit.rejected_unmapped_attachments {
            out.push_str("<tr><td class=\"mono\">");
            push_html_text(&mut out, &rejection.path);
            out.push_str("</td><td>");
            push_html_text(&mut out, rejection.reason);
            out.push_str("</td></tr>");
        }
        out.push_str("</tbody></table></div></section>");
    }
    out.push_str("</main></body></html>\n");
    out
}

fn certification_workspace_inventory_json(
    abi_version: u32,
    entries: &[WorkspaceInventoryEntry],
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-workspace-inventory");
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
        "file-size and SHA-256 inventory for generated local workspace artifacts",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "boundary",
        "workspace hash inventory only; external certification gates remain open",
    );
    out.push(',');
    push_json_str(
        &mut out,
        "exclusion_policy",
        "self-referential inventory files and workspace_manifest.json are listed as exclusions",
    );
    out.push_str(",\"excluded_paths\":[");
    for (idx, path) in WORKSPACE_INVENTORY_EXCLUDED_PATHS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "path", path);
        out.push(',');
        push_json_str(
            &mut out,
            "reason",
            "excluded to avoid self-referential or manifest-after-inventory hashing",
        );
        out.push('}');
    }
    out.push_str("],\"files\":[");
    for (idx, entry) in entries.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", entry.id);
        out.push(',');
        push_json_str(&mut out, "path", entry.path);
        out.push(',');
        push_json_str(&mut out, "category", entry.category);
        out.push(',');
        push_json_str(&mut out, "kind", entry.kind);
        out.push(',');
        push_json_str(&mut out, "status", entry.status);
        out.push(',');
        push_json_number(&mut out, "size_bytes", entry.size_bytes);
        out.push(',');
        push_json_str(&mut out, "sha256", &entry.sha256);
        out.push(',');
        push_json_str(&mut out, "description", entry.description);
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

fn certification_workspace_inventory_markdown(
    abi_version: u32,
    entries: &[WorkspaceInventoryEntry],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Workspace Inventory");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(
        out,
        "- Scope: file-size and SHA-256 inventory for generated local workspace artifacts"
    );
    let _ = writeln!(
        out,
        "- Boundary: workspace hash inventory only; external certification gates remain open"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Excluded Paths");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Path | Reason |");
    let _ = writeln!(out, "| --- | --- |");
    for path in WORKSPACE_INVENTORY_EXCLUDED_PATHS {
        let _ = writeln!(
            out,
            "| `{path}` | excluded to avoid self-referential or manifest-after-inventory hashing |"
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Inventory");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| ID | Path | Category | Kind | Status | Size Bytes | SHA-256 | Description |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for entry in entries {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {} | {} | {} | `{}` | {} |",
            entry.id,
            entry.path,
            entry.category,
            entry.kind,
            entry.status,
            entry.size_bytes,
            entry.sha256,
            entry.description
        );
    }
    out
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

fn push_html_text(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
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
        let audit_html = fs::read_to_string(dir.join("attachment_audit.html")).unwrap();
        let inventory = fs::read_to_string(dir.join("workspace_inventory.json")).unwrap();
        let inventory_markdown = fs::read_to_string(dir.join("workspace_inventory.md")).unwrap();
        let report = fs::read_to_string(dir.join("report_pack.json")).unwrap();
        assert!(manifest.contains("\"type\":\"certification-workspace-manifest\""));
        assert!(manifest.contains("\"entrypoint\":\"index.html\""));
        assert!(manifest.contains("\"CERT-OPEN-009\""));
        assert!(manifest.contains("certification_attachment_audit.json"));
        assert!(manifest.contains("prelab_apdu_trace_pack.jsonl"));
        assert!(manifest.contains("prelab_trace_pack_audit.json"));
        assert!(manifest.contains("attachment_audit.html"));
        assert!(manifest.contains("workspace_inventory.json"));
        assert!(dir.join("attachments/CERT-OPEN-001").is_dir());
        assert!(dir.join("attachments/CERT-OPEN-012").is_dir());
        assert!(dir.join("attachment_slot_guide.md").exists());
        assert!(dir.join("certification_attachment_audit.json").exists());
        assert!(dir.join("prelab_apdu_trace_pack.jsonl").exists());
        assert!(dir.join("prelab_trace_pack_audit.json").exists());
        assert!(dir.join("prelab_trace_pack_audit.md").exists());
        assert!(dir.join("attachment_audit.html").exists());
        assert!(dir.join("workspace_inventory.json").exists());
        assert!(dir.join("workspace_inventory.md").exists());
        assert!(index.contains("Hyperion Certification Workbench"));
        assert!(audit_html.contains("Hyperion Attachment Audit"));
        assert!(audit_html.contains("Report Workbench"));
        assert!(audit_html.contains("present unreviewed"));
        assert!(audit_html.contains("Hash inventory only"));
        assert!(audit_html.contains("rejected entries"));
        assert!(audit_html.contains("symlinks"));
        assert!(inventory.contains("\"type\":\"certification-workspace-inventory\""));
        assert!(inventory.contains("\"path\":\"prelab_apdu_trace_pack.jsonl\""));
        assert!(inventory.contains("\"path\":\"prelab_trace_pack_audit.json\""));
        assert!(inventory.contains("\"path\":\"attachment_audit.html\""));
        assert!(inventory.contains("\"sha256\""));
        assert!(inventory.contains("\"path\":\"workspace_manifest.json\""));
        assert!(inventory.contains("self-referential"));
        assert!(inventory_markdown.contains("Hyperion Certification Workspace Inventory"));
        assert!(inventory_markdown.contains("prelab_trace_pack_audit.md"));
        assert!(inventory_markdown.contains("workspace_manifest.json"));
        assert!(!inventory.contains("certified\":true"));
        assert!(report.contains("\"type\":\"certification-report-pack\""));

        fs::remove_dir_all(&dir).unwrap();
    }
}
