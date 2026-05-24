use hyperion_emv::evidence::{certification_evidence_requirements, EvidenceRequirement};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::provenance::{sha256, to_hex};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

const DEFAULT_ATTACHMENT_ROOT: &str = "target/hyperion-cert-attachments";

#[derive(Clone, Debug, Eq, PartialEq)]
struct Attachment {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlotAudit {
    open_issue: &'static str,
    area: &'static str,
    required_attachment: &'static str,
    required_metadata: &'static str,
    acceptance_gate: &'static str,
    status: &'static str,
    attachments: Vec<Attachment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttachmentAudit {
    root: String,
    slots: Vec<SlotAudit>,
    unmapped_attachments: Vec<Attachment>,
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => emit_json(Path::new(DEFAULT_ATTACHMENT_ROOT)),
        [flag, root] if flag == "--root" => emit_json(Path::new(root)),
        [flag, root, format] if flag == "--root" && format == "--markdown" => {
            emit_markdown(Path::new(root))
        }
        [out_flag, out_dir, root_flag, root] if out_flag == "--out" && root_flag == "--root" => {
            write_audit(Path::new(out_dir), Path::new(root)).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_attachment_audit.json").display()
                )
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_attachment_audit -- [--root <dir> [--markdown]|--out <dir> --root <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to audit certification attachments: {err}");
        process::exit(1);
    }
}

fn emit_json(root: &Path) -> io::Result<()> {
    let audit = audit_attachments(root)?;
    print!("{}", audit_json(&audit));
    Ok(())
}

fn emit_markdown(root: &Path) -> io::Result<()> {
    let audit = audit_attachments(root)?;
    print!("{}", audit_markdown(&audit));
    Ok(())
}

fn write_audit(dir: &Path, root: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let audit = audit_attachments(root)?;
    fs::write(
        dir.join("certification_attachment_audit.json"),
        audit_json(&audit),
    )?;
    fs::write(
        dir.join("certification_attachment_audit.md"),
        audit_markdown(&audit),
    )?;
    Ok(dir.to_path_buf())
}

fn audit_attachments(root: &Path) -> io::Result<AttachmentAudit> {
    let mut slots = Vec::new();
    for requirement in certification_evidence_requirements() {
        slots.push(audit_slot(root, requirement)?);
    }

    let mut unmapped_attachments = Vec::new();
    if root.is_dir() {
        let known = certification_evidence_requirements()
            .iter()
            .map(|requirement| requirement.open_issue)
            .collect::<Vec<_>>();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if known.iter().any(|issue| *issue == name) {
                continue;
            }
            if entry.file_type()?.is_file() {
                unmapped_attachments.push(read_attachment(root, &entry.path())?);
            } else if entry.file_type()?.is_dir() {
                collect_attachments(root, &entry.path(), &mut unmapped_attachments)?;
            }
        }
        unmapped_attachments.sort_by(|left, right| left.path.cmp(&right.path));
    }

    Ok(AttachmentAudit {
        root: root.display().to_string(),
        slots,
        unmapped_attachments,
    })
}

fn audit_slot(root: &Path, requirement: &'static EvidenceRequirement) -> io::Result<SlotAudit> {
    let slot_dir = root.join(requirement.open_issue);
    let mut attachments = Vec::new();
    if slot_dir.is_dir() {
        collect_attachments(root, &slot_dir, &mut attachments)?;
        attachments.sort_by(|left, right| left.path.cmp(&right.path));
    }
    let status = if attachments.is_empty() {
        "missing"
    } else {
        "present_unreviewed"
    };
    Ok(SlotAudit {
        open_issue: requirement.open_issue,
        area: requirement.area,
        required_attachment: requirement.required_attachment,
        required_metadata: requirement.required_metadata,
        acceptance_gate: requirement.acceptance_gate,
        status,
        attachments,
    })
}

fn collect_attachments(root: &Path, dir: &Path, out: &mut Vec<Attachment>) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_attachments(root, &entry.path(), out)?;
        } else if file_type.is_file() {
            out.push(read_attachment(root, &entry.path())?);
        }
    }
    Ok(())
}

fn read_attachment(root: &Path, path: &Path) -> io::Result<Attachment> {
    let bytes = fs::read(path)?;
    let relative = path.strip_prefix(root).unwrap_or(path);
    Ok(Attachment {
        path: normalize_path(relative),
        size_bytes: bytes.len() as u64,
        sha256: to_hex(&sha256(&bytes)),
    })
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn audit_json(audit: &AttachmentAudit) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-attachment-audit");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", KRN_ABI_VERSION as u64);
    out.push(',');
    push_json_str(&mut out, "attachment_root", &audit.root);
    out.push(',');
    push_json_str(
        &mut out,
        "boundary",
        "hash inventory only; accepted external authority review is still required before any CERT-OPEN item can close",
    );
    out.push_str(",\"slots\":[");
    for (idx, slot) in audit.slots.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_slot_json(&mut out, slot);
    }
    out.push_str("],\"unmapped_attachments\":[");
    for (idx, attachment) in audit.unmapped_attachments.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_attachment_json(&mut out, attachment);
    }
    out.push_str("]}\n");
    out
}

fn audit_markdown(audit: &AttachmentAudit) -> String {
    let mut out = String::new();
    out.push_str("# Hyperion Certification Attachment Audit\n\n");
    out.push_str(&format!(
        "- Kernel version: {}\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!("- ABI version: {KRN_ABI_VERSION}\n"));
    out.push_str(&format!("- Attachment root: `{}`\n", audit.root));
    out.push_str(
        "- Boundary: hash inventory only; accepted external authority review is still required before any `CERT-OPEN-*` item can close.\n\n",
    );
    out.push_str("## Slots\n");
    out.push_str(
        "| Open Issue | Area | Status | Attachments | Required Metadata | Acceptance Gate |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for slot in &audit.slots {
        let attachments = if slot.attachments.is_empty() {
            "none".to_string()
        } else {
            slot.attachments
                .iter()
                .map(|attachment| {
                    format!(
                        "`{}` ({} bytes, `{}`)",
                        attachment.path, attachment.size_bytes, attachment.sha256
                    )
                })
                .collect::<Vec<_>>()
                .join("<br>")
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            slot.open_issue,
            slot.area,
            slot.status,
            attachments,
            slot.required_metadata,
            slot.acceptance_gate
        ));
    }
    if !audit.unmapped_attachments.is_empty() {
        out.push_str("\n## Unmapped Attachments\n");
        for attachment in &audit.unmapped_attachments {
            out.push_str(&format!(
                "- `{}`: {} bytes, SHA-256 `{}`\n",
                attachment.path, attachment.size_bytes, attachment.sha256
            ));
        }
    }
    out
}

fn push_slot_json(out: &mut String, slot: &SlotAudit) {
    out.push('{');
    push_json_str(out, "open_issue", slot.open_issue);
    out.push(',');
    push_json_str(out, "area", slot.area);
    out.push(',');
    push_json_str(out, "status", slot.status);
    out.push(',');
    push_json_str(out, "required_attachment", slot.required_attachment);
    out.push(',');
    push_json_str(out, "required_metadata", slot.required_metadata);
    out.push(',');
    push_json_str(out, "acceptance_gate", slot.acceptance_gate);
    out.push_str(",\"attachments\":[");
    for (idx, attachment) in slot.attachments.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_attachment_json(out, attachment);
    }
    out.push_str("]}");
}

fn push_attachment_json(out: &mut String, attachment: &Attachment) {
    out.push('{');
    push_json_str(out, "path", &attachment.path);
    out.push(',');
    push_json_number(out, "size_bytes", attachment.size_bytes);
    out.push(',');
    push_json_str(out, "sha256", &attachment.sha256);
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
    fn audits_attachment_hashes_and_missing_slots() {
        let root = env::temp_dir().join(format!("hyperion-attachment-audit-{}", process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(root.join("CERT-OPEN-001")).unwrap();
        fs::create_dir_all(root.join("CERT-OPEN-009/coverage")).unwrap();
        fs::create_dir_all(root.join("unmapped")).unwrap();
        fs::write(root.join("CERT-OPEN-001/lab-approval.txt"), b"lab approval").unwrap();
        fs::write(root.join("CERT-OPEN-009/coverage/report.txt"), b"coverage").unwrap();
        fs::write(root.join("unmapped/notes.txt"), b"notes").unwrap();

        let audit = audit_attachments(&root).unwrap();
        let json = audit_json(&audit);
        let markdown = audit_markdown(&audit);

        assert!(json.contains("\"type\":\"certification-attachment-audit\""));
        assert!(json.contains("\"open_issue\":\"CERT-OPEN-001\""));
        assert!(json.contains("\"status\":\"present_unreviewed\""));
        assert!(json.contains("\"status\":\"missing\""));
        assert!(json.contains(&to_hex(&sha256(b"lab approval"))));
        assert!(json.contains("unmapped/notes.txt"));
        assert!(markdown.contains("# Hyperion Certification Attachment Audit"));
        assert!(markdown.contains("accepted external authority review is still required"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn absent_root_yields_missing_slots_without_error() {
        let root =
            env::temp_dir().join(format!("hyperion-attachment-audit-empty-{}", process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }

        let audit = audit_attachments(&root).unwrap();

        assert_eq!(
            audit.slots.len(),
            certification_evidence_requirements().len()
        );
        assert!(audit.slots.iter().all(|slot| slot.status == "missing"));
        assert!(audit.unmapped_attachments.is_empty());
    }
}
