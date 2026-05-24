use hyperion_emv::evidence::{
    audit_certification_attachments, certification_attachment_audit_json,
    certification_attachment_audit_markdown, DEFAULT_CERTIFICATION_ATTACHMENT_ROOT,
};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => emit_json(Path::new(DEFAULT_CERTIFICATION_ATTACHMENT_ROOT)),
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
    let audit = audit_certification_attachments(root)?;
    print!(
        "{}",
        certification_attachment_audit_json(KRN_ABI_VERSION, &audit)
    );
    Ok(())
}

fn emit_markdown(root: &Path) -> io::Result<()> {
    let audit = audit_certification_attachments(root)?;
    print!(
        "{}",
        certification_attachment_audit_markdown(KRN_ABI_VERSION, &audit)
    );
    Ok(())
}

fn write_audit(dir: &Path, root: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let audit = audit_certification_attachments(root)?;
    fs::write(
        dir.join("certification_attachment_audit.json"),
        certification_attachment_audit_json(KRN_ABI_VERSION, &audit),
    )?;
    fs::write(
        dir.join("certification_attachment_audit.md"),
        certification_attachment_audit_markdown(KRN_ABI_VERSION, &audit),
    )?;
    Ok(dir.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_emv::evidence::certification_evidence_requirements;
    use hyperion_emv::provenance::{sha256, to_hex};

    #[test]
    fn cli_library_audit_hashes_mapped_and_unmapped_files() {
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

        let audit = audit_certification_attachments(&root).unwrap();
        let json = certification_attachment_audit_json(KRN_ABI_VERSION, &audit);
        let markdown = certification_attachment_audit_markdown(KRN_ABI_VERSION, &audit);

        assert!(json.contains("\"type\":\"certification-attachment-audit\""));
        assert!(json.contains("\"open_issue\":\"CERT-OPEN-001\""));
        assert!(json.contains("\"status\":\"present_unreviewed\""));
        assert!(json.contains("\"status\":\"missing\""));
        assert!(json.contains(&to_hex(&sha256(b"lab approval"))));
        assert!(json.contains("unmapped/notes.txt"));
        assert!(json.contains("\"rejected_attachments\":[]"));
        assert!(json.contains("\"rejected_unmapped_attachments\":[]"));
        assert!(markdown.contains("# Hyperion Certification Attachment Audit"));
        assert!(markdown.contains("accepted external authority review is still required"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cli_library_audit_absent_root_yields_missing_slots_without_error() {
        let root =
            env::temp_dir().join(format!("hyperion-attachment-audit-empty-{}", process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }

        let audit = audit_certification_attachments(&root).unwrap();

        assert_eq!(
            audit.slots.len(),
            certification_evidence_requirements().len()
        );
        assert!(audit.slots.iter().all(|slot| slot.status == "missing"));
        assert!(audit.unmapped_attachments.is_empty());
        assert!(audit.rejected_unmapped_attachments.is_empty());
    }
}
