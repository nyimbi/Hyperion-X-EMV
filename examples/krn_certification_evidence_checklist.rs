use hyperion_emv::evidence::{
    certification_evidence_checklist_json, certification_evidence_checklist_markdown,
};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => {
            print!("{}", certification_evidence_checklist_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!("{}", certification_evidence_checklist_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!(
                "{}",
                certification_evidence_checklist_markdown(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_checklist(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_evidence_checklist.json").display()
                )
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_evidence_checklist -- [--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification evidence checklist: {err}");
        process::exit(1);
    }
}

fn write_checklist(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("certification_evidence_checklist.json"),
        certification_evidence_checklist_json(abi_version),
    )?;
    fs::write(
        dir.join("certification_evidence_checklist.md"),
        certification_evidence_checklist_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_and_markdown_checklists() {
        let dir = env::temp_dir().join(format!(
            "hyperion-evidence-checklist-test-{}",
            process::id()
        ));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_checklist(&dir, 2).unwrap();

        let json = fs::read_to_string(dir.join("certification_evidence_checklist.json")).unwrap();
        let markdown = fs::read_to_string(dir.join("certification_evidence_checklist.md")).unwrap();
        assert!(json.contains("\"type\":\"certification-evidence-checklist\""));
        assert!(markdown.contains("# Hyperion Certification Evidence Checklist"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
