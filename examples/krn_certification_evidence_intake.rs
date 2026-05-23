use hyperion_emv::evidence::{
    certification_evidence_intake_ledger_json, certification_evidence_intake_ledger_markdown,
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
            print!(
                "{}",
                certification_evidence_intake_ledger_json(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!(
                "{}",
                certification_evidence_intake_ledger_json(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!(
                "{}",
                certification_evidence_intake_ledger_markdown(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_intake_ledger(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_evidence_intake.json").display()
                )
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_evidence_intake -- [--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification evidence intake ledger: {err}");
        process::exit(1);
    }
}

fn write_intake_ledger(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("certification_evidence_intake.json"),
        certification_evidence_intake_ledger_json(abi_version),
    )?;
    fs::write(
        dir.join("certification_evidence_intake.md"),
        certification_evidence_intake_ledger_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_and_markdown_intake_ledger() {
        let dir = env::temp_dir().join(format!("hyperion-evidence-intake-test-{}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_intake_ledger(&dir, 2).unwrap();

        let json = fs::read_to_string(dir.join("certification_evidence_intake.json")).unwrap();
        let markdown = fs::read_to_string(dir.join("certification_evidence_intake.md")).unwrap();
        assert!(json.contains("\"type\":\"certification-evidence-intake-ledger\""));
        assert!(json.contains("\"slot_id\":\"CERT-OPEN-001-ATTACHMENT\""));
        assert!(markdown.contains("# Hyperion Certification Evidence Intake Ledger"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
