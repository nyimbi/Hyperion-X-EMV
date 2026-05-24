use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::tooling::{tooling_completeness_audit_json, tooling_completeness_audit_markdown};
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => {
            print!("{}", tooling_completeness_audit_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!("{}", tooling_completeness_audit_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!("{}", tooling_completeness_audit_markdown(KRN_ABI_VERSION));
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_tooling_completeness_audit(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!("{}", dir.join("tooling_completeness_audit.json").display());
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_tooling_completeness_audit -- [--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate tooling completeness audit: {err}");
        process::exit(1);
    }
}

fn write_tooling_completeness_audit(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("tooling_completeness_audit.json"),
        tooling_completeness_audit_json(abi_version),
    )?;
    fs::write(
        dir.join("tooling_completeness_audit.md"),
        tooling_completeness_audit_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_and_markdown_tooling_audit() {
        let dir = env::temp_dir().join(format!("hyperion-tooling-audit-test-{}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_tooling_completeness_audit(&dir, 2).unwrap();

        let json = fs::read_to_string(dir.join("tooling_completeness_audit.json")).unwrap();
        let markdown = fs::read_to_string(dir.join("tooling_completeness_audit.md")).unwrap();
        assert!(json.contains("\"type\":\"tooling-completeness-audit\""));
        assert!(json.contains("\"status\":\"repo-controlled-tools-complete\""));
        assert!(markdown.contains("# Hyperion Tooling Completeness Audit"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
