use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::freeze::{
    certification_freeze_manifest_json, certification_freeze_manifest_markdown,
};
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => {
            print!("{}", certification_freeze_manifest_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!("{}", certification_freeze_manifest_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!(
                "{}",
                certification_freeze_manifest_markdown(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag, dir] if flag == "--out" => write_freeze_manifest(Path::new(dir), KRN_ABI_VERSION)
            .map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_freeze_manifest.json").display()
                )
            }),
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_freeze_manifest -- [--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification freeze manifest: {err}");
        process::exit(1);
    }
}

fn write_freeze_manifest(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("certification_freeze_manifest.json"),
        certification_freeze_manifest_json(abi_version),
    )?;
    fs::write(
        dir.join("certification_freeze_manifest.md"),
        certification_freeze_manifest_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_and_markdown_freeze_manifest() {
        let dir = env::temp_dir().join(format!("hyperion-freeze-manifest-test-{}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_freeze_manifest(&dir, 2).unwrap();

        let json = fs::read_to_string(dir.join("certification_freeze_manifest.json")).unwrap();
        let markdown = fs::read_to_string(dir.join("certification_freeze_manifest.md")).unwrap();
        assert!(json.contains("\"type\":\"certification-freeze-manifest-template\""));
        assert!(json.contains("\"kernel_binary_hash\""));
        assert!(markdown.contains("# Hyperion Certification Freeze Manifest"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
