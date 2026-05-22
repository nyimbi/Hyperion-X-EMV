use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::provenance::{build_provenance_manifest, Artifact};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    let mut inputs = Vec::new();
    for path in env::args().skip(1) {
        match collect_input(Path::new(&path), &mut inputs) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("failed to collect artifact {path}: {err}");
                process::exit(2);
            }
        }
    }
    inputs.sort_by(|left, right| left.0.cmp(&right.0));
    if inputs.is_empty() {
        eprintln!("usage: cargo run --example krn_build_manifest -- <artifact-or-directory> [...]");
        process::exit(2);
    }

    let artifacts = inputs
        .iter()
        .map(|(name, bytes)| Artifact {
            name,
            bytes: bytes.as_slice(),
        })
        .collect::<Vec<_>>();
    match build_provenance_manifest(KRN_ABI_VERSION, &artifacts) {
        Ok(manifest) => println!("{}", manifest.canonical_json()),
        Err(err) => {
            eprintln!("failed to build provenance manifest: {}", err.name());
            process::exit(1);
        }
    }
}

fn collect_input(path: &Path, inputs: &mut Vec<(String, Vec<u8>)>) -> std::io::Result<()> {
    if path.is_dir() {
        let mut files = Vec::new();
        collect_files(path, &mut files)?;
        files.sort();
        for file in files {
            inputs.push((artifact_name(&file), fs::read(file)?));
        }
        Ok(())
    } else {
        inputs.push((artifact_name(path), fs::read(path)?));
        Ok(())
    }
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn artifact_name(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
