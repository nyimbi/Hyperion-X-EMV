use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::provenance::{build_provenance_manifest, Artifact};
use std::env;
use std::fs;
use std::process;

fn main() {
    let mut inputs = Vec::new();
    for path in env::args().skip(1) {
        match fs::read(&path) {
            Ok(bytes) => inputs.push((path, bytes)),
            Err(err) => {
                eprintln!("failed to read artifact: {err}");
                process::exit(2);
            }
        }
    }
    if inputs.is_empty() {
        eprintln!("usage: cargo run --example krn_build_manifest -- <artifact> [artifact...]");
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
