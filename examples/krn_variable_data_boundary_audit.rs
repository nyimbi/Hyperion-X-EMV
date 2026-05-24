use hyperion_emv::data_boundary::{audit_variable_data_boundary, BoundaryAuditInput};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let roots = if args.is_empty() {
        vec!["src".to_string()]
    } else {
        args
    };

    match collect_inputs(&roots) {
        Ok(inputs) => {
            let audit_inputs = inputs
                .iter()
                .map(|input| BoundaryAuditInput {
                    path: &input.path,
                    contents: &input.contents,
                })
                .collect::<Vec<_>>();
            match audit_variable_data_boundary(&audit_inputs) {
                Ok(audit) => {
                    println!("{}", audit.canonical_json());
                    if !audit.passed() {
                        process::exit(1);
                    }
                }
                Err(err) => {
                    eprintln!("variable data boundary audit failed: {}", err.name());
                    process::exit(1);
                }
            }
        }
        Err(err) => {
            eprintln!("failed to collect source files: {err}");
            process::exit(2);
        }
    }
}

struct OwnedAuditInput {
    path: String,
    contents: String,
}

fn collect_inputs(roots: &[String]) -> std::io::Result<Vec<OwnedAuditInput>> {
    let mut files = Vec::new();
    for root in roots {
        collect_source_files(Path::new(root), &mut files)?;
    }
    files.sort();
    files.dedup();

    let mut inputs = Vec::with_capacity(files.len());
    for file in files {
        let path = artifact_name(&file);
        let contents = fs::read_to_string(file)?;
        inputs.push(OwnedAuditInput { path, contents });
    }
    Ok(inputs)
}

fn collect_source_files(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                collect_source_files(&path, files)?;
            } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    } else if path.extension().is_some_and(|ext| ext == "rs") {
        files.push(path.to_path_buf());
    }
    Ok(())
}

fn artifact_name(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_audit_over_src_passes_current_boundary() {
        let inputs = collect_inputs(&["src".to_string()]).unwrap();
        let audit_inputs = inputs
            .iter()
            .map(|input| BoundaryAuditInput {
                path: &input.path,
                contents: &input.contents,
            })
            .collect::<Vec<_>>();
        let audit = audit_variable_data_boundary(&audit_inputs).unwrap();

        assert!(audit.checked_files > 0);
        assert!(audit.passed(), "unexpected findings: {:?}", audit.findings);
        assert!(audit
            .canonical_json()
            .contains("\"type\":\"variable-data-boundary-audit\""));
    }
}
