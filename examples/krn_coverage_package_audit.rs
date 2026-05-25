use hyperion_emv::coverage::{
    audit_coverage_package, coverage_package_audit_json, coverage_package_audit_markdown,
    coverage_package_is_certification_candidate, coverage_package_is_reviewable,
    DEFAULT_COVERAGE_ROOT,
};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use std::env;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => emit_json(Path::new(DEFAULT_COVERAGE_ROOT), Requirement::None),
        [flag, root] if flag == "--root" => emit_json(Path::new(root), Requirement::None),
        [flag, root, format] if flag == "--root" && format == "--markdown" => {
            emit_markdown(Path::new(root), Requirement::None)
        }
        [flag, root, requirement] if flag == "--root" && requirement == "--require-package" => {
            emit_json(Path::new(root), Requirement::Reviewable)
        }
        [flag, root, requirement]
            if flag == "--root" && requirement == "--require-certification-candidate" =>
        {
            emit_json(Path::new(root), Requirement::CertificationCandidate)
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_coverage_package_audit -- [--root <dir> [--markdown|--require-package|--require-certification-candidate]]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to audit coverage package: {err}");
        process::exit(1);
    }
}

#[derive(Clone, Copy)]
enum Requirement {
    None,
    Reviewable,
    CertificationCandidate,
}

fn emit_json(root: &Path, requirement: Requirement) -> io::Result<()> {
    let audit = audit_coverage_package(root)?;
    print!("{}", coverage_package_audit_json(KRN_ABI_VERSION, &audit));
    enforce_requirement(&audit, requirement);
    Ok(())
}

fn emit_markdown(root: &Path, requirement: Requirement) -> io::Result<()> {
    let audit = audit_coverage_package(root)?;
    print!(
        "{}",
        coverage_package_audit_markdown(KRN_ABI_VERSION, &audit)
    );
    enforce_requirement(&audit, requirement);
    Ok(())
}

fn enforce_requirement(
    audit: &hyperion_emv::coverage::CoveragePackageAudit,
    requirement: Requirement,
) {
    let accepted = match requirement {
        Requirement::None => true,
        Requirement::Reviewable => coverage_package_is_reviewable(audit),
        Requirement::CertificationCandidate => coverage_package_is_certification_candidate(audit),
    };
    if !accepted {
        eprintln!(
            "coverage package status `{}` does not satisfy requested requirement",
            audit.status
        );
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cli_audit_accepts_reviewable_measurement_package() {
        let root = env::temp_dir().join(format!(
            "hyperion-coverage-cli-reviewable-{}",
            process::id()
        ));
        write_coverage_package(&root, false).unwrap();

        let audit = audit_coverage_package(&root).unwrap();
        assert!(coverage_package_is_reviewable(&audit));
        assert!(!coverage_package_is_certification_candidate(&audit));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cli_audit_identifies_certification_candidate_package() {
        let root =
            env::temp_dir().join(format!("hyperion-coverage-cli-candidate-{}", process::id()));
        write_coverage_package(&root, true).unwrap();

        let audit = audit_coverage_package(&root).unwrap();
        assert!(coverage_package_is_certification_candidate(&audit));
        assert!(coverage_package_audit_json(KRN_ABI_VERSION, &audit)
            .contains("\"status\":\"certification_candidate_unreviewed\""));

        fs::remove_dir_all(&root).unwrap();
    }

    fn write_coverage_package(root: &Path, enforced: bool) -> io::Result<()> {
        if root.exists() {
            fs::remove_dir_all(root)?;
        }
        fs::create_dir_all(root.join("html"))?;
        fs::write(root.join("README.txt"), b"coverage package")?;
        fs::write(root.join("html/index.html"), b"<html>coverage</html>")?;
        fs::write(
            root.join("lcov.info"),
            b"TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n",
        )?;
        fs::write(
            root.join("metadata.json"),
            format!(
                "{{\"type\":\"hyperion-coverage-report-metadata\",\"source_commit\":\"abcdef0\",\"cargo_version\":\"cargo 1.70.0\",\"rustc_version\":\"rustc 1.70.0\",\"target_triple\":\"x86_64-unknown-linux-gnu\",\"coverage_tool_version\":\"cargo-llvm-cov 0.6.0\",\"workspace\":true,\"all_targets\":true,\"all_features\":true,\"line_coverage_threshold\":100,\"coverage_enforced\":{enforced},\"html_report\":\"target/coverage/html\",\"lcov_report\":\"target/coverage/lcov.info\",\"readme\":\"target/coverage/README.txt\",\"open_issue\":\"CERT-OPEN-009\",\"does_not_close\":\"CERT-OPEN-009\"}}"
            ),
        )?;
        Ok(())
    }
}
