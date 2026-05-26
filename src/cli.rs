//! First-class Hyperion command-line surface.
//!
//! The binary wrapper delegates here so the command behavior is unit-testable
//! while still shipping a real `hyperion` executable for users.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::artifact_import::{
    certification_artifact_import_report_json, import_certification_artifacts,
};
use crate::cert_bundle::{
    certification_bundle_compile_report, certification_bundle_compile_report_json,
    parse_trust_anchors, BundleLoadPolicy,
};
use crate::config::BuildMode;
use crate::ffi::KRN_ABI_VERSION;
use crate::productization::{
    hyperion_cli_catalog_json, hyperion_cli_catalog_markdown, write_c_header,
    write_report_workspace, write_schema_catalog, write_submission_pack, SubmissionPackInput,
};
use crate::quality::prelab_quality_gates_json;
use crate::restrictions::EmvDate;
use crate::wizard::{write_certification_wizard_workspace, CertificationWizardInput};

pub fn run_hyperion_cli<W: Write, E: Write>(
    args: &[String],
    stdout: &mut W,
    stderr: &mut E,
) -> i32 {
    match run_hyperion_cli_inner(args, stdout) {
        Ok(()) => 0,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            let _ = writeln!(stderr, "{err}");
            let _ = writeln!(stderr, "{}", hyperion_usage());
            2
        }
        Err(err) => {
            let _ = writeln!(stderr, "hyperion command failed: {err}");
            1
        }
    }
}

fn run_hyperion_cli_inner<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        writeln!(stdout, "{}", hyperion_usage())?;
        return Ok(());
    }
    match args[0].as_str() {
        "commands" => write_commands(args, stdout),
        "bundle" => run_bundle(args, stdout),
        "artifacts" => run_artifacts(args, stdout),
        "release" => run_release(args, stdout),
        "report" => run_report(args, stdout),
        "certify" => run_certify(args, stdout),
        "schemas" => run_schemas(args, stdout),
        "c-header" => run_c_header(args, stdout),
        _ => Err(usage_error("unknown command")),
    }
}

pub fn hyperion_usage() -> &'static str {
    "usage: hyperion <commands|bundle|artifacts|release|report|certify|schemas|c-header> [...]; run `hyperion commands --markdown` for the command catalogue"
}

fn write_commands<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd] if cmd == "commands" => write!(stdout, "{}", hyperion_cli_catalog_json()),
        [cmd, flag] if cmd == "commands" && flag == "--markdown" => {
            write!(stdout, "{}", hyperion_cli_catalog_markdown())
        }
        _ => Err(usage_error("usage: hyperion commands [--markdown]")),
    }
}

fn run_bundle<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub, out_flag, out] if cmd == "bundle" && sub == "init" && out_flag == "--out" => {
            let input = CertificationWizardInput::default();
            let output = write_certification_wizard_workspace(Path::new(out), &input)?;
            writeln!(stdout, "bundle={}", output.bundle_path.display())
        }
        [cmd, sub, out_flag, out] if cmd == "bundle" && sub == "sign" && out_flag == "--out" => {
            let input = CertificationWizardInput::default();
            let output = write_certification_wizard_workspace(Path::new(out), &input)?;
            writeln!(stdout, "bundle={}", output.bundle_path.display())
        }
        [cmd, sub, bundle_flag, bundle, trust_flag, trust]
            if cmd == "bundle"
                && sub == "lint"
                && bundle_flag == "--bundle"
                && trust_flag == "--trust-anchors" =>
        {
            lint_bundle(Path::new(bundle), Path::new(trust), stdout)
        }
        _ => Err(usage_error("usage: hyperion bundle init --out <dir> | bundle sign --out <dir> | bundle lint --bundle <file> --trust-anchors <file>")),
    }
}

fn run_artifacts<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub, root_flag, root]
            if cmd == "artifacts" && sub == "import" && root_flag == "--root" =>
        {
            let report = import_certification_artifacts(Path::new(root))?;
            write!(
                stdout,
                "{}",
                certification_artifact_import_report_json(KRN_ABI_VERSION, &report)
            )
        }
        [cmd, sub, root_flag, root, out_flag, out]
            if cmd == "artifacts"
                && sub == "import"
                && root_flag == "--root"
                && out_flag == "--out" =>
        {
            fs::create_dir_all(out)?;
            let report = import_certification_artifacts(Path::new(root))?;
            write_artifact_import_report(out, &report)?;
            writeln!(stdout, "out={out}")
        }
        _ => Err(usage_error(
            "usage: hyperion artifacts import --root <dir> [--out <dir>]",
        )),
    }
}

fn write_artifact_import_report(
    out: &str,
    report: &crate::artifact_import::ArtifactImportReport,
) -> io::Result<()> {
    let json = certification_artifact_import_report_json(KRN_ABI_VERSION, report);
    let path = Path::new(out).join("certification_artifact_import_report.json");
    fs::write(path, json)
}

fn run_release<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub, artifacts_flag, artifacts, out_flag, out]
            if cmd == "release"
                && sub == "freeze"
                && artifacts_flag == "--artifacts"
                && out_flag == "--out" =>
        {
            let output = write_submission_pack(&SubmissionPackInput {
                artifacts_root: artifacts.into(),
                out_dir: out.into(),
                allow_incomplete: false,
            })?;
            writeln!(stdout, "submission_pack={}", output.out_dir.display())
        }
        [cmd, sub, artifacts_flag, artifacts, out_flag, out, allow]
            if cmd == "release"
                && sub == "freeze"
                && artifacts_flag == "--artifacts"
                && out_flag == "--out"
                && allow == "--allow-incomplete" =>
        {
            let output = write_submission_pack(&SubmissionPackInput {
                artifacts_root: artifacts.into(),
                out_dir: out.into(),
                allow_incomplete: true,
            })?;
            writeln!(stdout, "submission_pack={}", output.out_dir.display())
        }
        _ => Err(usage_error(
            "usage: hyperion release freeze --artifacts <dir> --out <dir> [--allow-incomplete]",
        )),
    }
}

fn run_report<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub, out_flag, out]
            if cmd == "report" && sub == "workspace" && out_flag == "--out" =>
        {
            write_report_workspace(Path::new(out))?;
            writeln!(stdout, "report_workspace={out}")
        }
        _ => Err(usage_error("usage: hyperion report workspace --out <dir>")),
    }
}

fn run_certify<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub] if cmd == "certify" && sub == "check" => {
            write!(stdout, "{}", prelab_quality_gates_json(KRN_ABI_VERSION))
        }
        _ => Err(usage_error("usage: hyperion certify check")),
    }
}

fn run_schemas<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub, out_flag, out] if cmd == "schemas" && sub == "write" && out_flag == "--out" => {
            write_schema_catalog(Path::new(out))?;
            writeln!(stdout, "schemas={out}")
        }
        _ => Err(usage_error("usage: hyperion schemas write --out <dir>")),
    }
}

fn run_c_header<W: Write>(args: &[String], stdout: &mut W) -> io::Result<()> {
    match args {
        [cmd, sub, out_flag, out] if cmd == "c-header" && sub == "write" && out_flag == "--out" => {
            write_c_header(Path::new(out))?;
            writeln!(stdout, "header={out}")
        }
        _ => Err(usage_error("usage: hyperion c-header write --out <file>")),
    }
}

fn lint_bundle<W: Write>(bundle_path: &Path, trust_path: &Path, stdout: &mut W) -> io::Result<()> {
    let bundle = fs::read(bundle_path)?;
    let trust = fs::read(trust_path)?;
    let anchors = parse_trust_anchors(&trust).unwrap_or_default();
    let report = certification_bundle_compile_report(
        &bundle,
        &trust,
        &BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 26,
            },
            trust_anchors: anchors,
        },
    );
    let json = certification_bundle_compile_report_json(&report);
    stdout.write_all(json.as_bytes())?;
    if report.status == "fail" {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certification bundle lint failed",
        ))
    } else {
        Ok(())
    }
}

fn usage_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;

    #[test]
    fn cli_routes_productization_commands() {
        let root = env::temp_dir().join(format!("hyperion-cli-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("artifacts/scheme")).unwrap();
        fs::write(root.join("artifacts/scheme/profile.json"), b"profile").unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();

        assert_eq!(run(&[], &mut out, &mut err), 0);
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("usage: hyperion"));
        out.clear();
        assert_eq!(run(&["commands"], &mut out, &mut err), 0);
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("hyperion-cli-catalog"));
        out.clear();
        assert_eq!(run(&["commands", "--markdown"], &mut out, &mut err), 0);
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("release freeze"));
        out.clear();

        let bundle_root = root.join("bundle");
        assert_eq!(
            run(
                &["bundle", "init", "--out", bundle_root.to_str().unwrap(),],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(bundle_root
            .join("bundle/certification_bundle.json")
            .is_file());
        let bundle = bundle_root.join("bundle/certification_bundle.json");
        let anchors = bundle_root.join("bundle/trust_anchors.json");
        out.clear();
        assert_eq!(
            run(
                &[
                    "bundle",
                    "lint",
                    "--bundle",
                    bundle.to_str().unwrap(),
                    "--trust-anchors",
                    anchors.to_str().unwrap(),
                ],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("compile-report"));
        out.clear();

        let artifact_root = root.join("artifacts");
        assert_eq!(
            run(
                &[
                    "artifacts",
                    "import",
                    "--root",
                    artifact_root.to_str().unwrap()
                ],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("scheme/profile.json"));
        out.clear();
        let artifact_out = root.join("artifact-out");
        assert_eq!(
            run(
                &[
                    "artifacts",
                    "import",
                    "--root",
                    artifact_root.to_str().unwrap(),
                    "--out",
                    artifact_out.to_str().unwrap(),
                ],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(artifact_out
            .join("certification_artifact_import_report.json")
            .is_file());
        out.clear();
        let submission = root.join("submission");
        assert_eq!(
            run(
                &[
                    "release",
                    "freeze",
                    "--artifacts",
                    artifact_root.to_str().unwrap(),
                    "--out",
                    submission.to_str().unwrap(),
                    "--allow-incomplete",
                ],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(submission.join("submission_manifest.json").is_file());
        out.clear();
        let reports = root.join("reports");
        assert_eq!(
            run(
                &["report", "workspace", "--out", reports.to_str().unwrap()],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(reports.join("index.html").is_file());
        out.clear();
        assert_eq!(run(&["certify", "check"], &mut out, &mut err), 0);
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("prelab-quality-gates"));
        out.clear();
        let schemas = root.join("schemas");
        assert_eq!(
            run(
                &["schemas", "write", "--out", schemas.to_str().unwrap()],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(schemas.join("integration-manifest.schema.json").is_file());
        out.clear();
        let header = root.join("include/hyperion_emv.h");
        assert_eq!(
            run(
                &["c-header", "write", "--out", header.to_str().unwrap()],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(header.is_file());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cli_covers_usage_errors_sign_alias_lint_failure_and_strict_success() {
        let root = env::temp_dir().join(format!("hyperion-cli-edges-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut out = Vec::new();
        let mut err = Vec::new();

        assert_eq!(run(&["--help"], &mut out, &mut err), 0);
        out.clear();
        assert_eq!(run(&["commands", "--json"], &mut out, &mut err), 2);
        assert!(String::from_utf8(err.clone())
            .unwrap()
            .contains("hyperion commands"));
        err.clear();

        let sign_root = root.join("signed");
        assert_eq!(
            run(
                &["bundle", "sign", "--out", sign_root.to_str().unwrap()],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(sign_root.join("bundle/certification_bundle.json").is_file());
        out.clear();
        assert_eq!(run(&["bundle", "bad"], &mut out, &mut err), 2);
        err.clear();

        let bad_bundle = root.join("bad_bundle.json");
        let bad_trust = root.join("bad_trust.json");
        fs::create_dir_all(&root).unwrap();
        fs::write(&bad_bundle, b"{}").unwrap();
        fs::write(&bad_trust, b"{}").unwrap();
        assert_eq!(
            run(
                &[
                    "bundle",
                    "lint",
                    "--bundle",
                    bad_bundle.to_str().unwrap(),
                    "--trust-anchors",
                    bad_trust.to_str().unwrap(),
                ],
                &mut out,
                &mut err,
            ),
            1
        );
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("compile-report"));
        out.clear();
        err.clear();

        for args in [
            &["artifacts", "import"] as &[&str],
            &["release", "freeze"],
            &["report", "workspace"],
            &["certify", "lint"],
            &["schemas", "write"],
            &["c-header", "write"],
        ] {
            assert_eq!(run(args, &mut out, &mut err), 2);
            err.clear();
        }

        let complete = root.join("complete-artifacts");
        write_complete_artifact_root(&complete);
        assert_eq!(
            run(
                &[
                    "release",
                    "freeze",
                    "--artifacts",
                    complete.to_str().unwrap(),
                    "--out",
                    root.join("complete-submission").to_str().unwrap(),
                ],
                &mut out,
                &mut err,
            ),
            0
        );
        assert!(String::from_utf8(out).unwrap().contains("submission_pack="));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cli_reports_usage_and_strict_freeze_failures() {
        let root = env::temp_dir().join(format!("hyperion-cli-errors-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("artifacts")).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run(&["unknown"], &mut out, &mut err), 2);
        assert!(String::from_utf8(err.clone())
            .unwrap()
            .contains("unknown command"));
        err.clear();
        assert_eq!(
            run(
                &[
                    "release",
                    "freeze",
                    "--artifacts",
                    root.join("artifacts").to_str().unwrap(),
                    "--out",
                    root.join("submission").to_str().unwrap(),
                ],
                &mut out,
                &mut err,
            ),
            1
        );
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("submission freeze is incomplete"));
        fs::remove_dir_all(&root).unwrap();
    }

    fn write_complete_artifact_root(root: &Path) {
        for dir in ["device", "scheme", "capk", "vectors", "reports", "lab"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        for path in [
            "device/kernel.txt",
            "scheme/config.json",
            "scheme/profile.json",
            "capk/capk.json",
            "vectors/vectors.json",
            "reports/trace.json",
            "reports/coverage.lcov",
            "reports/fuzz.sarif",
            "lab/approval.json",
        ] {
            fs::write(root.join(path), format!("artifact:{path}")).unwrap();
        }
        fs::write(
            root.join("hyperion-integration-manifest.json"),
            r#"{"schema_version":"hyperion-certification-integration-manifest-1.0","manifest_id":"complete","authority":"test-lab","artifacts":[{"path":"device/kernel.txt","adapter_id":"DEVICE","artifact_id":"kernel.binary","artifact_kind":"build artifact","binds_open_issues":["CERT-OPEN-006"],"freeze_artifact_id":"kernel_binary_hash","metadata":["authority"]},{"path":"scheme/config.json","adapter_id":"SCHEME-PROFILE","artifact_id":"config.bundle","artifact_kind":"signed configuration","binds_open_issues":["CERT-OPEN-002"],"freeze_artifact_id":"config_bundle_hash","metadata":["authority"]},{"path":"scheme/profile.json","adapter_id":"SCHEME-PROFILE","artifact_id":"scheme.profile","artifact_kind":"scheme profile","binds_open_issues":["CERT-OPEN-002"],"freeze_artifact_id":"scheme_profile_hash","metadata":["authority"]},{"path":"capk/capk.json","adapter_id":"CAPK","artifact_id":"capk.bundle","artifact_kind":"public key material","binds_open_issues":["CERT-OPEN-003"],"freeze_artifact_id":"capk_bundle_hash","metadata":["authority"]},{"path":"vectors/vectors.json","adapter_id":"VECTOR","artifact_id":"vectors.bundle","artifact_kind":"test vectors","binds_open_issues":["CERT-OPEN-004"],"freeze_artifact_id":"test_vector_hash","metadata":["authority"]},{"path":"reports/trace.json","adapter_id":"REPORT","artifact_id":"trace.pack","artifact_kind":"trace pack","binds_open_issues":["CERT-OPEN-012"],"freeze_artifact_id":"trace_pack_hash","metadata":["authority"]},{"path":"reports/coverage.lcov","adapter_id":"REPORT","artifact_id":"coverage.report","artifact_kind":"quality report","binds_open_issues":["CERT-OPEN-009"],"freeze_artifact_id":"coverage_report_hash","metadata":["authority"]},{"path":"reports/fuzz.sarif","adapter_id":"REPORT","artifact_id":"fuzz.report","artifact_kind":"quality report","binds_open_issues":["CERT-OPEN-010"],"freeze_artifact_id":"static_fuzz_report_hash","metadata":["authority"]},{"path":"lab/approval.json","adapter_id":"LAB-APPROVAL","artifact_id":"approval.package","artifact_kind":"approval artifact","binds_open_issues":["CERT-OPEN-011"],"freeze_artifact_id":"approval_package_hash","metadata":["authority"]}]}"#,
        )
        .unwrap();
    }

    fn run(args: &[&str], out: &mut Vec<u8>, err: &mut Vec<u8>) -> i32 {
        let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        run_hyperion_cli(&args, out, err)
    }
}
