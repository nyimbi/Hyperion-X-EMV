use hyperion_emv::artifact_import::{
    certification_artifact_import_plan_json, certification_artifact_import_plan_markdown,
    certification_artifact_import_report_json, certification_artifact_import_report_markdown,
    import_certification_artifacts,
};
use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::integration_import::{
    certification_integration_import_report_json, certification_integration_import_report_markdown,
    certification_release_freeze_json, certification_release_freeze_markdown,
    compile_certification_integration_artifacts,
};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => emit_plan_json(),
        [flag] if flag == "--plan-json" => emit_plan_json(),
        [flag] if flag == "--plan-markdown" => emit_plan_markdown(),
        [flag, root] if flag == "--root" => emit_report_json(Path::new(root)),
        [flag, root, format] if flag == "--root" && format == "--markdown" => {
            emit_report_markdown(Path::new(root))
        }
        [flag, root] if flag == "--integration-root" => {
            emit_integration_report_json(Path::new(root))
        }
        [flag, root, format] if flag == "--integration-root" && format == "--markdown" => {
            emit_integration_report_markdown(Path::new(root))
        }
        [flag, root] if flag == "--release-freeze-root" => {
            emit_release_freeze_json(Path::new(root))
        }
        [flag, root, format] if flag == "--release-freeze-root" && format == "--markdown" => {
            emit_release_freeze_markdown(Path::new(root))
        }
        [flag, dir] if flag == "--out" => write_plan(Path::new(dir)).map(|dir| {
            println!(
                "{}",
                dir.join("certification_artifact_import_plan.json")
                    .display()
            )
        }),
        [out_flag, out_dir, root_flag, root] if out_flag == "--out" && root_flag == "--root" => {
            write_report(Path::new(out_dir), Path::new(root)).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_artifact_import_report.json")
                        .display()
                )
            })
        }
        [out_flag, out_dir, root_flag, root]
            if out_flag == "--out" && root_flag == "--integration-root" =>
        {
            write_integration_report(Path::new(out_dir), Path::new(root)).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_integration_import_report.json")
                        .display()
                )
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_artifact_import -- [--plan-json|--plan-markdown|--root <dir> [--markdown]|--integration-root <dir> [--markdown]|--release-freeze-root <dir> [--markdown]|--out <dir>|--out <dir> --root <dir>|--out <dir> --integration-root <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to import certification artifacts: {err}");
        process::exit(1);
    }
}

fn emit_plan_json() -> io::Result<()> {
    print!(
        "{}",
        certification_artifact_import_plan_json(KERN_ABI_VERSION)
    );
    Ok(())
}

fn emit_plan_markdown() -> io::Result<()> {
    print!(
        "{}",
        certification_artifact_import_plan_markdown(KERN_ABI_VERSION)
    );
    Ok(())
}

fn emit_report_json(root: &Path) -> io::Result<()> {
    let report = import_certification_artifacts(root)?;
    print!(
        "{}",
        certification_artifact_import_report_json(KERN_ABI_VERSION, &report)
    );
    Ok(())
}

fn emit_report_markdown(root: &Path) -> io::Result<()> {
    let report = import_certification_artifacts(root)?;
    print!(
        "{}",
        certification_artifact_import_report_markdown(KERN_ABI_VERSION, &report)
    );
    Ok(())
}

fn emit_integration_report_json(root: &Path) -> io::Result<()> {
    let report = compile_certification_integration_artifacts(root)?;
    print!(
        "{}",
        certification_integration_import_report_json(KERN_ABI_VERSION, &report)
    );
    Ok(())
}

fn emit_integration_report_markdown(root: &Path) -> io::Result<()> {
    let report = compile_certification_integration_artifacts(root)?;
    print!(
        "{}",
        certification_integration_import_report_markdown(KERN_ABI_VERSION, &report)
    );
    Ok(())
}

fn emit_release_freeze_json(root: &Path) -> io::Result<()> {
    let report = compile_certification_integration_artifacts(root)?;
    print!(
        "{}",
        certification_release_freeze_json(KERN_ABI_VERSION, &report)
    );
    Ok(())
}

fn emit_release_freeze_markdown(root: &Path) -> io::Result<()> {
    let report = compile_certification_integration_artifacts(root)?;
    print!(
        "{}",
        certification_release_freeze_markdown(KERN_ABI_VERSION, &report)
    );
    Ok(())
}

fn write_plan(dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("certification_artifact_import_plan.json"),
        certification_artifact_import_plan_json(KERN_ABI_VERSION),
    )?;
    fs::write(
        dir.join("certification_artifact_import_plan.md"),
        certification_artifact_import_plan_markdown(KERN_ABI_VERSION),
    )?;
    Ok(dir.to_path_buf())
}

fn write_report(dir: &Path, root: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let report = import_certification_artifacts(root)?;
    fs::write(
        dir.join("certification_artifact_import_report.json"),
        certification_artifact_import_report_json(KERN_ABI_VERSION, &report),
    )?;
    fs::write(
        dir.join("certification_artifact_import_report.md"),
        certification_artifact_import_report_markdown(KERN_ABI_VERSION, &report),
    )?;
    Ok(dir.to_path_buf())
}

fn write_integration_report(dir: &Path, root: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let report = compile_certification_integration_artifacts(root)?;
    fs::write(
        dir.join("certification_integration_import_report.json"),
        certification_integration_import_report_json(KERN_ABI_VERSION, &report),
    )?;
    fs::write(
        dir.join("certification_integration_import_report.md"),
        certification_integration_import_report_markdown(KERN_ABI_VERSION, &report),
    )?;
    fs::write(
        dir.join("certification_release_freeze.json"),
        certification_release_freeze_json(KERN_ABI_VERSION, &report),
    )?;
    fs::write(
        dir.join("certification_release_freeze.md"),
        certification_release_freeze_markdown(KERN_ABI_VERSION, &report),
    )?;
    Ok(dir.to_path_buf())
}

const KERN_ABI_VERSION: u32 = KRN_ABI_VERSION;

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_emv::artifact_import::DEFAULT_CERTIFICATION_ARTIFACT_IMPORT_ROOT;

    #[test]
    fn writes_plan_and_import_report_artifacts() {
        let base = env::temp_dir().join(format!("hyperion-artifact-import-cli-{}", process::id()));
        let input = base.join("input");
        let out = base.join("out");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(input.join("scheme")).unwrap();
        fs::write(input.join("scheme/profile.json"), b"profile").unwrap();

        write_plan(&out).unwrap();
        write_report(&out, &input).unwrap();
        write_integration_report(&out, &input).unwrap();

        let plan = fs::read_to_string(out.join("certification_artifact_import_plan.json")).unwrap();
        let report =
            fs::read_to_string(out.join("certification_artifact_import_report.json")).unwrap();
        let markdown =
            fs::read_to_string(out.join("certification_artifact_import_report.md")).unwrap();
        let integration =
            fs::read_to_string(out.join("certification_integration_import_report.json")).unwrap();
        let release_freeze =
            fs::read_to_string(out.join("certification_release_freeze.json")).unwrap();
        assert!(plan.contains("certification-artifact-import-plan"));
        assert!(report.contains("certification-artifact-import-report"));
        assert!(report.contains("scheme/profile.json"));
        assert!(markdown.contains("SCHEME-PROFILE Imported Files"));
        assert!(integration.contains("certification-integration-import-report"));
        assert!(release_freeze.contains("certification-release-freeze"));
        assert_eq!(
            DEFAULT_CERTIFICATION_ARTIFACT_IMPORT_ROOT,
            "target/hyperion-cert-artifact-import"
        );

        fs::remove_dir_all(&base).unwrap();
    }
}
