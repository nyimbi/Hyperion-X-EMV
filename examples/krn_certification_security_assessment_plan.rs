use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::security::{
    certification_security_assessment_plan_json, certification_security_assessment_plan_markdown,
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
            print!(
                "{}",
                certification_security_assessment_plan_json(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!(
                "{}",
                certification_security_assessment_plan_json(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!(
                "{}",
                certification_security_assessment_plan_markdown(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_security_assessment_plan(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_security_assessment_plan.json")
                        .display()
                )
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_security_assessment_plan -- [--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification security assessment plan: {err}");
        process::exit(1);
    }
}

fn write_security_assessment_plan(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("certification_security_assessment_plan.json"),
        certification_security_assessment_plan_json(abi_version),
    )?;
    fs::write(
        dir.join("certification_security_assessment_plan.md"),
        certification_security_assessment_plan_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_and_markdown_security_assessment_plan() {
        let dir = env::temp_dir().join(format!(
            "hyperion-security-assessment-plan-test-{}",
            process::id()
        ));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_security_assessment_plan(&dir, 2).unwrap();

        let json =
            fs::read_to_string(dir.join("certification_security_assessment_plan.json")).unwrap();
        let markdown =
            fs::read_to_string(dir.join("certification_security_assessment_plan.md")).unwrap();
        assert!(json.contains("\"type\":\"certification-security-assessment-plan\""));
        assert!(json.contains("\"SEC-ASSESS-APDU-INJECTION\""));
        assert!(markdown.contains("# Hyperion Certification Security Assessment Plan"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
