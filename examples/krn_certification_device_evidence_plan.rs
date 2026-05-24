use hyperion_emv::device::{
    certification_device_evidence_plan_json, certification_device_evidence_plan_markdown,
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
                certification_device_evidence_plan_json(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!(
                "{}",
                certification_device_evidence_plan_json(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!(
                "{}",
                certification_device_evidence_plan_markdown(KRN_ABI_VERSION)
            );
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_device_evidence_plan(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!(
                    "{}",
                    dir.join("certification_device_evidence_plan.json")
                        .display()
                )
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_device_evidence_plan -- [--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification device evidence plan: {err}");
        process::exit(1);
    }
}

fn write_device_evidence_plan(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("certification_device_evidence_plan.json"),
        certification_device_evidence_plan_json(abi_version),
    )?;
    fs::write(
        dir.join("certification_device_evidence_plan.md"),
        certification_device_evidence_plan_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_and_markdown_device_evidence_plan() {
        let dir = env::temp_dir().join(format!(
            "hyperion-device-evidence-plan-test-{}",
            process::id()
        ));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_device_evidence_plan(&dir, 2).unwrap();

        let json = fs::read_to_string(dir.join("certification_device_evidence_plan.json")).unwrap();
        let markdown =
            fs::read_to_string(dir.join("certification_device_evidence_plan.md")).unwrap();
        assert!(json.contains("\"type\":\"certification-device-evidence-plan\""));
        assert!(json.contains("\"DEVICE-PED-PTS\""));
        assert!(json.contains("\"DEVICE-BUILD-BINDING\""));
        assert!(markdown.contains("# Hyperion Device, L1, and PED Evidence Plan"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
