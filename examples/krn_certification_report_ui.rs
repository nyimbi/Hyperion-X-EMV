use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::reporting::{
    certification_report_markdown, certification_report_pack_json, certification_report_ui_html,
};
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => write_report_pack(Path::new("target/hyperion-cert-ui"), KRN_ABI_VERSION).map(|dir| {
            println!("{}", dir.join("index.html").display());
        }),
        [flag] if flag == "--html" => {
            print!("{}", certification_report_ui_html(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--json" => {
            print!("{}", certification_report_pack_json(KRN_ABI_VERSION));
            Ok(())
        }
        [flag] if flag == "--markdown" => {
            print!("{}", certification_report_markdown(KRN_ABI_VERSION));
            Ok(())
        }
        [flag, dir] if flag == "--out" => {
            write_report_pack(Path::new(dir), KRN_ABI_VERSION).map(|dir| {
                println!("{}", dir.join("index.html").display());
            })
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_certification_report_ui -- [--html|--json|--markdown|--out <dir>]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to generate certification report UI: {err}");
        process::exit(1);
    }
}

fn write_report_pack(dir: &Path, abi_version: u32) -> io::Result<&Path> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("index.html"),
        certification_report_ui_html(abi_version),
    )?;
    fs::write(
        dir.join("report_pack.json"),
        certification_report_pack_json(abi_version),
    )?;
    fs::write(
        dir.join("report_pack.md"),
        certification_report_markdown(abi_version),
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_static_ui_json_and_markdown_pack() {
        let dir = env::temp_dir().join(format!("hyperion-cert-ui-test-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        write_report_pack(&dir, 2).unwrap();

        let html = fs::read_to_string(dir.join("index.html")).unwrap();
        let json = fs::read_to_string(dir.join("report_pack.json")).unwrap();
        let markdown = fs::read_to_string(dir.join("report_pack.md")).unwrap();
        assert!(html.contains("Hyperion Certification Workbench"));
        assert!(json.contains("\"type\":\"certification-report-pack\""));
        assert!(markdown.contains("# Hyperion Certification Report Pack"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
