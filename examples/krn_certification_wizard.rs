use hyperion_emv::wizard::{
    write_certification_wizard_workspace, CertificationWizardInput,
    DEFAULT_CERTIFICATION_WIZARD_ROOT,
};
use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut out_dir = DEFAULT_CERTIFICATION_WIZARD_ROOT.to_string();
    let mut interactive = true;
    let mut input = CertificationWizardInput::default();
    if let Ok(signing_key) = env::var("HYPERION_CERT_WIZARD_SIGNING_KEY_HEX") {
        input.signing_private_key_hex = signing_key;
    }
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--out" if idx + 1 < args.len() => {
                out_dir = args[idx + 1].clone();
                idx += 2;
            }
            "--non-interactive" => {
                interactive = false;
                idx += 1;
            }
            "--product-name" if idx + 1 < args.len() => {
                input.product_name = args[idx + 1].clone();
                idx += 2;
            }
            "--product-version" if idx + 1 < args.len() => {
                input.product_version = args[idx + 1].clone();
                idx += 2;
            }
            "--target" if idx + 1 < args.len() => {
                input.certification_target = args[idx + 1].clone();
                idx += 2;
            }
            "--interfaces" if idx + 1 < args.len() => {
                input.interfaces = args[idx + 1].clone();
                idx += 2;
            }
            "--schemes" if idx + 1 < args.len() => {
                input.schemes = args[idx + 1].clone();
                idx += 2;
            }
            "--device-model" if idx + 1 < args.len() => {
                input.device_model = args[idx + 1].clone();
                idx += 2;
            }
            "--firmware-version" if idx + 1 < args.len() => {
                input.firmware_version = args[idx + 1].clone();
                idx += 2;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            _ => {
                print_usage();
                process::exit(2);
            }
        }
    }

    let result = if interactive {
        run_interactive(&mut input)
            .and_then(|()| write_certification_wizard_workspace(Path::new(&out_dir), &input))
    } else {
        write_certification_wizard_workspace(Path::new(&out_dir), &input)
    };

    match result {
        Ok(output) => {
            println!("wizard_workspace={}", output.root.display());
            println!("plan={}", output.plan_markdown_path.display());
            println!("bundle={}", output.bundle_path.display());
            println!("workbench={}", output.workbench_path.display());
            println!("commands={}", output.commands_path.display());
            println!("next_steps={}", output.next_steps_path.display());
        }
        Err(err) => {
            eprintln!("certification wizard failed: {err}");
            process::exit(1);
        }
    }
}

fn run_interactive(input: &mut CertificationWizardInput) -> io::Result<()> {
    println!("Hyperion certification wizard");
    println!(
        "Press Enter to accept each default. External approvals still need to be attached later."
    );
    println!(
        "Signing uses the local scaffold key or HYPERION_CERT_WIZARD_SIGNING_KEY_HEX from a secure wrapper; key material is not written to the workspace."
    );
    input.product_name = prompt("Product name", &input.product_name)?;
    input.product_version = prompt("Product version", &input.product_version)?;
    input.certification_target = prompt("Certification target", &input.certification_target)?;
    input.interfaces = prompt("Interfaces", &input.interfaces)?;
    input.schemes = prompt("Schemes", &input.schemes)?;
    input.authorities = prompt("Authorities", &input.authorities)?;
    input.terminal_type = prompt("Terminal type", &input.terminal_type)?;
    input.device_model = prompt("Device model", &input.device_model)?;
    input.firmware_version = prompt("Firmware version", &input.firmware_version)?;
    input.l1_approval_reference = prompt("L1 approval reference", &input.l1_approval_reference)?;
    input.pci_pts_reference = prompt("PCI/PED reference", &input.pci_pts_reference)?;
    input.c8_package = prompt("C-8 package reference", &input.c8_package)?;
    input.signer_id = prompt("Local signer ID", &input.signer_id)?;
    Ok(())
}

fn prompt(label: &str, default: &str) -> io::Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn usage() -> &'static str {
    "usage: cargo run --example krn_certification_wizard -- [--non-interactive] [--out <dir>] [--product-name <name>] [--product-version <version>] [--target <scope>] [--interfaces <csv>] [--schemes <csv>] [--device-model <model>] [--firmware-version <version>]\noptional env: HYPERION_CERT_WIZARD_SIGNING_KEY_HEX for wrapper-provided local scaffold signing"
}

fn print_usage() {
    eprintln!("{}", usage());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_mentions_non_interactive_mode() {
        assert!(usage().contains("--non-interactive"));
        assert!(usage().contains("HYPERION_CERT_WIZARD_SIGNING_KEY_HEX"));
    }
}
