use hyperion_emv::cert_bundle::{
    certification_bundle_workbench_html, create_bundle_from_inputs, BundleClass,
    BundleProvisioningInput, CallbackTimeoutProfile,
};
use hyperion_emv::restrictions::EmvDate;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process;

const DEFAULT_PROFILE: &str = include_str!("../docs/scheme_profiles.cert.json");
const DEFAULT_VECTORS: &str = include_str!("../docs/oda_test_vectors.json");
const DEFAULT_SIGNING_PRIVATE_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn default_vector_bundle() -> String {
    format!(
        "{{\"schema_version\":\"hyperion-vector-bundle-1.0\",\"vector_class\":\"PRELAB_FIXTURE_PENDING_CERTIFICATION_VECTORS\",\"source_artifacts\":[{{\"path\":\"docs/oda_test_vectors.json\",\"sha256\":\"{}\"}}],\"cases\":[]}}",
        hyperion_emv::provenance::to_hex(&hyperion_emv::provenance::sha256(DEFAULT_VECTORS.as_bytes()))
    )
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let out_dir = match args.as_slice() {
        [] => "target/hyperion-cert-bundle-tui".to_string(),
        [flag, dir] if flag == "--out" => dir.to_string(),
        _ => {
            eprintln!("usage: cargo run --example krn_certification_bundle_tui -- [--out <dir>]");
            process::exit(2);
        }
    };
    if let Err(err) = run_tui(Path::new(&out_dir)) {
        eprintln!("bundle TUI failed: {err}");
        process::exit(1);
    }
}

fn run_tui(out_dir: &Path) -> io::Result<()> {
    println!("Hyperion certification bundle provisioner");
    println!("Press Enter to accept each default. The generated files stay local.");
    let bundle_id = prompt("Bundle ID", "hyperion-c8-contact-certification-fixture")?;
    let product_name = prompt("Product name", "Hyperion EMV Kernel")?;
    let product_version = prompt("Product version", env!("CARGO_PKG_VERSION"))?;
    let certification_target = prompt("Certification target", "contact-and-c8-contactless-prelab")?;
    let interfaces = prompt("Interfaces", "contact,contactless")?;
    let authorities = prompt(
        "Authorities",
        "Hyperion-X Certification,recognized-lab-pending,scheme-authority-pending",
    )?;
    let device_model = prompt(
        "Device model",
        "hyperion-certification-device-profile-pending",
    )?;
    let firmware_version = prompt("Firmware version", "submitted-firmware-version-pending")?;
    let signer_id = prompt("Signer ID", "hyperion-local-bundle-authority")?;
    let signing_private_key_hex =
        prompt("Signing private key hex", DEFAULT_SIGNING_PRIVATE_KEY_HEX)?;
    let vector_bundle = default_vector_bundle();

    let (bundle, anchors) = create_bundle_from_inputs(BundleProvisioningInput {
        bundle_id: &bundle_id,
        bundle_version: 2,
        rollback_counter: 2,
        bundle_class: BundleClass::Certification,
        created: EmvDate {
            year: 26,
            month: 5,
            day: 25,
        },
        product_name: &product_name,
        product_version: &product_version,
        certification_target: &certification_target,
        interfaces: &interfaces,
        authorities: &authorities,
        emv_contact_version: "EMV 4.3",
        emv_contactless_kernel: "EMV Contactless Kernel C-8",
        bulletins_included: "public-standards-watch-2026-05-25",
        bulletins_excluded: "none",
        terminal_type: "attended-online-pos",
        device_model: &device_model,
        firmware_version: &firmware_version,
        l1_approval_reference: "external-l1-evidence-required",
        pci_pts_reference: "external-pci-pts-evidence-required",
        kernel_profile_id: "c8-contactless-data-profile",
        kernel_interface: "contactless",
        kernel_algorithm: "hyperion-rust-c8-module",
        c8_package: "c8-lab-package-pending",
        scheme_scope: "Visa,Mastercard",
        vector_class: "PRELAB_FIXTURE_PENDING_CERTIFICATION_VECTORS",
        signer_id: &signer_id,
        signing_private_key_hex: Some(&signing_private_key_hex),
        trust_not_after: Some(EmvDate {
            year: 28,
            month: 1,
            day: 1,
        }),
        callback_timeouts: Some(CallbackTimeoutProfile::defaults()),
        scheme_profile_set_json: DEFAULT_PROFILE,
        vector_bundle_json: &vector_bundle,
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("certification_bundle.json"), &bundle)?;
    fs::write(out_dir.join("trust_anchors.json"), &anchors)?;
    fs::write(
        out_dir.join("index.html"),
        certification_bundle_workbench_html(&bundle, &anchors),
    )?;
    println!(
        "Wrote {}",
        out_dir.join("certification_bundle.json").display()
    );
    println!("Wrote {}", out_dir.join("trust_anchors.json").display());
    println!("Wrote {}", out_dir.join("index.html").display());
    Ok(())
}

fn prompt(label: &str, default: &str) -> io::Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let value = input.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}
