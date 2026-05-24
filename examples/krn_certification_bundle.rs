use hyperion_emv::cert_bundle::{
    certification_bundle_compile_report, certification_bundle_compile_report_json,
    certification_bundle_compile_report_markdown, certification_bundle_report_markdown,
    certification_bundle_workbench_html, create_bundle_from_inputs, load_certification_bundle,
    parse_trust_anchors, BundleClass, BundleLoadPolicy, BundleProvisioningInput,
    CallbackTimeoutProfile,
};
use hyperion_emv::config::BuildMode;
use hyperion_emv::provenance::to_hex;
use hyperion_emv::restrictions::EmvDate;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

const DEFAULT_PROFILE: &str = include_str!("../docs/scheme_profiles.cert.json");
const DEFAULT_VECTORS: &str = include_str!("../docs/oda_test_vectors.json");
const DEFAULT_SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => write_default_bundle(Path::new("target/hyperion-cert-bundle")).map(|dir| {
            println!("{}", dir.join("index.html").display());
        }),
        [flag, dir] if flag == "--out" => write_default_bundle(Path::new(dir)).map(|dir| {
            println!("{}", dir.join("index.html").display());
        }),
        [flag] if flag == "--json-template" => default_bundle_pair().map(|(bundle, _)| {
            print!("{bundle}");
        }),
        [flag] if flag == "--trust-template" => default_bundle_pair().map(|(_, anchors)| {
            print!("{anchors}");
        }),
        [flag, bundle_flag, bundle, trust_flag, trust]
            if flag == "--validate"
                && bundle_flag == "--bundle"
                && trust_flag == "--trust-anchors" =>
        {
            validate_bundle(
                Path::new(bundle),
                Path::new(trust),
                BuildMode::Certification,
            )
        }
        [flag, bundle_flag, bundle, trust_flag, trust, mode_flag, mode]
            if flag == "--validate"
                && bundle_flag == "--bundle"
                && trust_flag == "--trust-anchors"
                && mode_flag == "--mode" =>
        {
            validate_bundle(Path::new(bundle), Path::new(trust), parse_mode(mode))
        }
        [flag, bundle_flag, bundle, trust_flag, trust]
            if flag == "--lint" && bundle_flag == "--bundle" && trust_flag == "--trust-anchors" =>
        {
            lint_bundle(
                Path::new(bundle),
                Path::new(trust),
                BuildMode::Certification,
            )
        }
        [flag, bundle_flag, bundle, trust_flag, trust, mode_flag, mode]
            if flag == "--lint"
                && bundle_flag == "--bundle"
                && trust_flag == "--trust-anchors"
                && mode_flag == "--mode" =>
        {
            lint_bundle(Path::new(bundle), Path::new(trust), parse_mode(mode))
        }
        _ => {
            eprintln!("usage: cargo run --example krn_certification_bundle -- [--out <dir>|--json-template|--trust-template|--validate --bundle <file> --trust-anchors <file> [--mode test|certification|production]|--lint --bundle <file> --trust-anchors <file> [--mode test|certification|production]]");
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("certification bundle operation failed: {err}");
        process::exit(1);
    }
}

fn parse_mode(input: &str) -> BuildMode {
    match input {
        "test" => BuildMode::Test,
        "certification" => BuildMode::Certification,
        "production" => BuildMode::Production,
        _ => {
            eprintln!("unsupported mode: {input}");
            process::exit(2);
        }
    }
}

fn default_vector_bundle() -> String {
    format!(
        "{{\"schema_version\":\"hyperion-vector-bundle-1.0\",\"vector_class\":\"PRELAB_FIXTURE_PENDING_CERTIFICATION_VECTORS\",\"source_artifacts\":[{{\"path\":\"docs/oda_test_vectors.json\",\"sha256\":\"{}\"}}],\"cases\":[]}}",
        hyperion_emv::provenance::to_hex(&hyperion_emv::provenance::sha256(DEFAULT_VECTORS.as_bytes()))
    )
}

fn default_bundle_pair() -> io::Result<(String, String)> {
    let vector_bundle = default_vector_bundle();
    create_bundle_from_inputs(BundleProvisioningInput {
        bundle_id: "hyperion-c8-contact-certification-fixture",
        bundle_version: 2,
        rollback_counter: 2,
        bundle_class: BundleClass::Certification,
        created: EmvDate {
            year: 26,
            month: 5,
            day: 25,
        },
        product_name: "Hyperion EMV Kernel",
        product_version: env!("CARGO_PKG_VERSION"),
        certification_target: "contact-and-c8-contactless-prelab",
        interfaces: "contact,contactless",
        authorities: "Hyperion-X Certification,recognized-lab-pending,scheme-authority-pending",
        emv_contact_version: "EMV 4.3",
        emv_contactless_kernel: "EMV Contactless Kernel C-8",
        bulletins_included: "public-standards-watch-2026-05-25",
        bulletins_excluded: "none",
        terminal_type: "attended-online-pos",
        device_model: "hyperion-certification-device-profile-pending",
        firmware_version: "submitted-firmware-version-pending",
        l1_approval_reference: "external-l1-evidence-required",
        pci_pts_reference: "external-pci-pts-evidence-required",
        kernel_profile_id: "c8-contactless-data-profile",
        kernel_interface: "contactless",
        kernel_algorithm: "hyperion-rust-c8-module",
        c8_package: "c8-lab-package-pending",
        scheme_scope: "Visa,Mastercard",
        vector_class: "PRELAB_FIXTURE_PENDING_CERTIFICATION_VECTORS",
        signer_id: "hyperion-local-bundle-authority",
        verification_secret_hex: Some(DEFAULT_SECRET_HEX),
        trust_not_after: Some(EmvDate {
            year: 28,
            month: 1,
            day: 1,
        }),
        callback_timeouts: Some(CallbackTimeoutProfile::defaults()),
        scheme_profile_set_json: DEFAULT_PROFILE,
        vector_bundle_json: &vector_bundle,
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn write_default_bundle(dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let (bundle, anchors) = default_bundle_pair()?;
    let loaded = load_pair(&bundle, &anchors, BuildMode::Certification)?;
    let markdown = certification_bundle_report_markdown(&loaded);
    let lint_report = certification_bundle_compile_report(
        bundle.as_bytes(),
        anchors.as_bytes(),
        &BundleLoadPolicy {
            mode: BuildMode::Certification,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: parse_trust_anchors(anchors.as_bytes())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
        },
    );
    let html = certification_bundle_workbench_html(&bundle, &anchors);
    fs::write(dir.join("certification_bundle.json"), &bundle)?;
    fs::write(dir.join("trust_anchors.json"), &anchors)?;
    fs::write(dir.join("certification_bundle_report.md"), markdown)?;
    fs::write(
        dir.join("certification_bundle_lint.json"),
        certification_bundle_compile_report_json(&lint_report),
    )?;
    fs::write(
        dir.join("certification_bundle_lint.md"),
        certification_bundle_compile_report_markdown(&lint_report),
    )?;
    fs::write(dir.join("index.html"), html)?;
    fs::write(
        dir.join("bundle_fingerprints.json"),
        format!(
            "{{\"type\":\"hyperion-certification-bundle-fingerprints\",\"bundle_sha256\":\"{}\",\"payload_sha256\":\"{}\",\"scheme_profile_sha256\":\"{}\",\"vector_bundle_sha256\":\"{}\"}}\n",
            to_hex(&loaded.bundle_sha256),
            to_hex(&loaded.payload_sha256),
            to_hex(&loaded.scheme_profile_sha256),
            to_hex(&loaded.vector_bundle_sha256)
        ),
    )?;
    Ok(dir.to_path_buf())
}

fn validate_bundle(bundle_path: &Path, trust_path: &Path, mode: BuildMode) -> io::Result<()> {
    let bundle = fs::read(bundle_path)?;
    let trust = fs::read(trust_path)?;
    let loaded = load_pair_bytes(&bundle, &trust, mode)?;
    println!("bundle_id={}", loaded.bundle.bundle_id);
    println!("verification_status={}", loaded.verification_status);
    println!("bundle_sha256={}", to_hex(&loaded.bundle_sha256));
    println!("payload_sha256={}", to_hex(&loaded.payload_sha256));
    println!(
        "scheme_profile_sha256={}",
        to_hex(&loaded.scheme_profile_sha256)
    );
    println!(
        "vector_bundle_sha256={}",
        to_hex(&loaded.vector_bundle_sha256)
    );
    Ok(())
}

fn lint_bundle(bundle_path: &Path, trust_path: &Path, mode: BuildMode) -> io::Result<()> {
    let bundle = fs::read(bundle_path)?;
    let trust = fs::read(trust_path)?;
    let anchors = parse_trust_anchors(&trust).unwrap_or_default();
    let report = certification_bundle_compile_report(
        &bundle,
        &trust,
        &BundleLoadPolicy {
            mode,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: anchors,
        },
    );
    print!("{}", certification_bundle_compile_report_json(&report));
    if report.status == "fail" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certification bundle lint failed",
        ));
    }
    Ok(())
}

fn load_pair(
    bundle: &str,
    anchors: &str,
    mode: BuildMode,
) -> io::Result<hyperion_emv::cert_bundle::LoadedCertificationBundle> {
    load_pair_bytes(bundle.as_bytes(), anchors.as_bytes(), mode)
}

fn load_pair_bytes(
    bundle: &[u8],
    anchors: &[u8],
    mode: BuildMode,
) -> io::Result<hyperion_emv::cert_bundle::LoadedCertificationBundle> {
    let anchors = parse_trust_anchors(anchors)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    load_certification_bundle(
        bundle,
        &BundleLoadPolicy {
            mode,
            installed_rollback_counter: 1,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 25,
            },
            trust_anchors: anchors,
        },
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_emv::provenance::sha256;

    #[test]
    fn writes_and_validates_default_bundle_workspace() {
        let dir = env::temp_dir().join(format!("hyperion-cert-bundle-{}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        write_default_bundle(&dir).unwrap();
        let bundle = fs::read_to_string(dir.join("certification_bundle.json")).unwrap();
        let anchors = fs::read_to_string(dir.join("trust_anchors.json")).unwrap();
        let loaded = load_pair(&bundle, &anchors, BuildMode::Certification).unwrap();
        assert_eq!(loaded.verification_status, "trust-anchor-verified");
        assert!(fs::read_to_string(dir.join("index.html"))
            .unwrap()
            .contains("Data Bundle Workbench"));
        assert!(
            fs::read_to_string(dir.join("certification_bundle_report.md"))
                .unwrap()
                .contains("Data-Driven Certification Bundle")
        );
        assert!(fs::read_to_string(dir.join("bundle_fingerprints.json"))
            .unwrap()
            .contains(&to_hex(&sha256(bundle.as_bytes()))));
        assert!(
            fs::read_to_string(dir.join("certification_bundle_lint.json"))
                .unwrap()
                .contains("capability_coverage")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
