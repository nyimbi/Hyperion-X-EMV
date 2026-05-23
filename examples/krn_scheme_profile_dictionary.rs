use hyperion_emv::config::{
    load_profile_set, BuildMode, CdaAuthenticationData, CdaRequestEncoding, ConfigLoadPolicy,
    ProfileClass, ProfileSet, SignatureStatus,
};
use hyperion_emv::restrictions::EmvDate;
use hyperion_emv::taa::{ActionCodes, TerminalAction};
use hyperion_emv::KernelResult;
use std::fmt::Write;
use std::process;

const PROFILE_BUNDLE: &[u8] = include_bytes!("../docs/scheme_profiles.cert.json");

fn main() {
    match scheme_profile_dictionary_markdown() {
        Ok(markdown) => print!("{markdown}"),
        Err(err) => {
            eprintln!(
                "failed to generate scheme profile dictionary: {}",
                err.name()
            );
            process::exit(1);
        }
    }
}

fn scheme_profile_dictionary_markdown() -> KernelResult<String> {
    let profile_set = load_profile_set(PROFILE_BUNDLE, &dictionary_policy())?;
    Ok(render_dictionary(&profile_set))
}

fn dictionary_policy() -> ConfigLoadPolicy {
    ConfigLoadPolicy {
        mode: BuildMode::Certification,
        signature_status: SignatureStatus::Verified,
        installed_version: 1,
        candidate_version: 2,
        evaluation_date: EmvDate {
            year: 26,
            month: 5,
            day: 21,
        },
    }
}

fn render_dictionary(profile_set: &ProfileSet) -> String {
    let mut out = String::new();
    out.push_str("# Scheme Profile Dictionary\n\n");
    out.push_str("Generated from `docs/scheme_profiles.cert.json` by `cargo run --example krn_scheme_profile_dictionary`.\n\n");
    out.push_str("This is a repository-controlled review aid. It does not replace lab, scheme, acquirer, or CAPK authority evidence and does not close `CERT-OPEN-002` or `CERT-OPEN-003`.\n\n");

    out.push_str("## Bundle Scope\n\n");
    let _ = writeln!(out, "- Version: {}", profile_set.version);
    let _ = writeln!(
        out,
        "- Profile class: {}",
        profile_class_name(profile_set.profile_class)
    );
    let _ = writeln!(out, "- Source owner: {}", profile_set.profile_source.owner);
    let _ = writeln!(
        out,
        "- Source document: {}",
        profile_set.profile_source.document
    );
    let _ = writeln!(
        out,
        "- Source verification: {}",
        profile_set.profile_source.verification
    );
    let _ = writeln!(
        out,
        "- Source retrieved: {}",
        profile_set
            .profile_source
            .retrieved
            .map(format_emv_date)
            .unwrap_or("not recorded".to_string())
    );
    let _ = writeln!(out, "- Scheme count: {}", profile_set.schemes.len());
    out.push('\n');

    for (scheme_idx, scheme) in profile_set.schemes.iter().enumerate() {
        let _ = writeln!(out, "## {}\n", scheme.scheme_name);
        let _ = writeln!(out, "- RID: {}", hex_upper(&scheme.rid));
        let _ = writeln!(out, "- Contactless kernel profile: {}", scheme.kernel_type);
        let _ = writeln!(
            out,
            "- Contact kernel profile: {}",
            scheme.contact_kernel_type.as_deref().unwrap_or("none")
        );
        let _ = writeln!(
            out,
            "- TAA fallback when unable online: {}",
            terminal_action_name(scheme.taa.fallback_when_offline_unable_online)
        );
        let _ = writeln!(
            out,
            "- TAA no-match default when online capable: {}",
            terminal_action_name(scheme.taa.no_match_default_when_online_capable)
        );
        let _ = writeln!(
            out,
            "- TAA no-match default when offline only: {}",
            terminal_action_name(scheme.taa.no_match_default_when_offline_only)
        );
        out.push_str("\n### AID Profiles\n\n");

        for aid in &scheme.aids {
            let _ = writeln!(out, "#### AID `{}`\n", hex_upper(&aid.aid));
            let _ = writeln!(out, "- Priority: {}", aid.priority);
            let _ = writeln!(out, "- Partial selection: {}", aid.partial_selection);
            let _ = writeln!(out, "- Interfaces: {}", aid.interfaces.join(", "));
            let _ = writeln!(
                out,
                "- Terminal capabilities: 9F33 is supplied through the ABI, not embedded in this profile"
            );
            let _ = writeln!(
                out,
                "- Additional Terminal Capabilities: 9F40 is supplied through the ABI, not embedded in this profile"
            );
            let _ = writeln!(
                out,
                "- TTQ: 9F66 is supplied through the ABI for contactless DOL data, not embedded in this profile"
            );
            let _ = writeln!(out, "- Floor limit: {}", aid.floor_limit);
            let _ = writeln!(out, "- Contact CVM limit: {}", aid.cvm_limit_contact);
            let _ = writeln!(
                out,
                "- Contactless transaction limit: {}",
                aid.contactless_transaction_limit
            );
            let _ = writeln!(
                out,
                "- Contactless CVM limit: {}",
                aid.contactless_cvm_limit
            );
            let _ = writeln!(
                out,
                "- Random selection percent: {}",
                aid.random_selection_percent
            );
            let _ = writeln!(out, "- CDCVM supported: {}", aid.cdcvm_supported);
            let _ = writeln!(out, "- CDA supported: {}", aid.cda_supported);
            let _ = writeln!(
                out,
                "- CDA request encoding: {}",
                aid.cda_request_encoding
                    .map(cda_encoding_name)
                    .unwrap_or("none".to_string())
            );
            let _ = writeln!(
                out,
                "- CDA authentication data: {}",
                cda_authentication_data_name(aid.cda_authentication_data)
            );
            let _ = writeln!(
                out,
                "- Default CDOL1 length: {} bytes",
                aid.default_cdol1.as_ref().map_or(0, Vec::len)
            );
            let _ = writeln!(
                out,
                "- Critical issuer script INS: {}",
                join_hex_bytes(&aid.critical_issuer_script_ins)
            );
            append_action_codes(&mut out, "TAC", aid.action_codes);
            append_action_codes(&mut out, "IAC", aid.issuer_action_codes);
            out.push('\n');
        }

        out.push_str("### CAPK Provenance\n\n");
        for capk in &scheme.capks {
            let _ = writeln!(out, "- RID: {}", hex_upper(&capk.rid));
            let _ = writeln!(out, "  - Key index: {}", capk.key_index);
            let _ = writeln!(out, "  - Modulus length: {} bytes", capk.modulus.len());
            let _ = writeln!(out, "  - Exponent length: {} bytes", capk.exponent.len());
            let _ = writeln!(out, "  - Expiry: {}", format_emv_date(capk.expiry));
            let _ = writeln!(out, "  - Checksum: {}", hex_upper(&capk.checksum));
            let _ = writeln!(out, "  - Source owner: {}", capk.source.owner);
            let _ = writeln!(out, "  - Source document: {}", capk.source.document);
            let _ = writeln!(out, "  - Source verification: {}", capk.source.verification);
            let _ = writeln!(
                out,
                "  - Source retrieved: {}",
                capk.source
                    .retrieved
                    .map(format_emv_date)
                    .unwrap_or("not recorded".to_string())
            );
        }
        if scheme_idx + 1 < profile_set.schemes.len() {
            out.push('\n');
        }
    }

    out
}

fn append_action_codes(out: &mut String, label: &str, action_codes: ActionCodes) {
    let _ = writeln!(
        out,
        "- {label}: denial={}, online={}, default={}",
        hex_upper(&action_codes.denial),
        hex_upper(&action_codes.online),
        hex_upper(&action_codes.default)
    );
}

fn profile_class_name(profile_class: ProfileClass) -> &'static str {
    match profile_class {
        ProfileClass::Certification => "CERTIFICATION",
        ProfileClass::ExampleOnly => "EXAMPLE_ONLY",
    }
}

fn terminal_action_name(action: TerminalAction) -> &'static str {
    match action {
        TerminalAction::Aac => "AAC",
        TerminalAction::Tc => "TC",
        TerminalAction::Arqc => "ARQC",
    }
}

fn cda_encoding_name(encoding: CdaRequestEncoding) -> String {
    match encoding {
        CdaRequestEncoding::InCdolData => "CDOL1 bit".to_string(),
        CdaRequestEncoding::P1LowBits(bits) => format!("P1 low bits 0x{bits:02X}"),
    }
}

fn cda_authentication_data_name(data: CdaAuthenticationData) -> &'static str {
    match data {
        CdaAuthenticationData::ApplicationCryptogram => "application cryptogram",
        CdaAuthenticationData::ApplicationCryptogramAndIccDynamicNumber => {
            "application cryptogram + 9F4C"
        }
    }
}

fn join_hex_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "none".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_emv_date(date: EmvDate) -> String {
    format!("20{:02}-{:02}-{:02}", date.year, date.month, date.day)
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_is_deterministic_and_review_scoped() {
        let markdown = scheme_profile_dictionary_markdown().unwrap();

        assert!(markdown.starts_with("# Scheme Profile Dictionary\n\n"));
        assert!(markdown.contains("Generated from `docs/scheme_profiles.cert.json`"));
        assert!(markdown.contains("does not close `CERT-OPEN-002` or `CERT-OPEN-003`"));
        assert!(markdown.contains("## Visa"));
        assert!(markdown.contains("## Mastercard"));
        assert!(markdown.contains("- Interfaces: contact, contactless"));
        assert!(markdown.contains("- TTQ: 9F66 is supplied through the ABI"));
        assert!(markdown.contains("- Terminal capabilities: 9F33 is supplied through the ABI"));
        assert!(markdown
            .contains("- Additional Terminal Capabilities: 9F40 is supplied through the ABI"));
        assert!(
            markdown.contains("- TAC: denial=0000000000, online=E0F8C80000, default=8000000000")
        );
        assert!(markdown.contains("- Modulus length: 248 bytes"));
        assert!(markdown.contains("- Source verification: external_signature_required"));
        assert!(markdown.contains("- Source retrieved: 2026-05-21"));
        assert!(markdown.contains("  - Source retrieved: 2026-05-21"));
    }

    #[test]
    fn dictionary_does_not_emit_raw_capk_moduli_or_cdol_values() {
        let markdown = scheme_profile_dictionary_markdown().unwrap();

        assert!(!markdown.contains("9D912248DE0A4E39"));
        assert!(!markdown.contains("CB26FC830B43785B"));
        assert!(!markdown.contains("9F370495059F02069A039C019F1A029F3403"));
    }
}
