use hyperion_emv::apdu::{
    generate_ac, select_environment, CdaRequestControl, CryptogramRequest, Interface,
};
use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::state::Tvr;
use hyperion_emv::taa::{decide, ActionCodes, TaaInput, TaaProfile, TerminalAction};
use hyperion_emv::tlv;

const RTM: &str = concat!(
    include_str!("../docs/requirements-traceability-matrix.csv"),
    include_str!("../docs/requirements_traceability.csv")
);
const SCHEME_PROFILES: &str = include_str!("../docs/scheme_profiles.cert.json");
const TLV_CATALOGUE: &str = include_str!("../docs/tlv_catalogue.csv");

#[test]
fn rtm_contains_foundation_requirements_under_test() {
    for krn_id in [
        "KRN-SEL-001",
        "KRN-TVR-001",
        "KRN-TVR-002",
        "KRN-CID-001",
        "KRN-GAC-008",
        "KRN-GAC-009",
        "KRN-TAA-004",
        "KRN-TAA-005",
        "KRN-TAA-006",
        "KRN-TAA-007",
        "KRN-API-006",
    ] {
        assert!(
            RTM.contains(krn_id),
            "missing traceability row for {krn_id}"
        );
    }
}

#[test]
fn scheme_profile_annex_contains_deterministic_taa_keys() {
    for key in [
        "taa_fallback_when_offline_unable_online",
        "taa_no_match_default_when_online_capable",
        "taa_no_match_default_when_offline_only",
    ] {
        assert!(
            SCHEME_PROFILES.contains(key),
            "scheme profile annex missing {key}"
        );
    }
}

#[test]
fn tlv_catalogue_contains_required_foundation_tags() {
    for row_prefix in ["84,", "94,", "95,", "9B,", "9F26,", "9F27,", "9F37,"] {
        assert!(
            TLV_CATALOGUE
                .lines()
                .any(|line| line.starts_with(row_prefix)),
            "missing TLV catalogue row {row_prefix}"
        );
    }
}

#[test]
fn krn_sel_001_exact_pse_ppse_apdus_are_stable() {
    assert_eq!(
        select_environment(Interface::Contact).encode().unwrap(),
        hex("00A404000E315041592E5359532E444446303100")
    );
    assert_eq!(
        select_environment(Interface::Contactless).encode().unwrap(),
        hex("00A404000E325041592E5359532E444446303100")
    );
}

#[test]
fn krn_gac_008_009_cda_control_never_changes_type_bits() {
    let arqc = generate_ac(
        CryptogramRequest::Arqc,
        &[0x00, 0x00],
        CdaRequestControl::P1LowBits(0x10),
    )
    .unwrap();
    assert_eq!(arqc.p1 & 0xc0, 0x80);

    let invalid = generate_ac(
        CryptogramRequest::Arqc,
        &[],
        CdaRequestControl::P1LowBits(0x40),
    );
    assert!(invalid.is_err());
}

#[test]
fn krn_cid_001_decodes_with_high_bit_mask_only() {
    assert_eq!(Cid::new(0x8f).cryptogram_type(), CryptogramType::Arqc);
    assert_eq!(Cid::new(0x47).cryptogram_type(), CryptogramType::Tc);
    assert_eq!(Cid::new(0x0f).cryptogram_type(), CryptogramType::Aac);
}

#[test]
fn krn_tvr_001_002_tvr_is_symbolic_and_cleared() {
    let mut tvr = Tvr::cleared();
    assert_eq!(tvr.bytes(), [0; 5]);
    tvr.set(Tvr::B1_SDA_FAILED);
    assert_eq!(tvr.bytes(), [0x40, 0, 0, 0, 0]);
}

#[test]
fn krn_taa_004_005_006_007_uses_iac_tac_order_and_profile_fallbacks() {
    let mut tvr = Tvr::cleared();
    tvr.set(Tvr::B1_SDA_FAILED);
    let decision = decide(TaaInput {
        tvr,
        tac: ActionCodes {
            denial: [0x40, 0, 0, 0, 0],
            online: [0x40, 0, 0, 0, 0],
            default: [0; 5],
        },
        iac: ActionCodes::zeroed(),
        terminal_online_capable: true,
        profile: TaaProfile::spec_defaults(),
    });
    assert_eq!(decision.action, TerminalAction::Aac);

    let no_match = decide(TaaInput {
        tvr: Tvr::cleared(),
        tac: ActionCodes::zeroed(),
        iac: ActionCodes::zeroed(),
        terminal_online_capable: true,
        profile: TaaProfile::new(TerminalAction::Aac, TerminalAction::Tc, TerminalAction::Aac)
            .unwrap(),
    });
    assert_eq!(no_match.action, TerminalAction::Tc);
}

#[test]
fn tlv_parser_is_deterministic_for_valid_and_truncated_inputs() {
    let bytes = hex("770A82021800940408010100");
    let tlvs = tlv::parse_many(&bytes).unwrap();
    assert_eq!(tlv::find_first(&tlvs, &[0x82]), Some(&[0x18, 0x00][..]));
    assert!(tlv::parse_many(&hex("770A820218009404080101")).is_err());
}

fn hex(input: &str) -> Vec<u8> {
    assert!(input.len() % 2 == 0);
    input
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = from_hex(pair[0]);
            let low = from_hex(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn from_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
