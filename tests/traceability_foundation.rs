use hyperion_emv::afl::{parse_afl, read_record_commands, record_plan};
use hyperion_emv::apdu::{
    generate_ac, select_environment, CdaRequestControl, CryptogramRequest, Interface,
};
use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::cvm::{
    evaluate as evaluate_cvm, parse_cvm_list, CvmAction, CvmContext, CvmOutcome,
    Interface as CvmInterface, PedPinHandle,
};
use hyperion_emv::restrictions::{
    evaluate as evaluate_restrictions, ApplicationUsageControl, EmvDate, RestrictionInput,
    ServiceType, TransactionRegion,
};
use hyperion_emv::state::Tvr;
use hyperion_emv::sw::{classify, ApduContext, StatusAction, StatusWord};
use hyperion_emv::taa::{decide, ActionCodes, TaaInput, TaaProfile, TerminalAction};
use hyperion_emv::tlv;
use hyperion_emv::trm::{evaluate as evaluate_trm, TrmInput, TrmProfile};

const RTM: &str = concat!(
    include_str!("../docs/requirements-traceability-matrix.csv"),
    include_str!("../docs/requirements_traceability.csv")
);
const SCHEME_PROFILES: &str = include_str!("../docs/scheme_profiles.cert.json");
const TLV_CATALOGUE: &str = include_str!("../docs/tlv_catalogue.csv");
const CORRECTED_SPEC: &str = include_str!("../docs/hyperion_emv_l2_kernel_spec_v3_1_corrected.md");

#[test]
fn rtm_contains_foundation_requirements_under_test() {
    for krn_id in [
        "KRN-SEL-001",
        "KRN-TVR-001",
        "KRN-TVR-002",
        "KRN-CID-001",
        "KRN-CVM-001",
        "KRN-CVM-002",
        "KRN-CVM-003",
        "KRN-GAC-008",
        "KRN-GAC-009",
        "KRN-TAA-004",
        "KRN-TAA-005",
        "KRN-TAA-006",
        "KRN-TAA-007",
        "KRN-APDU-009",
        "KRN-APDU-010",
        "KRN-SEC-004",
        "KRN-API-006",
    ] {
        assert!(
            RTM.contains(krn_id),
            "missing traceability row for {krn_id}"
        );
    }
}

#[test]
fn spec_contains_certified_cvm_code_table_and_ped_boundary() {
    let spec = include_str!("../docs/spec.md");
    for fragment in [
        "`0x01` | Offline plaintext PIN",
        "`0x02` | Online PIN",
        "`0x1E` | Fail CVM processing",
        "`0x1F` | No CVM required",
        "CDCVM handling **SHALL** be contactless",
    ] {
        assert!(spec.contains(fragment), "spec missing {fragment}");
    }
}

#[test]
fn corrected_spec_contains_processing_restriction_and_trm_requirements() {
    for krn_id in [
        "KRN-REST-001",
        "KRN-REST-002",
        "KRN-TRM-001",
        "KRN-TRM-002",
        "KRN-TRM-003",
        "KRN-TRM-004",
    ] {
        assert!(
            CORRECTED_SPEC.contains(krn_id),
            "corrected spec missing {krn_id}"
        );
    }
}

#[test]
fn state_machine_annex_contains_afl_read_record_rows() {
    let state_machine = include_str!("../docs/state_machine.csv");
    for fragment in [
        "Parse AIP/AFL, start reading",
        "Store record, continue AFL loop",
        "Set TVR_ICC_DATA_MISSING, continue",
    ] {
        assert!(
            state_machine.contains(fragment),
            "state machine missing {fragment}"
        );
    }
}

#[test]
fn state_machine_annex_contains_restrictions_and_trm_rows() {
    let state_machine = include_str!("../docs/state_machine.csv");
    for fragment in [
        "Processing restrictions ok",
        "Processing restrictions failed",
        "TRM ok",
        "TRM force online",
    ] {
        assert!(
            state_machine.contains(fragment),
            "state machine missing {fragment}"
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
fn lifecycle_afl_plan_produces_read_record_sequence_and_oda_flags() {
    let entries = parse_afl(&hex("10010302")).unwrap();
    let plan = record_plan(&entries).unwrap();
    assert_eq!(plan.len(), 3);
    assert!(plan[0].contributes_to_offline_auth);
    assert!(plan[1].contributes_to_offline_auth);
    assert!(!plan[2].contributes_to_offline_auth);

    let commands: Vec<Vec<u8>> = read_record_commands(&entries)
        .unwrap()
        .iter()
        .map(|cmd| cmd.encode().unwrap())
        .collect();
    assert_eq!(
        commands,
        vec![hex("00B2011400"), hex("00B2021400"), hex("00B2031400")]
    );
}

#[test]
fn krn_apdu_009_010_status_handling_is_context_specific() {
    assert_eq!(
        classify(ApduContext::SelectPse, StatusWord::new(0x6a, 0x82)),
        StatusAction::FallbackToDirectAid
    );
    assert_eq!(
        classify(ApduContext::SelectAid, StatusWord::new(0x6a, 0x82)),
        StatusAction::TryNextAid
    );
    assert_eq!(
        classify(ApduContext::ReadRecord, StatusWord::new(0x6a, 0x83)),
        StatusAction::EndOfRecords
    );
    assert_eq!(
        classify(ApduContext::ReadRecord, StatusWord::new(0x69, 0x85)),
        StatusAction::ContinueWithTvr {
            bit: Tvr::B1_ICC_DATA_MISSING
        }
    );
    assert_eq!(
        classify(ApduContext::GenerateAc, StatusWord::new(0x69, 0x85)),
        StatusAction::Fail {
            error: hyperion_emv::KernelError::CardRemoved
        }
    );
}

#[test]
fn krn_cvm_001_002_003_and_sec_004_use_cvm_table_without_clear_pin() {
    let cvm_list = parse_cvm_list(&[
        0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x27, 0x10, 0x01, 0x00, 0x02, 0x07, 0x1f, 0x00,
    ])
    .unwrap();
    let context = CvmContext {
        amount_authorized: 1_000,
        transaction_currency_matches_application: true,
        interface: CvmInterface::Contact,
        offline_pin_supported: true,
        online_pin_supported: true,
        signature_supported: true,
        cdcvm_performed: false,
    };
    assert_eq!(
        evaluate_cvm(&cvm_list, context, None),
        CvmOutcome::Failed {
            cvm_results: [0x01, 0x00, 0x01],
            tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
        }
    );

    let handle = PedPinHandle::new(42).unwrap();
    assert_eq!(
        evaluate_cvm(&cvm_list, context, Some(handle)),
        CvmOutcome::Selected {
            action: CvmAction::OfflinePlaintextPin { ped_handle: handle },
            cvm_results: [0x01, 0x00, 0x02]
        }
    );
}

#[test]
fn contactless_cdcvm_is_not_hardcoded_to_cvm_code_0x05() {
    let cvm_list = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x00]).unwrap();
    let context = CvmContext {
        amount_authorized: 1_000,
        transaction_currency_matches_application: true,
        interface: CvmInterface::Contactless,
        offline_pin_supported: false,
        online_pin_supported: true,
        signature_supported: false,
        cdcvm_performed: true,
    };

    assert_eq!(
        evaluate_cvm(&cvm_list, context, None),
        CvmOutcome::Selected {
            action: CvmAction::Cdcvm,
            cvm_results: [0x20, 0x00, 0x02]
        }
    );
}

#[test]
fn processing_restrictions_mutate_only_defined_tvr_bits() {
    let result = evaluate_restrictions(
        RestrictionInput {
            transaction_date: EmvDate::from_bcd([0x31, 0x01, 0x01]).unwrap(),
            application_expiration_date: EmvDate::from_bcd([0x30, 0x12, 0x31]).unwrap(),
            application_effective_date: Some(EmvDate::from_bcd([0x32, 0x01, 0x01]).unwrap()),
            card_application_version: Some([0x00, 0x02]),
            terminal_application_version: Some([0x00, 0x01]),
            auc: ApplicationUsageControl::new([0x00, 0x00]),
            region: TransactionRegion::Domestic,
            service: ServiceType::Goods,
            new_card: true,
        },
        Tvr::cleared(),
    );

    assert!(result.failed);
    assert_eq!(result.tvr.bytes(), [0x00, 0xf8, 0x00, 0x00, 0x00]);
}

#[test]
fn trm_sets_floor_random_velocity_exception_and_tsi_bits() {
    let result = evaluate_trm(
        TrmInput {
            amount_authorized: 6_000,
            exception_file_match: true,
            merchant_forced_online: true,
            consecutive_offline_count: Some(5),
            random_sample_basis_points: Some(499),
            profile: TrmProfile::new(5_000, 5, Some(2), Some(4)).unwrap(),
        },
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
    );

    assert!(result.force_online);
    assert_eq!(result.tvr.bytes(), [0x10, 0x00, 0x00, 0xf8, 0x00]);
    assert_eq!(result.tsi.bytes(), [0x08, 0x00]);
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
