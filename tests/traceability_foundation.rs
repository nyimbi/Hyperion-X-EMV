use hyperion_emv::afl::{parse_afl, read_record_commands, record_plan};
use hyperion_emv::apdu::{
    generate_ac, select_environment, CdaRequestControl, CryptogramRequest, Interface,
};
use hyperion_emv::c8::{
    evaluate_contactless_limits, outcome_from_limit_decision, AlternateInterface,
    ContactlessLimitDecision, ContactlessLimitInput, ContactlessOutcome, ContactlessOutcomeCode,
    StartSignal, UiRequest, UiStatus,
};
use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::config::{load_profile_set, BuildMode, ConfigLoadPolicy, SignatureStatus};
use hyperion_emv::cvm::{
    evaluate as evaluate_cvm, parse_cvm_list, CvmAction, CvmContext, CvmOutcome,
    Interface as CvmInterface, PedPinHandle,
};
use hyperion_emv::dol::DataStore;
use hyperion_emv::ffi::{
    krn_apply_host_response, krn_context_free, krn_context_new, krn_error_code_at,
    krn_error_description, krn_error_name, krn_error_table_len, krn_get_final_outcome,
    krn_get_fsm_state, krn_get_issuer_script_result, krn_get_issuer_script_result_count,
    krn_get_last_error, krn_get_online_authorization_data, krn_get_profile_version, krn_init,
    krn_load_profiles_verified, krn_process_final_generate_ac, krn_process_issuer_authentication,
    krn_process_issuer_scripts, krn_process_post_final_issuer_scripts, krn_reset,
    krn_run_transaction, krn_set_transaction_params, KrnOutcome, KrnRuntime, KrnTxnParams,
    KRN_ABI_VERSION,
};
use hyperion_emv::fsm::{
    transition, validate_state_machine_annex, FsmEvent, FsmState, TransactionFsm,
};
use hyperion_emv::gac::{build_online_authorization_package, parse_generate_ac_response};
use hyperion_emv::gpo::{parse_gpo_response, parse_pdol_from_fci, GpoResponseFormat};
use hyperion_emv::issuer::{
    apply_script_results, parse_host_response, ScriptCommandResult, ScriptPhase,
};
use hyperion_emv::oda::{
    apply_oda_outcome, select_capk, select_oda_method, selection_input_from_aip,
    validate_oda_vector_annex, CapkIntegrity, OdaFailure, OdaMethod, OdaOutcome, OdaSelection,
    OdaSelectionInput,
};
use hyperion_emv::record::parse_read_record_body;
use hyperion_emv::restrictions::{
    evaluate as evaluate_restrictions, ApplicationUsageControl, EmvDate, RestrictionInput,
    ServiceType, TransactionRegion,
};
use hyperion_emv::selection::{match_profile_candidates, parse_fci_candidate_aids};
use hyperion_emv::state::Tvr;
use hyperion_emv::sw::{classify, ApduContext, StatusAction, StatusWord};
use hyperion_emv::taa::{decide, ActionCodes, TaaInput, TaaProfile, TerminalAction};
use hyperion_emv::tlv;
use hyperion_emv::trace::{
    mask_apdu_response, mask_tlv_value, ApduTraceContext, LogPolicy, MaskedValue, ReplayExchange,
    ReplayScript, TraceIdentity,
};
use hyperion_emv::trm::{evaluate as evaluate_trm, TrmInput, TrmProfile};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

const RTM: &str = concat!(
    include_str!("../docs/requirements-traceability-matrix.csv"),
    include_str!("../docs/requirements_traceability.csv")
);
const SCHEME_PROFILES: &str = include_str!("../docs/scheme_profiles.cert.json");
const TLV_CATALOGUE: &str = include_str!("../docs/tlv_catalogue.csv");
const CORRECTED_SPEC: &str = include_str!("../docs/hyperion_emv_l2_kernel_spec_v3_1_corrected.md");
const ODA_VECTORS: &str = include_str!("../docs/oda_test_vectors.json");
const STATE_MACHINE_CSV: &str = include_str!("../docs/state_machine.csv");

static IT_TRANSMITTED_INS: AtomicU8 = AtomicU8::new(0);
static IT_TRANSMITTED_LEN: AtomicUsize = AtomicUsize::new(0);
static IT_TRANSMIT_COUNT: AtomicUsize = AtomicUsize::new(0);
static IT_TRANSMIT_TIMEOUT_MS: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn it_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    _user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let count = IT_TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
    IT_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
    IT_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    write_scripted_response(command, count, resp, resp_len)
}

unsafe extern "C" fn it_rng_test_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    _timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let counter = &*(user_data as *const AtomicUsize);
    let count = counter.fetch_add(1, Ordering::SeqCst);
    write_scripted_response(command, count, resp, resp_len)
}

unsafe fn write_scripted_response(
    command: &[u8],
    count: usize,
    resp: *mut u8,
    resp_len: *mut usize,
) -> i32 {
    let response = match count {
        0 => hex("6F13A511BF0C0E610C4F07A00000000310108701019000"),
        1 => hex("6F118407A0000000031010A5069F38039F37049000"),
        2 => hex("770A820280009404100101009000"),
        3 => hex(
            "70675A08123456789012345F5F24033012315F25032501015F280208409F0702FF809F090200018E0A00000000000000001F009F0D0500000000009F0E0500000000009F0F0500000080008C129F02069F370495059A039C019F1A029F34038D088A02910895059B029000",
        ),
        4 => hex(
            "771A9F2701809F360200099F260811121314151617189F1003AABBCC9000",
        ),
        _ if command[1] == 0xae => hex("77149F2701409F3602000A9F260821222324252627289000"),
        _ => hex("9000"),
    };
    let capacity = *resp_len;
    *resp_len = response.len();
    if capacity < response.len() {
        return hyperion_emv::KernelError::BufferTooSmall.code();
    }
    ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
    hyperion_emv::KernelError::Ok.code()
}

unsafe extern "C" fn it_unpredictable_number(
    out: *mut u8,
    out_len: usize,
    _user_data: *mut c_void,
) -> i32 {
    for idx in 0..out_len {
        *out.add(idx) = (idx as u8).wrapping_add(1);
    }
    hyperion_emv::KernelError::Ok.code()
}

unsafe extern "C" fn it_zero_unpredictable_number(
    out: *mut u8,
    out_len: usize,
    _user_data: *mut c_void,
) -> i32 {
    for idx in 0..out_len {
        *out.add(idx) = 0;
    }
    hyperion_emv::KernelError::Ok.code()
}

unsafe extern "C" fn it_fixed_unpredictable_number(
    out: *mut u8,
    out_len: usize,
    _user_data: *mut c_void,
) -> i32 {
    let value = [0x11, 0x22, 0x33, 0x44];
    for idx in 0..out_len {
        *out.add(idx) = value[idx % value.len()];
    }
    hyperion_emv::KernelError::Ok.code()
}

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
        "KRN-SEC-002",
        "KRN-GAC-008",
        "KRN-GAC-009",
        "KRN-TAA-004",
        "KRN-TAA-005",
        "KRN-TAA-006",
        "KRN-TAA-007",
        "KRN-APDU-009",
        "KRN-APDU-010",
        "KRN-GPO-001",
        "KRN-GPO-002",
        "KRN-RR-001",
        "KRN-RR-002",
        "KRN-RR-003",
        "KRN-SEC-004",
        "KRN-API-006",
        "KRN-LOG-001",
        "KRN-C8-001",
        "KRN-C8-002",
        "KRN-C8-003",
        "KRN-ODA-001",
        "KRN-ODA-005",
        "KRN-ODA-006",
        "KRN-ODA-007",
        "KRN-ODA-008",
        "KRN-IAUTH-001",
        "KRN-IAUTH-002",
        "KRN-IAUTH-003",
        "KRN-GAC2-001",
        "KRN-GAC2-002",
        "KRN-GAC2-003",
        "KRN-GAC2-004",
        "KRN-SCR-001",
        "KRN-SCR-002",
        "KRN-SCR-003",
        "KRN-SCR-004",
        "KRN-SCR-005",
        "KRN-SCR-006",
        "KRN-DPL-004",
        "KRN-RNG-001",
        "KRN-RNG-002",
        "KRN-ERR-001",
    ] {
        assert!(
            RTM.contains(krn_id),
            "missing traceability row for {krn_id}"
        );
    }
}

#[test]
fn corrected_spec_contains_logging_and_replay_requirements() {
    for krn_id in [
        "KRN-FSM-001",
        "KRN-FSM-002",
        "KRN-FSM-003",
        "KRN-FSM-004",
        "KRN-LOG-001",
        "KRN-LOG-002",
        "KRN-LOG-003",
        "KRN-LOG-004",
        "KRN-RNG-001",
        "KRN-RNG-002",
        "KRN-ERR-001",
    ] {
        assert!(
            CORRECTED_SPEC.contains(krn_id),
            "corrected spec missing {krn_id}"
        );
    }
}

#[test]
fn corrected_spec_contains_api_transaction_runner_requirements() {
    for krn_id in [
        "KRN-API-001",
        "KRN-API-002",
        "KRN-API-003",
        "KRN-API-004",
        "KRN-API-005",
        "KRN-API-006",
        "KRN-API-007",
    ] {
        assert!(
            CORRECTED_SPEC.contains(krn_id),
            "corrected spec missing {krn_id}"
        );
    }
}

#[test]
fn corrected_spec_contains_contactless_c8_outcome_requirements() {
    for krn_id in [
        "KRN-INT-002",
        "KRN-CLESS-001",
        "KRN-CLESS-002",
        "KRN-CLESS-003",
        "KRN-C8-001",
        "KRN-C8-002",
    ] {
        assert!(
            CORRECTED_SPEC.contains(krn_id),
            "corrected spec missing {krn_id}"
        );
    }
}

#[test]
fn corrected_spec_contains_gac_online_and_script_requirements() {
    for krn_id in [
        "KRN-GAC1-004",
        "KRN-ONL-001",
        "KRN-ONL-002",
        "KRN-IAUTH-001",
        "KRN-IAUTH-002",
        "KRN-IAUTH-003",
        "KRN-GAC2-001",
        "KRN-GAC2-002",
        "KRN-GAC2-003",
        "KRN-GAC2-004",
        "KRN-SCR-001",
        "KRN-SCR-002",
        "KRN-SCR-003",
        "KRN-SCR-004",
        "KRN-SCR-005",
        "KRN-SCR-006",
    ] {
        assert!(
            CORRECTED_SPEC.contains(krn_id),
            "corrected spec missing {krn_id}"
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
fn corrected_spec_contains_config_profile_and_capk_requirements() {
    for krn_id in [
        "KRN-CFG-001",
        "KRN-CFG-002",
        "KRN-CFG-003",
        "KRN-CFG-004",
        "KRN-PROFILE-001",
        "KRN-PROFILE-002",
        "KRN-CAPK-001",
        "KRN-CAPK-002",
        "KRN-DPL-004",
    ] {
        assert!(
            CORRECTED_SPEC.contains(krn_id),
            "corrected spec missing {krn_id}"
        );
    }
}

#[test]
fn corrected_spec_contains_oda_selection_capk_and_vector_requirements() {
    for krn_id in [
        "KRN-ODA-001",
        "KRN-ODA-002",
        "KRN-ODA-003",
        "KRN-ODA-004",
        "KRN-ODA-005",
        "KRN-ODA-006",
        "KRN-ODA-007",
        "KRN-CAPK-001",
        "KRN-CAPK-002",
        "KRN-ODATV-001",
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
        "EXTERNAL AUTHENTICATE returns 9000",
        "Set issuer-authentication TSI and TVR failure bit",
    ] {
        assert!(
            state_machine.contains(fragment),
            "state machine missing {fragment}"
        );
    }
}

#[test]
fn state_machine_annex_contains_post_final_script_rows() {
    let state_machine = include_str!("../docs/state_machine.csv");
    for fragment in [
        "Process post-final issuer scripts before online approve",
        "Template 72",
        "Log post-final script failure, continue (non-critical)",
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
fn profile_loader_requires_verified_signature_and_extracts_capk_tac_limits() {
    let unsigned_policy = ConfigLoadPolicy {
        mode: BuildMode::Certification,
        signature_status: SignatureStatus::NotPresent,
        installed_version: 1,
        candidate_version: 2,
        evaluation_date: EmvDate {
            year: 26,
            month: 5,
            day: 21,
        },
    };
    assert_eq!(
        load_profile_set(SCHEME_PROFILES.as_bytes(), &unsigned_policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let verified_policy = ConfigLoadPolicy {
        signature_status: SignatureStatus::Verified,
        ..unsigned_policy
    };
    let profiles = load_profile_set(SCHEME_PROFILES.as_bytes(), &verified_policy).unwrap();
    assert_eq!(profiles.schemes.len(), 2);
    assert_eq!(profiles.schemes[0].rid, hex("A000000003").as_slice());
    assert_eq!(
        profiles.schemes[0].aids[0].action_codes.online,
        [0xe0, 0xf8, 0xc8, 0x00, 0x00]
    );
    assert_eq!(
        profiles.schemes[0].aids[0].critical_issuer_script_ins,
        [0xe2]
    );
    assert_eq!(
        profiles.schemes[1].aids[0].critical_issuer_script_ins,
        [0xe2]
    );
    assert_eq!(
        profiles.schemes[0].aids[0]
            .trm_profile()
            .unwrap()
            .random_selection_percent,
        5
    );
    assert_eq!(profiles.schemes[0].capks[0].key_index, 8);
    assert!(profiles.schemes[0].capks[0].modulus.len() >= 64);
    assert_eq!(
        profiles.schemes[0].capks[0].checksum,
        hex("20D213126955DE205ADC2FD2822BD22DE21CF9A8")
    );
    assert_eq!(profiles.schemes[1].capks[0].key_index, 5);
    assert_eq!(
        profiles.schemes[1].capks[0].checksum,
        hex("EBFA0D5D06D8CE702DA3EAE890701D45E274C845")
    );
    assert!(profiles
        .schemes
        .iter()
        .flat_map(|scheme| scheme.capks.iter())
        .all(|capk| capk.checksum.len() == 20));
    assert!(profiles.schemes.iter().all(|scheme| {
        scheme.rid != hex("A000000999").as_slice()
            && scheme.aids.iter().all(|aid| aid.aid != hex("A000000999C8"))
    }));
}

#[test]
fn profile_loader_rejects_rollback_placeholders_and_expired_capks() {
    let base_policy = ConfigLoadPolicy {
        mode: BuildMode::Certification,
        signature_status: SignatureStatus::Verified,
        installed_version: 2,
        candidate_version: 1,
        evaluation_date: EmvDate {
            year: 26,
            month: 5,
            day: 21,
        },
    };
    assert_eq!(
        load_profile_set(SCHEME_PROFILES.as_bytes(), &base_policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let expired_policy = ConfigLoadPolicy {
        installed_version: 1,
        candidate_version: 2,
        evaluation_date: EmvDate {
            year: 31,
            month: 1,
            day: 2,
        },
        ..base_policy
    };
    assert_eq!(
        load_profile_set(SCHEME_PROFILES.as_bytes(), &expired_policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let placeholder = br#"{"scheme_profiles":[{"scheme_name":"Visa","rid":"A000000003","kernel_type":"x","taa_fallback_when_offline_unable_online":"AAC","taa_no_match_default_when_online_capable":"ARQC","taa_no_match_default_when_offline_only":"AAC","aids":[{"aid":"A0000000031010","priority":1,"partial_selection":true,"interfaces":["contact"],"tac_online":"0000000000","tac_denial":"0000000000","tac_default":"0000000000","iac_online":"0000000000","iac_denial":"0000000000","iac_default":"0000000000","floor_limit":0,"cvm_limit_contact":0,"random_selection_percent":0,"contactless_transaction_limit":0,"contactless_cvm_limit":0,"cdcvm_supported":false,"cda_supported":false}],"capks":[{"key_index":1,"modulus_hex":"D2E5F5B3A1...","exponent_hex":"010001","expiry":"2030-01-01","checksum_hex":"00112233445566778899AABBCCDDEEFF"}]}]}"#;
    let valid_policy = ConfigLoadPolicy {
        installed_version: 1,
        candidate_version: 2,
        evaluation_date: EmvDate {
            year: 26,
            month: 5,
            day: 21,
        },
        ..base_policy
    };
    assert_eq!(
        load_profile_set(placeholder, &valid_policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
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
fn krn_fsm_001_002_004_validates_annex_and_error_transitions() {
    assert!(validate_state_machine_annex(STATE_MACHINE_CSV).unwrap() >= 45);

    let mut fsm = TransactionFsm::new();
    for event in [
        FsmEvent::SetTransactionParams,
        FsmEvent::CardDetected,
        FsmEvent::PseSelected,
        FsmEvent::CandidateAidAvailable,
        FsmEvent::AidSelected,
        FsmEvent::GpoTemplate77,
    ] {
        fsm.apply(event).unwrap();
    }
    assert_eq!(fsm.state(), FsmState::S4);

    assert_eq!(
        transition(FsmState::S4, FsmEvent::RecordReadFailed)
            .unwrap()
            .to,
        FsmState::S5
    );
    let fatal = transition(FsmState::S3, FsmEvent::GpoFailed).unwrap();
    assert_eq!(fatal.to, FsmState::Se);
    assert_eq!(fatal.error, hyperion_emv::KernelError::MissingMandatoryTag);
    assert_eq!(
        transition(FsmState::S11, FsmEvent::HostTimeout)
            .unwrap()
            .error,
        hyperion_emv::KernelError::HostTimeout
    );
    assert_eq!(
        transition(FsmState::S10, FsmEvent::CardRemoved)
            .unwrap()
            .error,
        hyperion_emv::KernelError::CardRemoved
    );
}

#[test]
fn krn_sel_001_002_003_parses_candidates_and_matches_signed_profiles() {
    let fci = hex("6F13A511BF0C0E610C4F07A0000000031010870101");
    let card_candidates = parse_fci_candidate_aids(&fci).unwrap();
    assert_eq!(card_candidates, vec![hex("A0000000031010")]);

    let profiles = load_profile_set(
        SCHEME_PROFILES.as_bytes(),
        &ConfigLoadPolicy {
            mode: BuildMode::Certification,
            signature_status: SignatureStatus::Verified,
            installed_version: 1,
            candidate_version: 2,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
        },
    )
    .unwrap();
    let selected = match_profile_candidates(&profiles, Interface::Contact, &card_candidates)
        .unwrap()
        .remove(0);
    assert_eq!(selected.aid, hex("A0000000031010"));
}

#[test]
fn krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates() {
    let selected_fci = hex("6F118407A0000000031010A5069F38039F3704");
    let pdol = parse_pdol_from_fci(&selected_fci).unwrap();
    assert_eq!(pdol.len(), 1);
    assert_eq!(pdol[0].tag, hex("9F37"));
    assert_eq!(pdol[0].length, 4);

    let template77 = parse_gpo_response(&hex("770A82021800940410010100")).unwrap();
    assert_eq!(template77.format, GpoResponseFormat::Template77);
    assert_eq!(template77.aip, [0x18, 0x00]);
    assert_eq!(template77.afl, parse_afl(&hex("10010100")).unwrap());

    let template80 = parse_gpo_response(&hex("80021800")).unwrap();
    assert_eq!(template80.format, GpoResponseFormat::Template80);
    assert_eq!(template80.aip, [0x18, 0x00]);
    assert!(template80.afl.is_empty());

    assert_eq!(
        parse_gpo_response(&hex("770482021800")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
}

#[test]
fn krn_api_006_007_run_transaction_entrypoint_errors_without_runtime_callbacks() {
    unsafe {
        let ctx = krn_context_new();
        assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::Se.code());

        assert_eq!(krn_reset(ctx), hyperion_emv::KernelError::Ok.code());
        let merchant = b"HYPERION TEST MERCHANT";
        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: merchant.as_ptr(),
            merchant_name_location_len: merchant.len(),
        };
        assert_eq!(
            krn_set_transaction_params(ctx, &params),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S1.code());

        assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::Se.code());
        krn_context_free(ctx);
    }
}

#[test]
fn krn_api_001_002_004_006_runtime_callbacks_are_versioned_and_bounded() {
    unsafe {
        let mut ctx = ptr::null_mut();
        let missing = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: None,
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(ptr::null(), &missing, &mut ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert!(ctx.is_null());

        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(ptr::null(), &runtime, &mut ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert!(!ctx.is_null());
        assert_eq!(
            krn_load_profiles_verified(
                ctx,
                SCHEME_PROFILES.as_ptr(),
                SCHEME_PROFILES.len(),
                1,
                2,
                26,
                5,
                21,
            ),
            hyperion_emv::KernelError::Ok.code()
        );
        let mut profile_version = 0u64;
        assert_eq!(
            krn_get_profile_version(ctx, &mut profile_version),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(profile_version, 2);

        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 0,
        };
        assert_eq!(
            krn_set_transaction_params(ctx, &params),
            hyperion_emv::KernelError::Ok.code()
        );
        IT_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error as i32);
        assert_eq!(IT_TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(IT_TRANSMIT_COUNT.load(Ordering::SeqCst), 5);
        assert_eq!(IT_TRANSMITTED_LEN.load(Ordering::SeqCst), 30);
        assert!(IT_TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst) > 0);
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S11.code());
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        let mut auth_len = 0usize;
        assert_eq!(
            krn_get_online_authorization_data(ctx, ptr::null_mut(), &mut auth_len),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut auth = vec![0u8; auth_len];
        assert_eq!(
            krn_get_online_authorization_data(ctx, auth.as_mut_ptr(), &mut auth_len),
            hyperion_emv::KernelError::Ok.code()
        );
        let auth_tlvs = tlv::parse_many(&auth).unwrap();
        assert_eq!(
            tlv::find_first(&auth_tlvs, &[0x9f, 0x26]),
            Some(&hex("1112131415161718")[..])
        );
        assert_eq!(
            tlv::find_first(&auth_tlvs, &[0x9f, 0x27]),
            Some(&[0x80][..])
        );
        assert_eq!(
            tlv::find_first(&auth_tlvs, &[0x82]),
            Some(&[0x80, 0x00][..])
        );
        let host = hex("8A023030910811223344556677887108860600DA000001AA7208860680E2000001BB");
        assert_eq!(
            krn_apply_host_response(ctx, host.as_ptr(), host.len()),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S12.code());
        assert_eq!(
            krn_process_issuer_authentication(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(IT_TRANSMITTED_INS.load(Ordering::SeqCst), 0x82);
        assert_eq!(IT_TRANSMITTED_LEN.load(Ordering::SeqCst), 13);
        assert_eq!(IT_TRANSMIT_COUNT.load(Ordering::SeqCst), 6);
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S13.code());
        assert_eq!(
            krn_process_issuer_scripts(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(IT_TRANSMITTED_INS.load(Ordering::SeqCst), 0xda);
        assert_eq!(IT_TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(IT_TRANSMIT_COUNT.load(Ordering::SeqCst), 7);
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S14.code());
        assert_eq!(krn_get_issuer_script_result_count(ctx), 1);
        let mut sw1 = 0u8;
        let mut sw2 = 0u8;
        assert_eq!(
            krn_get_issuer_script_result(ctx, 0, &mut sw1, &mut sw2),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!((sw1, sw2), (0x90, 0x00));
        assert_eq!(
            krn_process_final_generate_ac(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(IT_TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(IT_TRANSMITTED_LEN.load(Ordering::SeqCst), 23);
        assert_eq!(IT_TRANSMIT_COUNT.load(Ordering::SeqCst), 8);
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S15.code());
        assert_eq!(
            krn_get_final_outcome(ctx),
            KrnOutcome::ApprovedOnline as i32
        );
        assert_eq!(
            krn_process_post_final_issuer_scripts(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(IT_TRANSMITTED_INS.load(Ordering::SeqCst), 0xe2);
        assert_eq!(IT_TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(IT_TRANSMIT_COUNT.load(Ordering::SeqCst), 9);
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S16.code());
        assert_eq!(krn_get_issuer_script_result_count(ctx), 2);
        assert_eq!(
            krn_get_issuer_script_result(ctx, 1, &mut sw1, &mut sw2),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!((sw1, sw2), (0x90, 0x00));
        assert_eq!(
            krn_get_final_outcome(ctx),
            KrnOutcome::ApprovedOnline as i32
        );
        krn_context_free(ctx);
    }
}

#[test]
fn krn_rng_001_002_rejects_zero_and_repeated_unpredictable_numbers() {
    unsafe fn init_with_rng(
        callback: hyperion_emv::ffi::KrnGetUnpredictableNumberCallback,
        apdu_counter: &AtomicUsize,
    ) -> *mut hyperion_emv::ffi::KrnContext {
        let mut ctx = ptr::null_mut();
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_rng_test_transmit_apdu),
            get_unpredictable_number: Some(callback),
            contactless_outcome: None,
            user_data: (apdu_counter as *const AtomicUsize)
                .cast_mut()
                .cast::<c_void>(),
        };
        assert_eq!(
            krn_init(ptr::null(), &runtime, &mut ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            krn_load_profiles_verified(
                ctx,
                SCHEME_PROFILES.as_ptr(),
                SCHEME_PROFILES.len(),
                1,
                2,
                26,
                5,
                21,
            ),
            hyperion_emv::KernelError::Ok.code()
        );
        ctx
    }

    unsafe fn set_params(ctx: *mut hyperion_emv::ffi::KrnContext) {
        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 0,
        };
        assert_eq!(
            krn_set_transaction_params(ctx, &params),
            hyperion_emv::KernelError::Ok.code()
        );
    }

    unsafe {
        let zero_apdu_counter = AtomicUsize::new(0);
        let zero_ctx = init_with_rng(it_zero_unpredictable_number, &zero_apdu_counter);
        set_params(zero_ctx);
        assert_eq!(krn_run_transaction(zero_ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(zero_ctx),
            hyperion_emv::KernelError::RngFailure.code()
        );
        assert_eq!(krn_get_fsm_state(zero_ctx), FsmState::Se.code());
        krn_context_free(zero_ctx);

        let repeated_apdu_counter = AtomicUsize::new(0);
        let repeated_ctx = init_with_rng(it_fixed_unpredictable_number, &repeated_apdu_counter);
        set_params(repeated_ctx);
        assert_eq!(krn_run_transaction(repeated_ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(repeated_ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(
            krn_reset(repeated_ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        set_params(repeated_ctx);
        repeated_apdu_counter.store(0, Ordering::SeqCst);
        assert_eq!(krn_run_transaction(repeated_ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(repeated_ctx),
            hyperion_emv::KernelError::RngFailure.code()
        );
        assert_eq!(krn_get_fsm_state(repeated_ctx), FsmState::Se.code());
        krn_context_free(repeated_ctx);
    }
}

#[test]
fn krn_err_001_exposes_stable_abi_error_table() {
    unsafe {
        assert!(krn_error_table_len() >= 14);

        let mut first_code = -1i32;
        assert_eq!(
            krn_error_code_at(0, &mut first_code),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(first_code, hyperion_emv::KernelError::Ok.code());

        let mut rng_code = -1i32;
        assert_eq!(
            krn_error_code_at(13, &mut rng_code),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(rng_code, hyperion_emv::KernelError::RngFailure.code());

        let mut len = 0usize;
        assert_eq!(
            krn_error_name(rng_code, ptr::null_mut(), &mut len),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut name = vec![0u8; len];
        assert_eq!(
            krn_error_name(rng_code, name.as_mut_ptr(), &mut len),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(&name, b"KRN_ERR_RNG_FAILURE");

        let mut description_len = 0usize;
        assert_eq!(
            krn_error_description(rng_code, ptr::null_mut(), &mut description_len),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut description = vec![0u8; description_len];
        assert_eq!(
            krn_error_description(rng_code, description.as_mut_ptr(), &mut description_len),
            hyperion_emv::KernelError::Ok.code()
        );
        let description = core::str::from_utf8(&description).unwrap();
        assert!(description.contains("RNG"));

        assert_eq!(
            krn_error_name(9_999, ptr::null_mut(), &mut len),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
    }
}

#[test]
fn krn_log_001_masks_sensitive_tlv_and_gac_trace_values() {
    let pan = mask_tlv_value(&[0x5a], &hex("123456789012345F"), LogPolicy::production());
    assert_eq!(pan.value, MaskedValue::Pan("***********2345".to_string()));

    let track = mask_tlv_value(
        &[0x57],
        &hex("123456789012D25122012345678F"),
        LogPolicy::production(),
    );
    assert_eq!(track.value, MaskedValue::Suppressed("track2"));

    let response = hex("800B800001DEADBEEF00000001");
    let event = mask_apdu_response(
        1,
        ApduTraceContext::GenerateAcResponse,
        &response,
        [0x90, 0x00],
        LogPolicy::production(),
    )
    .unwrap();
    let json = event.to_json();
    assert!(json.contains("\"tag\":\"9f26\""));
    assert!(json.contains("transaction-cryptogram"));
    assert!(!json.contains("deadbeef00000001"));
}

#[test]
fn deterministic_replay_matches_script_order_and_emits_masked_jsonl() {
    let select = ReplayExchange::new(
        &hex("00A4040007A000000003101000"),
        &hex("6F098407A0000000031010"),
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )
    .unwrap();
    let record = ReplayExchange::new(
        &hex("00B2011400"),
        &hex("700A5A08123456789012345F"),
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )
    .unwrap();
    let mut script = ReplayScript::new(vec![select, record]).unwrap();

    assert!(script.exchange(&hex("00B2011400")).is_err());
    assert_eq!(
        script.exchange(&hex("00A4040007A000000003101000")).unwrap(),
        hex("6F098407A00000000310109000")
    );
    assert_eq!(
        script.exchange(&hex("00B2011400")).unwrap(),
        hex("700A5A08123456789012345F9000")
    );

    let identity = TraceIdentity::current(KRN_ABI_VERSION, 2);
    let jsonl = script
        .masked_jsonl_with_trace_identity(LogPolicy::production(), &identity)
        .unwrap();
    assert!(jsonl.contains("\"type\":\"trace-identity\""));
    assert!(jsonl.contains("\"profile_version\":2"));
    assert!(jsonl.contains("***********2345"));
    assert!(!jsonl.contains("123456789012345"));

    assert!(ReplayExchange::new(
        &hex("0020008008241234FFFFFFFFFF"),
        &[],
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )
    .is_err());
}

#[test]
fn krn_c8_001_002_003_uses_structured_contactless_only_outcomes() {
    let outcome = ContactlessOutcome::new(
        ContactlessOutcomeCode::OnlineRequired,
        StartSignal::Start,
        UiRequest {
            message_id: 0x1234,
            status: UiStatus::Processing,
            hold_time_ms: 500,
        },
        false,
        &hex("9F270180"),
        &hex("DF010102"),
        AlternateInterface::None,
    )
    .unwrap();
    let ffi = outcome.as_ffi();
    assert_eq!(
        ffi.outcome_code,
        ContactlessOutcomeCode::OnlineRequired as u8
    );
    assert_eq!(ffi.data_record_len, 4);
    assert_eq!(ffi.discretionary_data_len, 4);
    assert!(!ffi.data_record.is_null());
    assert!(!ffi.discretionary_data.is_null());

    let invalid = ContactlessOutcome::new(
        ContactlessOutcomeCode::Approved,
        StartSignal::None,
        UiRequest::none(),
        false,
        &[],
        &[],
        AlternateInterface::Contact,
    );
    assert!(invalid.is_err());

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
fn krn_cless_003_limits_are_signed_profile_inputs() {
    let input = ContactlessLimitInput {
        amount_authorised_minor: 4_000,
        contactless_transaction_limit: 5_000,
        contactless_cvm_limit: 3_000,
        floor_limit: 4_500,
        cvm_satisfied: false,
    };
    assert_eq!(
        evaluate_contactless_limits(input),
        ContactlessLimitDecision::CvmRequired
    );
    assert_eq!(
        outcome_from_limit_decision(ContactlessLimitDecision::CvmRequired)
            .unwrap()
            .outcome_code,
        ContactlessOutcomeCode::CvmRequired
    );
    assert_eq!(
        evaluate_contactless_limits(ContactlessLimitInput {
            cvm_satisfied: true,
            ..input
        }),
        ContactlessLimitDecision::Allowed
    );
    assert_eq!(
        evaluate_contactless_limits(ContactlessLimitInput {
            amount_authorised_minor: 4_600,
            cvm_satisfied: true,
            ..input
        }),
        ContactlessLimitDecision::OnlineRequired
    );
    assert_eq!(
        evaluate_contactless_limits(ContactlessLimitInput {
            amount_authorised_minor: 5_001,
            cvm_satisfied: true,
            ..input
        }),
        ContactlessLimitDecision::AlternateInterface
    );
}

#[test]
fn krn_oda_001_005_006_007_selects_method_and_sets_tvr_tsi_without_cda_fallback() {
    assert_eq!(
        select_oda_method(selection_input_from_aip([0x80, 0x00], true, true)),
        OdaSelection::Perform(OdaMethod::Sda)
    );
    assert_eq!(
        select_oda_method(selection_input_from_aip([0xc0, 0x00], true, true)),
        OdaSelection::Perform(OdaMethod::Dda)
    );
    assert_eq!(
        select_oda_method(selection_input_from_aip([0xc0, 0x80], true, true)),
        OdaSelection::Perform(OdaMethod::Cda)
    );

    let selection = select_oda_method(OdaSelectionInput {
        aip_sda_supported: true,
        aip_dda_supported: true,
        aip_cda_supported: true,
        profile_sda_allowed: true,
        profile_dda_allowed: true,
        profile_cda_allowed: true,
        terminal_supports_dynamic_authentication: true,
        oda_required: true,
    });
    assert_eq!(selection, OdaSelection::Perform(OdaMethod::Cda));

    let (tvr, tsi) = apply_oda_outcome(
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
        OdaOutcome::Failed {
            method: OdaMethod::Cda,
            failure: OdaFailure::CdaSignature,
        },
    );
    assert!(tvr.is_set(Tvr::B1_CDA_FAILED));
    assert!(!tvr.is_set(Tvr::B1_DDA_FAILED));
    assert!(tsi.is_set(hyperion_emv::state::Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));

    let (tvr, _) = apply_oda_outcome(
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
        OdaOutcome::Failed {
            method: OdaMethod::Sda,
            failure: OdaFailure::StaticSignature,
        },
    );
    assert!(tvr.is_set(Tvr::B1_SDA_FAILED));

    let (tvr, _) = apply_oda_outcome(
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
        OdaOutcome::Failed {
            method: OdaMethod::Dda,
            failure: OdaFailure::DynamicSignature,
        },
    );
    assert!(tvr.is_set(Tvr::B1_DDA_FAILED));
}

#[test]
fn krn_capk_001_002_lookup_requires_verified_profile_integrity() {
    let policy = ConfigLoadPolicy {
        mode: BuildMode::Certification,
        signature_status: SignatureStatus::Verified,
        installed_version: 1,
        candidate_version: 2,
        evaluation_date: EmvDate {
            year: 26,
            month: 5,
            day: 21,
        },
    };
    let profiles = load_profile_set(SCHEME_PROFILES.as_bytes(), &policy).unwrap();
    let rid = [0xa0, 0x00, 0x00, 0x00, 0x03];

    assert_eq!(
        select_capk(
            &profiles,
            &rid,
            8,
            policy.evaluation_date,
            CapkIntegrity::Unverified,
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
    let capk = select_capk(
        &profiles,
        &rid,
        8,
        policy.evaluation_date,
        CapkIntegrity::Verified,
    )
    .unwrap();
    assert_eq!(capk.rid, rid);
    assert_eq!(capk.key_index, 8);
}

#[test]
fn krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode() {
    assert_eq!(
        validate_oda_vector_annex(ODA_VECTORS.as_bytes(), true).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let complete = br#"{"test_vectors":[{"id":"SDA","capk":{"rid":"A000000003","key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0","exponent_hex":"010001","checksum_hex":"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"},"issuer_certificate_hex":"6F2A9F103A1B2C3D4E5F60718293A4B5C6D7E8F9A0","static_signature_hex":"ABCD1234567890ABCD","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
    validate_oda_vector_annex(complete, true).unwrap();
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
fn krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data() {
    let entries = parse_afl(&hex("10010101")).unwrap();
    let command = read_record_commands(&entries).unwrap().remove(0);
    assert_eq!(command.encode().unwrap(), hex("00B2011400"));

    let mut data = DataStore::new();
    assert_eq!(
        parse_read_record_body(&hex("700A5A08123456789012345F"), &mut data).unwrap(),
        1
    );
    assert_eq!(
        data.get(&hex("5A")),
        Some(hex("123456789012345F").as_slice())
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
fn gac_parsing_uses_card_returned_cryptogram_for_online_handoff() {
    let response = parse_generate_ac_response(&hex(
        "771A9F2701809F360200099F260811121314151617189F1003AABBCC",
    ))
    .unwrap();
    let mut data = DataStore::new();
    data.put(&[0x9f, 0x37], &hex("01020304")).unwrap();
    data.put(&[0x95], &hex("0000000000")).unwrap();
    data.put(&[0x9a], &hex("260521")).unwrap();
    data.put(&[0x9f, 0x02], &hex("000000001000")).unwrap();

    let package = build_online_authorization_package(&response, &data);
    assert!(package
        .objects
        .iter()
        .any(|object| object.tag == [0x9f, 0x26] && object.value == hex("1112131415161718")));
    assert!(package
        .objects
        .iter()
        .any(|object| object.tag == [0x9f, 0x37]));
    assert!(package.objects.iter().any(|object| object.tag == [0x95]));
}

#[test]
fn host_response_extracts_arpc_and_phase_specific_script_results() {
    let host = parse_host_response(&hex(
        "8A02303091081122334455667788710F9F1804DEADBEEF860600DA000001AA7208860680E2000001BB",
    ))
    .unwrap();
    assert_eq!(
        host.issuer_authentication_data,
        Some(hex("1122334455667788"))
    );
    assert_eq!(host.scripts.len(), 2);
    assert_eq!(host.scripts[0].phase, ScriptPhase::BeforeFinalGenerateAc);
    assert_eq!(host.scripts[1].phase, ScriptPhase::AfterFinalGenerateAc);

    let before = apply_script_results(
        ScriptPhase::BeforeFinalGenerateAc,
        &[ScriptCommandResult {
            sw1: 0x6a,
            sw2: 0x80,
        }],
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
    );
    assert_eq!(before.tvr.bytes(), [0x00, 0x00, 0x00, 0x00, 0x20]);
    assert_eq!(before.tsi.bytes(), [0x04, 0x00]);
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
