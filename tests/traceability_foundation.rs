use hyperion_emv::afl::{parse_afl, read_record_commands, record_plan};
use hyperion_emv::apdu::{
    generate_ac, internal_authenticate_from_ddol, select_environment, CdaRequestControl,
    CryptogramRequest, Interface,
};
use hyperion_emv::c8::{
    evaluate_contactless_limits, evaluate_relay_resistance, outcome_from_limit_decision,
    outcome_from_relay_resistance_failure, AlternateInterface, ContactlessLimitDecision,
    ContactlessLimitInput, ContactlessOutcome, ContactlessOutcomeCode, RelayResistanceDecision,
    RelayResistanceFailureOutcome, RelayResistanceProfile, StartSignal, UiRequest, UiStatus,
};
use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::config::{
    load_profile_set, BuildMode, CdaRequestEncoding, ConfigLoadPolicy, ProfileClass,
    SignatureStatus,
};
use hyperion_emv::conformance::baseline_conformance_statement;
use hyperion_emv::cvm::{
    apply_offline_pin_verify_status, evaluate as evaluate_cvm, parse_cvm_list, CvmAction,
    CvmContext, CvmMethod, CvmOutcome, CvmPinHandles, Interface as CvmInterface, PedPinHandle,
};
use hyperion_emv::dol::{build_dol_with_policy, parse_dol, DataStore, DolPaddingPolicy};
use hyperion_emv::ffi::{
    krn_apply_host_response, krn_build_generate_ac, krn_build_internal_authenticate,
    krn_build_select_environment, krn_context_free, krn_context_new, krn_error_code_at,
    krn_error_description, krn_error_name, krn_error_table_len, krn_get_conformance_statement_json,
    krn_get_final_outcome, krn_get_fsm_state, krn_get_issuer_script_result,
    krn_get_issuer_script_result_count, krn_get_last_error, krn_get_online_authorization_data,
    krn_get_profile_version, krn_init, krn_load_profiles_verified, krn_mask_apdu_command_json,
    krn_mask_apdu_response_json, krn_process_final_generate_ac, krn_process_issuer_authentication,
    krn_process_issuer_scripts, krn_process_post_final_issuer_scripts, krn_reset,
    krn_run_transaction, krn_set_cvm_capabilities, krn_set_nonvolatile_offline_counter,
    krn_set_offline_pin_handle, krn_set_terminal_capabilities,
    krn_set_terminal_transaction_qualifiers, krn_set_transaction_params, KrnConfigBlob, KrnOutcome,
    KrnRuntime, KrnTxnParams, KRN_ABI_VERSION, KRN_PIN_METHOD_OFFLINE_ENCIPHERED,
    KRN_PIN_METHOD_OFFLINE_PLAINTEXT,
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
    apply_oda_outcome, build_static_authentication_data, capk_checksum, capk_checksum_is_valid,
    parse_internal_authenticate_response, parse_recovered_public_key_certificate,
    recover_and_verify_public_key_certificate, recover_and_verify_signed_application_data,
    recover_rsa_public_block, recovered_public_key_certificate_hash_input,
    recovered_public_key_certificate_hash_is_valid,
    recovered_signed_application_data_hash_is_valid, select_capk, select_oda_method,
    selection_input_from_aip, validate_icc_public_key_inputs, validate_issuer_public_key_inputs,
    validate_oda_vector_annex, verify_static_data_authentication, CapkIntegrity, OdaFailure,
    OdaMethod, OdaOutcome, OdaSelection, OdaSelectionInput, RecoveredCertificateKind,
    RecoveredPublicKeyCertificate, RecoveredSignedDataKind, StaticAuthenticationRecord,
};
use hyperion_emv::perf::{parse_performance_profile, PerfAccumulator, PerfStage};
use hyperion_emv::provenance::{build_provenance_manifest, sha256, to_hex, Artifact};
use hyperion_emv::quality::prelab_quality_gates_json;
use hyperion_emv::record::parse_read_record_body;
use hyperion_emv::restrictions::{
    evaluate as evaluate_restrictions, ApplicationUsageControl, EmvDate, RestrictionInput,
    ServiceType, TransactionRegion,
};
use hyperion_emv::selection::{match_profile_candidates, parse_fci_candidate_aids};
use hyperion_emv::state::{Tsi, Tvr};
use hyperion_emv::sw::{classify, ApduContext, StatusAction, StatusWord};
use hyperion_emv::taa::{decide, ActionCodes, TaaInput, TaaProfile, TerminalAction};
use hyperion_emv::tlv;
use hyperion_emv::trace::{
    mask_apdu_response, mask_tlv_value, ApduTraceContext, LogPolicy, MaskedValue, ReplayExchange,
    ReplayScript, TraceIdentity,
};
use hyperion_emv::trm::{evaluate as evaluate_trm, OfflineCounter, TrmInput, TrmProfile};
use std::collections::BTreeSet;
use std::ffi::c_void;
use std::fs;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

const LEGACY_RTM: &str = include_str!("../docs/requirements-traceability-matrix.csv");
const CURRENT_RTM: &str = include_str!("../docs/requirements_traceability.csv");
const RTM: &str = concat!(
    include_str!("../docs/requirements-traceability-matrix.csv"),
    include_str!("../docs/requirements_traceability.csv")
);
const ABI_CONFORMANCE_STATEMENT: &str = include_str!("../docs/abi_conformance_statement.json");
const SCHEME_PROFILES: &str = include_str!("../docs/scheme_profiles.cert.json");
const TLV_CATALOGUE: &str = include_str!("../docs/tlv_catalogue.csv");
const CORRECTED_SPEC: &str = include_str!("../docs/hyperion_emv_l2_kernel_spec_v3_1_corrected.md");
const ODA_VECTORS: &str = include_str!("../docs/oda_test_vectors.json");
const STATE_MACHINE_CSV: &str = include_str!("../docs/state_machine.csv");
const BITMAP_CATALOGUE: &str = include_str!("../docs/bitmap_catalogue.csv");
const PERFORMANCE_PROFILE: &str = include_str!("../docs/performance_profile.csv");
const LAB_SUBMISSION_MANIFEST: &str = include_str!("../docs/lab_submission_manifest.md");
const CERTIFICATION_OPEN_ISSUES: &str = include_str!("../docs/certification_open_issues.md");
const STANDARDS_WATCH: &str = include_str!("../docs/standards_watch.md");
const PRELAB_APDU_TRACE_PACK: &str = include_str!("../docs/prelab_apdu_trace_pack.jsonl");
const PRELAB_QUALITY_GATES: &str = include_str!("../docs/prelab_quality_gates.json");

static IT_TRANSMITTED_INS: AtomicU8 = AtomicU8::new(0);
static IT_TRANSMITTED_LEN: AtomicUsize = AtomicUsize::new(0);
static IT_TRANSMIT_COUNT: AtomicUsize = AtomicUsize::new(0);
static IT_TRANSMIT_TIMEOUT_MS: AtomicI32 = AtomicI32::new(0);
static IT_RNG_CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

fn krn_ids_from_csv(csv: &str) -> BTreeSet<&str> {
    csv.lines()
        .skip(1)
        .filter_map(|line| line.split_once(',').map(|(id, _)| id))
        .filter(|id| id.starts_with("KRN-"))
        .collect()
}

fn krn_ids_from_spec(spec: &str) -> BTreeSet<&str> {
    spec.lines()
        .filter_map(|line| line.split_once(',').map(|(id, _)| id))
        .filter(|id| id.starts_with("KRN-"))
        .collect()
}

fn krn_ids_from_markdown(markdown: &str) -> BTreeSet<String> {
    markdown
        .split(|ch: char| !(ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '-'))
        .filter(|token| {
            let mut parts = token.split('-');
            matches!(parts.next(), Some("KRN"))
                && parts.next().is_some_and(|part| !part.is_empty())
                && parts.next().is_some_and(|part| {
                    part.len() == 3 && part.chars().all(|ch| ch.is_ascii_digit())
                })
                && parts.next().is_none()
        })
        .map(str::to_string)
        .collect()
}

fn csv_row_for_requirement<'a>(csv: &'a str, id: &str) -> Option<&'a str> {
    csv.lines().find(|line| {
        line.strip_prefix(id)
            .is_some_and(|rest| rest.starts_with(','))
    })
}

fn certification_policy() -> ConfigLoadPolicy {
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

struct CvmMethodScript {
    counter: AtomicUsize,
    cvm_code: u8,
}

struct TerminalCapabilitiesScript {
    counter: AtomicUsize,
    commands: Mutex<Vec<Vec<u8>>>,
}

unsafe extern "C" fn it_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let count = if user_data.is_null() {
        let count = IT_TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        IT_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        IT_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        count
    } else {
        let script = &*(user_data as *const TerminalCapabilitiesScript);
        let count = script.counter.fetch_add(1, Ordering::SeqCst);
        script.commands.lock().unwrap().push(command.to_vec());
        IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        count
    };
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

unsafe extern "C" fn it_offline_pin_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let counter = &*(user_data as *const AtomicUsize);
    let count = counter.fetch_add(1, Ordering::SeqCst);
    IT_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
    IT_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    write_offline_pin_response(command, count, resp, resp_len)
}

unsafe extern "C" fn it_cvm_method_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let script = &*(user_data as *const CvmMethodScript);
    let count = script.counter.fetch_add(1, Ordering::SeqCst);
    IT_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
    IT_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    write_cvm_method_response(command, count, script.cvm_code, resp, resp_len)
}

unsafe extern "C" fn it_terminal_capabilities_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let script = &*(user_data as *const TerminalCapabilitiesScript);
    let count = script.counter.fetch_add(1, Ordering::SeqCst);
    script.commands.lock().unwrap().push(command.to_vec());
    IT_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
    IT_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    write_terminal_capabilities_response(command, count, resp, resp_len)
}

unsafe extern "C" fn it_terminal_qualifiers_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    let command = std::slice::from_raw_parts(cmd, cmd_len);
    let script = &*(user_data as *const TerminalCapabilitiesScript);
    let count = script.counter.fetch_add(1, Ordering::SeqCst);
    script.commands.lock().unwrap().push(command.to_vec());
    IT_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
    IT_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    write_terminal_qualifiers_response(command, count, resp, resp_len)
}

unsafe extern "C" fn it_host_timeout_transmit_apdu(
    _cmd: *const u8,
    _cmd_len: usize,
    _resp: *mut u8,
    _resp_len: *mut usize,
    timeout_ms: i32,
    _user_data: *mut c_void,
) -> i32 {
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    hyperion_emv::KernelError::HostTimeout.code()
}

unsafe extern "C" fn it_unknown_error_transmit_apdu(
    _cmd: *const u8,
    _cmd_len: usize,
    _resp: *mut u8,
    _resp_len: *mut usize,
    timeout_ms: i32,
    _user_data: *mut c_void,
) -> i32 {
    IT_TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    12_345
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

unsafe fn write_offline_pin_response(
    command: &[u8],
    count: usize,
    resp: *mut u8,
    resp_len: *mut usize,
) -> i32 {
    let response = match count {
        3 => hex(
            "70675A08123456789012345F5F24033012315F25032501015F280208409F0702FF809F090200018E0A000000000000000001009F0D0500000000009F0E0500000000009F0F0500000080008C129F02069F370495059A039C019F1A029F34038D088A02910895059B029000",
        ),
        _ => return write_scripted_response(command, count, resp, resp_len),
    };
    let capacity = *resp_len;
    *resp_len = response.len();
    if capacity < response.len() {
        return hyperion_emv::KernelError::BufferTooSmall.code();
    }
    ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
    hyperion_emv::KernelError::Ok.code()
}

unsafe fn write_cvm_method_response(
    command: &[u8],
    count: usize,
    cvm_code: u8,
    resp: *mut u8,
    resp_len: *mut usize,
) -> i32 {
    let response = match (count, cvm_code) {
        (3, 0x02) => hex(
            "70675A08123456789012345F5F24033012315F25032501015F280208409F0702FF809F090200018E0A000000000000000002009F0D0500000000009F0E0500000000009F0F0500000080008C129F02069F370495059A039C019F1A029F34038D088A02910895059B029000",
        ),
        (3, 0x06) => hex(
            "70675A08123456789012345F5F24033012315F25032501015F280208409F0702FF809F090200018E0A000000000000000006009F0D0500000000009F0E0500000000009F0F0500000080008C129F02069F370495059A039C019F1A029F34038D088A02910895059B029000",
        ),
        (3, 0x20) => hex(
            "70675A08123456789012345F5F24033012315F25032501015F280208409F0702FF809F090200018E0A000000000000000020009F0D0500000000009F0E0500000000009F0F0500000080008C129F02069F370495059A039C019F1A029F34038D088A02910895059B029000",
        ),
        _ => return write_scripted_response(command, count, resp, resp_len),
    };
    let capacity = *resp_len;
    *resp_len = response.len();
    if capacity < response.len() {
        return hyperion_emv::KernelError::BufferTooSmall.code();
    }
    ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
    hyperion_emv::KernelError::Ok.code()
}

unsafe fn write_terminal_capabilities_response(
    command: &[u8],
    count: usize,
    resp: *mut u8,
    resp_len: *mut usize,
) -> i32 {
    let response = match count {
        1 => hex("6F148407A0000000031010A5099F38069F33039F37049000"),
        _ => return write_scripted_response(command, count, resp, resp_len),
    };
    let capacity = *resp_len;
    *resp_len = response.len();
    if capacity < response.len() {
        return hyperion_emv::KernelError::BufferTooSmall.code();
    }
    ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
    hyperion_emv::KernelError::Ok.code()
}

unsafe fn write_terminal_qualifiers_response(
    command: &[u8],
    count: usize,
    resp: *mut u8,
    resp_len: *mut usize,
) -> i32 {
    let response = match count {
        1 => hex("6F148407A0000000031010A5099F38069F66049F37049000"),
        _ => return write_scripted_response(command, count, resp, resp_len),
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

unsafe extern "C" fn it_counted_unpredictable_number(
    out: *mut u8,
    out_len: usize,
    user_data: *mut c_void,
) -> i32 {
    IT_RNG_CALLBACK_COUNT.fetch_add(1, Ordering::SeqCst);
    it_unpredictable_number(out, out_len, user_data)
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
        "KRN-REF-001",
        "KRN-SEL-001",
        "KRN-TVR-001",
        "KRN-TVR-002",
        "KRN-TVR-003",
        "KRN-TSI-001",
        "KRN-TERMCAP-001",
        "KRN-TTQ-001",
        "KRN-CID-001",
        "KRN-CVM-001",
        "KRN-CVM-002",
        "KRN-CVM-003",
        "KRN-CVMCAP-001",
        "KRN-CVMRES-001",
        "KRN-SEC-001",
        "KRN-SEC-002",
        "KRN-SEC-003",
        "KRN-PIN-001",
        "KRN-PIN-002",
        "KRN-PIN-003",
        "KRN-GAC-008",
        "KRN-GAC-009",
        "KRN-GAC-010",
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
        "KRN-API-005",
        "KRN-API-006",
        "KRN-API-007",
        "KRN-PINAPI-001",
        "KRN-PINAPI-002",
        "KRN-LOG-001",
        "KRN-C8-001",
        "KRN-C8-002",
        "KRN-C8-003",
        "KRN-CFG-004",
        "KRN-ODA-001",
        "KRN-ODA-002",
        "KRN-ODA-003",
        "KRN-ODA-004",
        "KRN-ODA-005",
        "KRN-ODA-006",
        "KRN-ODA-007",
        "KRN-ODA-008",
        "KRN-DDA-001",
        "KRN-DDA-002",
        "KRN-ODATV-001",
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
        "KRN-DPL-001",
        "KRN-DPL-002",
        "KRN-DPL-003",
        "KRN-DPL-004",
        "KRN-RNG-001",
        "KRN-RNG-002",
        "KRN-ERR-001",
        "KRN-ERR-002",
        "KRN-CERT-004",
    ] {
        assert!(
            RTM.contains(krn_id),
            "missing traceability row for {krn_id}"
        );
    }
}

#[test]
fn krn_sec_001_002_sources_exclude_issuer_key_custody_and_cryptogram_generation() {
    let forbidden_terms = [
        "issuer master key",
        "issuer_master",
        "master_key",
        "issuer_secret",
        "issuer_private",
        "arqc_key",
        "arpc_key",
        "mkac",
        "udk",
        "session_key",
        "cryptogram_key",
        "generate_arqc",
        "generate_tc",
        "generate_aac",
        "compute_arqc",
        "compute_tc",
        "compute_aac",
    ];

    let mut scanned = 0usize;
    for entry in fs::read_dir(Path::new("src")).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        scanned += 1;
        let source = fs::read_to_string(&path).unwrap().to_ascii_lowercase();
        for term in forbidden_terms {
            assert!(
                !source.contains(term),
                "{} contains forbidden issuer-key or cryptogram-generation custody term `{}`",
                path.display(),
                term
            );
        }
    }
    assert!(
        scanned >= 20,
        "source custody scan covered only {scanned} files"
    );
}

#[test]
fn rtm_promotes_security_trust_boundary_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-SEC-001", "KRN-SEC-002", "KRN-SEC-003", "KRN-SEC-004"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("Code review")
                    && !row.contains("APDU logs")
                    && !row.contains("PED statement")
                    && !row.contains("Architecture review"),
                "{id} should cite executable trust-boundary evidence"
            );
            assert!(
                row.contains("rtm_promotes_security_trust_boundary_evidence"),
                "{id} should cite this RTM guard"
            );
        }

        let issuer_key = csv_row_for_requirement(csv, "KRN-SEC-001").unwrap();
        assert!(issuer_key.contains(
            "krn_sec_001_002_sources_exclude_issuer_key_custody_and_cryptogram_generation"
        ));

        let card_cryptograms = csv_row_for_requirement(csv, "KRN-SEC-002").unwrap();
        assert!(card_cryptograms
            .contains("builds_online_authorization_package_without_generating_cryptograms"));
        assert!(card_cryptograms
            .contains("gac_parsing_uses_card_returned_cryptogram_for_online_handoff"));
        assert!(card_cryptograms.contains(
            "krn_sec_001_002_sources_exclude_issuer_key_custody_and_cryptogram_generation"
        ));

        let capk_integrity = csv_row_for_requirement(csv, "KRN-SEC-003").unwrap();
        assert!(capk_integrity
            .contains("rejects_certification_capk_checksum_mismatch_or_metadata_drift"));
        assert!(capk_integrity
            .contains("krn_sec_003_oda_001_cert_profile_loader_rejects_capk_checksum_drift"));
        assert!(
            capk_integrity.contains("krn_sec_003_oda_002_capks_retain_signed_public_provenance")
        );

        let ped_boundary = csv_row_for_requirement(csv, "KRN-SEC-004").unwrap();
        assert!(ped_boundary.contains("offline_pin_requires_ped_owned_opaque_handle"));
        assert!(ped_boundary.contains("offline_pin_debug_redacts_ped_handle_values"));
        assert!(ped_boundary
            .contains("krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles"));
    }
}

#[test]
fn rtm_annexes_cover_the_same_requirement_ids_independently() {
    let current_ids = krn_ids_from_csv(CURRENT_RTM);
    let legacy_ids = krn_ids_from_csv(LEGACY_RTM);
    assert_eq!(
        legacy_ids, current_ids,
        "RTM annexes must independently cover the same KRN requirement set"
    );

    let spec_ids = krn_ids_from_spec(include_str!("../docs/spec.md"));
    for krn_id in spec_ids {
        assert!(
            current_ids.contains(krn_id),
            "current RTM missing spec requirement {krn_id}"
        );
        assert!(
            legacy_ids.contains(krn_id),
            "legacy RTM missing spec requirement {krn_id}"
        );
    }
}

#[test]
fn spec_delegates_requirement_traceability_to_csv_annexes() {
    let spec = include_str!("../docs/spec.md");
    assert!(spec.contains("The executable RTM is `docs/requirements_traceability.csv`"));
    assert!(spec.contains("compatibility copy is `docs/requirements-traceability-matrix.csv`"));
    assert!(spec.contains("SHALL NOT carry a duplicated inline RTM row set"));
    assert!(
        krn_ids_from_spec(spec).is_empty(),
        "spec.md must not carry stale inline RTM rows"
    );

    let current_ids = krn_ids_from_csv(CURRENT_RTM);
    assert!(
        current_ids.contains("KRN-GAC2-004"),
        "canonical RTM missing final GAC requirement"
    );
    assert!(
        current_ids.contains("KRN-SCR-006"),
        "canonical RTM missing issuer script result reporting requirement"
    );
}

#[test]
fn corrected_spec_requirement_ids_are_all_in_rtm_annexes() {
    let corrected_ids = krn_ids_from_markdown(CORRECTED_SPEC);
    let current_ids = krn_ids_from_csv(CURRENT_RTM)
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let legacy_ids = krn_ids_from_csv(LEGACY_RTM)
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();

    let missing_current = corrected_ids
        .difference(&current_ids)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_current.is_empty(),
        "current RTM missing corrected-spec KRN IDs: {missing_current:?}"
    );

    let missing_legacy = corrected_ids
        .difference(&legacy_ids)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_legacy.is_empty(),
        "legacy RTM missing corrected-spec KRN IDs: {missing_legacy:?}"
    );

    assert!(
        !CURRENT_RTM.contains("pending implementation evidence"),
        "RTM rows should cite concrete executable evidence or explicit external certification gates"
    );
    assert!(
        include_str!("../docs/spec.md").contains("engineering baseline pending licensed review")
    );
}

#[test]
fn rtm_external_lab_gates_are_explicit() {
    for (name, csv) in [
        ("requirements_traceability.csv", CURRENT_RTM),
        ("requirements-traceability-matrix.csv", LEGACY_RTM),
    ] {
        let pending = csv
            .lines()
            .skip(1)
            .filter(|line| line.contains("pending implementation evidence"))
            .map(|line| line.split_once(',').unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(
            pending,
            Vec::<&str>::new(),
            "{name} has unexpected pending evidence rows"
        );

        let vectors = csv_row_for_requirement(csv, "KRN-ANNEX-005").unwrap();
        assert!(vectors.contains("complete cryptographic vectors"));
        assert!(!vectors.contains("pending implementation evidence"));
        assert!(vectors.contains("validates_complete_vector_syntax_and_rejects_placeholders"));
        assert!(vectors.contains("certification_vector_coverage_is_method_specific"));
        assert!(
            vectors.contains("krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode")
        );
        assert!(vectors.contains("lab-supplied SDA/DDA/CDA vectors required"));

        let approval = csv_row_for_requirement(csv, "KRN-CERT-001").unwrap();
        assert!(approval.contains("EMV Level 2 approval"));
        assert!(!approval.contains("pending implementation evidence"));
        assert!(approval.contains("conformance_statement_json_is_deterministic_and_scoped"));
        assert!(approval.contains("krn_ref_001_conformance_statement_declares_normative_hierarchy"));
        assert!(approval.contains("external EMV Level 2 approval and signed LoA required"));
    }

    assert!(LAB_SUBMISSION_MANIFEST.contains("lab-supplied SDA/DDA/CDA vectors"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("Conformance statement (signed EMVCo/lab template)"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("APDU trace logs (masked) for all test cases"));
    assert!(include_str!("../docs/spec.md").contains("approval artifacts"));
}

#[test]
fn rtm_promotes_runtime_apdu_selection_status_policy_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-SEL-001", "KRN-SEL-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete PSE/PPSE evidence"
            );
            assert!(row.contains("builds_exact_contact_pse_and_contactless_ppse_selects"));
            assert!(row.contains("extracts_candidate_aids_from_directory_fci"));
            assert!(row.contains("rejects_duplicate_adf_names_in_directory_entries"));
            assert!(row.contains("rejects_duplicate_adf_names_across_directory_entries"));
            assert!(row.contains("rejects_candidate_aid_lists_above_limit"));
            assert!(row.contains("krn_sel_001_exact_pse_ppse_apdus_are_stable"));
            assert!(
                row.contains("krn_sel_001_002_003_parses_candidates_and_matches_signed_profiles")
            );
            assert!(row.contains("ffi_builds_select_into_caller_buffer"));
        }

        for id in ["KRN-APDU-002", "KRN-APDU-003", "KRN-SEL-003"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete runtime evidence"
            );
            assert!(
                row.contains(
                    "runtime_selection_uses_status_policy_for_get_response_and_invalidated_aids"
                ),
                "{id} should cite runtime SELECT status-policy coverage"
            );
        }
    }
}

#[test]
fn rtm_promotes_apdu_command_construction_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-APDU-001").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-APDU-001 should cite concrete APDU construction evidence"
        );
        assert!(row.contains("encodes_kernel_command_apdu_matrix"));
        assert!(row.contains("builds_exact_contact_pse_and_contactless_ppse_selects"));
        assert!(row.contains("validates_read_record_sfi"));
        assert!(row.contains("rtm_promotes_apdu_command_construction_evidence"));
    }
}

#[test]
fn rtm_promotes_gpo_and_read_record_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let gpo_valid = csv_row_for_requirement(csv, "KRN-GPO-001").expect("RTM row exists");
        assert!(
            !gpo_valid.contains("GPO response parser evidence"),
            "KRN-GPO-001 should cite executable GPO parser evidence"
        );
        assert!(gpo_valid.contains("extracts_pdol_from_selected_application_fci"));
        assert!(gpo_valid.contains("rejects_duplicate_pdol_objects_in_selected_fci"));
        assert!(gpo_valid.contains("parses_gpo_template_77_with_aip_and_afl"));
        assert!(gpo_valid.contains("parses_gpo_template_80_without_afl"));
        assert!(gpo_valid.contains("rejects_nested_or_duplicate_gpo_response_data"));
        assert!(gpo_valid.contains("krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates"));
        assert!(gpo_valid.contains("rtm_promotes_gpo_and_read_record_evidence"));

        let gpo_missing = csv_row_for_requirement(csv, "KRN-GPO-002").expect("RTM row exists");
        assert!(
            !gpo_missing.contains("GPO state transition evidence"),
            "KRN-GPO-002 should cite executable missing-mandatory GPO evidence"
        );
        assert!(gpo_missing.contains("extracts_pdol_from_selected_application_fci"));
        assert!(gpo_missing.contains("rejects_duplicate_pdol_objects_in_selected_fci"));
        assert!(gpo_missing.contains("rejects_gpo_without_mandatory_aip_afl"));
        assert!(gpo_missing.contains("rejects_nested_or_duplicate_gpo_response_data"));
        assert!(gpo_missing.contains("krn_gpo_001_002_extracts_pdol_and_parses_aip_afl_templates"));
        assert!(gpo_missing.contains("rtm_promotes_gpo_and_read_record_evidence"));

        let sfi = csv_row_for_requirement(csv, "KRN-RR-001").expect("RTM row exists");
        assert!(
            !sfi.contains("READ RECORD APDU evidence"),
            "KRN-RR-001 should cite executable SFI and AFL validation evidence"
        );
        assert!(sfi.contains("validates_read_record_sfi"));
        assert!(sfi.contains("rejects_malformed_afl_entries"));
        assert!(sfi.contains("rejects_afl_sfi_bytes_with_nonzero_low_bits"));
        assert!(sfi.contains("rejects_afl_lists_above_entry_limit"));
        assert!(sfi.contains("rejects_record_plans_above_locator_limit"));
        assert!(sfi.contains("rejects_duplicate_afl_record_locators"));
        assert!(sfi.contains("krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data"));
        assert!(sfi.contains("rtm_promotes_gpo_and_read_record_evidence"));

        let p2 = csv_row_for_requirement(csv, "KRN-RR-002").expect("RTM row exists");
        assert!(
            !p2.contains("READ RECORD APDU evidence"),
            "KRN-RR-002 should cite executable READ RECORD encoding evidence"
        );
        assert!(p2.contains("validates_read_record_sfi"));
        assert!(p2.contains("builds_read_record_commands_from_afl_order"));
        assert!(p2.contains("rejects_duplicate_afl_record_locators"));
        assert!(p2.contains("krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data"));
        assert!(p2.contains("rtm_promotes_gpo_and_read_record_evidence"));

        let record = csv_row_for_requirement(csv, "KRN-RR-003").expect("RTM row exists");
        assert!(
            !record.contains("Record parser and masked logging evidence"),
            "KRN-RR-003 should cite executable record parsing and masking evidence"
        );
        assert!(record.contains("parses_record_template_into_card_data_store"));
        assert!(record.contains("rejects_empty_or_malformed_record_templates"));
        assert!(record.contains("rejects_unwrapped_or_extra_record_data"));
        assert!(record.contains("rejects_duplicate_record_data_without_partial_store"));
        assert!(record.contains("rejects_nested_record_data_without_partial_store"));
        assert!(record.contains("apdu_trace_debug_redacts_masked_payloads_for_crash_safety"));
        assert!(
            record.contains("krn_rr_001_002_003_reads_records_in_afl_order_and_stores_card_data")
        );
        assert!(record.contains("rtm_promotes_gpo_and_read_record_evidence"));
    }
}

#[test]
fn rtm_promotes_apdu_status_word_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let state_specific = csv_row_for_requirement(csv, "KRN-APDU-009").expect("RTM row exists");
        assert!(
            !state_specific.contains("APDU + state")
                && !state_specific.contains("APDU logs + state trace"),
            "KRN-APDU-009 should cite concrete status-word classifier evidence"
        );
        assert!(state_specific.contains("select_status_words_are_state_specific"));
        assert!(state_specific.contains("same_non_9000_status_words_are_context_specific"));
        assert!(state_specific.contains("krn_apdu_009_010_status_handling_is_context_specific"));
        assert!(state_specific.contains("rtm_promotes_apdu_status_word_evidence"));

        let non_generic = csv_row_for_requirement(csv, "KRN-APDU-010").expect("RTM row exists");
        assert!(
            !non_generic.contains("Error injection"),
            "KRN-APDU-010 should cite concrete non-9000 status-word evidence"
        );
        assert!(
            non_generic.contains("handles_success_and_transport_followups_before_context_rules")
        );
        assert!(non_generic
            .contains("read_record_status_words_continue_or_end_without_generic_failure"));
        assert!(non_generic.contains("verify_and_script_status_words_keep_their_own_meaning"));
        assert!(non_generic.contains("same_non_9000_status_words_are_context_specific"));
        assert!(non_generic.contains("krn_apdu_009_010_status_handling_is_context_specific"));
        assert!(non_generic.contains("rtm_promotes_apdu_status_word_evidence"));
    }
}

#[test]
fn rtm_promotes_rng_callback_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let callback = csv_row_for_requirement(csv, "KRN-RNG-001").expect("RTM row exists");
        assert!(
            !callback.contains("RNG callback trace"),
            "KRN-RNG-001 should cite executable RNG callback evidence"
        );
        assert!(
            callback.contains("krn_rng_001_002_rejects_zero_and_repeated_unpredictable_numbers")
        );
        assert!(callback.contains("rtm_promotes_rng_callback_evidence"));

        let rejection = csv_row_for_requirement(csv, "KRN-RNG-002").expect("RTM row exists");
        assert!(
            !rejection.contains("RNG failure injection"),
            "KRN-RNG-002 should cite executable weak-output rejection evidence"
        );
        assert!(
            rejection.contains("krn_rng_001_002_rejects_zero_and_repeated_unpredictable_numbers")
        );
        assert!(rejection.contains("krn_err_001_exposes_stable_abi_error_table"));
        assert!(rejection.contains("rtm_promotes_rng_callback_evidence"));
    }
}

#[test]
fn rtm_annexes_are_six_column_csv() {
    fn column_count(line: &str) -> Option<usize> {
        let mut columns = 1;
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '"' if in_quotes && chars.peek() == Some(&'"') => {
                    chars.next();
                }
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => columns += 1,
                _ => {}
            }
        }
        (!in_quotes).then_some(columns)
    }

    for (name, csv) in [
        ("requirements_traceability.csv", CURRENT_RTM),
        ("requirements-traceability-matrix.csv", LEGACY_RTM),
    ] {
        for (index, line) in csv.lines().enumerate() {
            assert_eq!(
                column_count(line),
                Some(6),
                "{name}:{} is not six-column CSV",
                index + 1
            );
        }
    }
}

#[test]
fn rtm_promotes_state_machine_annex_validation_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-ANNEX-001", "KRN-ANNEX-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete state-machine annex validation evidence"
            );
            assert!(row.contains("validates_machine_readable_state_annex"));
            assert!(row.contains("rejects_state_machine_annex_schema_and_semantic_drift"));
            assert!(row.contains("rtm_promotes_state_machine_annex_validation_evidence"));
        }
    }
}

#[test]
fn rtm_promotes_bitmap_catalogue_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-BIT-001").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-BIT-001 should cite concrete bitmap catalogue evidence"
        );
        assert!(row.contains("bitmap_catalogue_defines_tvr_tsi_symbols_and_rfu_masks"));
        assert!(row.contains("implementation_uses_symbolic_bitmap_setters"));
        assert!(row.contains("rtm_promotes_bitmap_catalogue_evidence"));
    }
}

#[test]
fn rtm_promotes_tvr_and_cvm_table_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let tvr = csv_row_for_requirement(csv, "KRN-TVR-001").expect("RTM row exists");
        assert!(
            !tvr.contains("Code review"),
            "KRN-TVR-001 should cite executable bitmap evidence"
        );
        assert!(tvr.contains("state::tests::uses_symbolic_tvr_bits"));
        assert!(tvr.contains("bitmap_catalogue_defines_tvr_tsi_symbols_and_rfu_masks"));
        assert!(tvr.contains("implementation_uses_symbolic_bitmap_setters"));
        assert!(tvr.contains("rtm_promotes_tvr_and_cvm_table_evidence"));

        let cvm = csv_row_for_requirement(csv, "KRN-CVM-003").expect("RTM row exists");
        assert!(
            !cvm.contains("Code review"),
            "KRN-CVM-003 should cite executable CVM table evidence"
        );
        assert!(cvm.contains("maps_certified_cvm_method_code_table_and_masks_continue_bit"));
        assert!(cvm.contains("parses_cvm_list_amounts_and_certified_method_codes"));
        assert!(cvm.contains("krn_cvm_001_002_003_and_sec_004_use_cvm_table_without_clear_pin"));
        assert!(cvm.contains("contactless_cdcvm_is_not_hardcoded_to_cvm_code_0x05"));
        assert!(cvm.contains("rtm_promotes_tvr_and_cvm_table_evidence"));
    }
}

#[test]
fn rtm_promotes_tvr_clearing_and_tsi_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let cleared = csv_row_for_requirement(csv, "KRN-TVR-002").expect("RTM row exists");
        assert!(
            !cleared.contains("Unit test log"),
            "KRN-TVR-002 should cite executable TVR clearing evidence"
        );
        assert!(cleared.contains("tvr_starts_cleared_for_each_transaction"));
        assert!(cleared.contains("krn_tvr_001_002_tvr_is_symbolic_and_cleared"));
        assert!(cleared.contains("rtm_promotes_tvr_clearing_and_tsi_evidence"));

        let rfu = csv_row_for_requirement(csv, "KRN-TVR-003").expect("RTM row exists");
        assert!(
            !rfu.contains("TVR trace"),
            "KRN-TVR-003 should cite executable RFU masking evidence"
        );
        assert!(rfu.contains("tvr_and_tsi_mutation_masks_rfu_bits"));
        assert!(rfu.contains("krn_tvr_003_tsi_001_state_bits_are_defined_and_rfu_safe"));
        assert!(rfu.contains("rtm_promotes_tvr_clearing_and_tsi_evidence"));

        let tsi = csv_row_for_requirement(csv, "KRN-TSI-001").expect("RTM row exists");
        assert!(
            !tsi.contains("TSI trace"),
            "KRN-TSI-001 should cite executable TSI bit evidence"
        );
        assert!(tsi.contains("tvr_and_tsi_mutation_masks_rfu_bits"));
        assert!(tsi.contains("krn_tvr_003_tsi_001_state_bits_are_defined_and_rfu_safe"));
        assert!(tsi.contains("tsi_bits_are_set_only_after_corresponding_processing"));
        assert!(tsi.contains("rtm_promotes_tvr_clearing_and_tsi_evidence"));
    }
}

#[test]
fn rtm_promotes_cvm_outcome_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let parsing = csv_row_for_requirement(csv, "KRN-CVM-001").expect("RTM row exists");
        assert!(
            !parsing.contains("CVM trace"),
            "KRN-CVM-001 should cite parser and evaluator regressions"
        );
        assert!(parsing.contains("parses_cvm_list_amounts_and_certified_method_codes"));
        assert!(parsing.contains("rejects_cvm_lists_above_rule_limit"));
        assert!(parsing.contains("amount_conditions_are_enforced"));
        assert!(parsing.contains("continue_on_failure_skips_to_next_matching_cvm_rule"));
        assert!(parsing.contains("krn_cvm_001_002_003_and_sec_004_use_cvm_table_without_clear_pin"));
        assert!(parsing.contains("rtm_promotes_cvm_outcome_evidence"));

        let outcome = csv_row_for_requirement(csv, "KRN-CVM-002").expect("RTM row exists");
        assert!(
            !outcome.contains("TVR after CVM"),
            "KRN-CVM-002 should cite executable CVM result and TVR regressions"
        );
        assert!(outcome.contains("offline_pin_requires_ped_owned_opaque_handle"));
        assert!(outcome.contains("offline_pin_verify_status_updates_cvm_results_and_tvr_bits"));
        assert!(outcome.contains("krn_cvm_001_002_003_and_sec_004_use_cvm_table_without_clear_pin"));
        assert!(outcome.contains("rtm_promotes_cvm_outcome_evidence"));
    }
}

#[test]
fn rtm_promotes_cvm_pin_capability_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let capabilities = csv_row_for_requirement(csv, "KRN-CVMCAP-001").expect("RTM row exists");
        assert!(
            !capabilities.contains("CVM capability ABI test"),
            "KRN-CVMCAP-001 should cite executable CVM capability evidence"
        );
        assert!(capabilities.contains("krn_cvmcap_001_uses_terminal_cvm_capabilities_from_abi"));
        assert!(capabilities.contains("continue_on_failure_skips_to_next_matching_cvm_rule"));
        assert!(capabilities.contains("rtm_promotes_cvm_pin_capability_evidence"));

        let cvm_results = csv_row_for_requirement(csv, "KRN-CVMRES-001").expect("RTM row exists");
        assert!(
            !cvm_results.contains("9F34 transaction data"),
            "KRN-CVMRES-001 should cite executable CVM Results evidence"
        );
        assert!(cvm_results
            .contains("krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles"));
        assert!(cvm_results.contains("offline_pin_verify_status_updates_cvm_results_and_tvr_bits"));
        assert!(
            cvm_results.contains("krn_pin_004_verify_63cx_updates_try_counter_tvr_and_cvm_results")
        );
        assert!(cvm_results.contains("rtm_promotes_cvm_pin_capability_evidence"));

        let methods = csv_row_for_requirement(csv, "KRN-PIN-001").expect("RTM row exists");
        assert!(
            !methods.contains("CVM method evidence"),
            "KRN-PIN-001 should cite executable PIN method evidence"
        );
        assert!(methods.contains("maps_certified_cvm_method_code_table_and_masks_continue_bit"));
        assert!(methods.contains("offline_pin_requires_ped_owned_opaque_handle"));
        assert!(
            methods.contains("krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles")
        );
        assert!(methods.contains("rtm_promotes_cvm_pin_capability_evidence"));

        let no_clear_pin = csv_row_for_requirement(csv, "KRN-PIN-002").expect("RTM row exists");
        assert!(
            !no_clear_pin.contains("Opaque handle ABI test"),
            "KRN-PIN-002 should cite executable no-clear-PIN evidence"
        );
        assert!(no_clear_pin.contains("offline_pin_requires_ped_owned_opaque_handle"));
        assert!(no_clear_pin.contains("offline_pin_debug_redacts_ped_handle_values"));
        assert!(no_clear_pin.contains("replay_rejects_pin_verify_payload_custody"));
        assert!(no_clear_pin.contains("rtm_promotes_cvm_pin_capability_evidence"));

        let ped_delegation = csv_row_for_requirement(csv, "KRN-PIN-003").expect("RTM row exists");
        assert!(
            !ped_delegation.contains("Opaque handle ABI test"),
            "KRN-PIN-003 should cite executable PED delegation evidence"
        );
        assert!(ped_delegation.contains("offline_pin_requires_ped_owned_opaque_handle"));
        assert!(ped_delegation
            .contains("krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles"));
        assert!(ped_delegation.contains("rtm_promotes_cvm_pin_capability_evidence"));

        let online_pin = csv_row_for_requirement(csv, "KRN-PINAPI-002").expect("RTM row exists");
        assert!(
            !online_pin.contains("ABI boundary review"),
            "KRN-PINAPI-002 should cite executable online-PIN custody evidence"
        );
        assert!(online_pin.contains("offline_pin_debug_redacts_ped_handle_values"));
        assert!(online_pin.contains("replay_rejects_pin_verify_payload_custody"));
        assert!(online_pin
            .contains("krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles"));
        assert!(online_pin.contains("rtm_promotes_cvm_pin_capability_evidence"));
    }
}

#[test]
fn performance_profile_defines_product_targets_and_buckets() {
    assert!(LAB_SUBMISSION_MANIFEST.contains("performance_profile.csv"));

    let targets = parse_performance_profile(PERFORMANCE_PROFILE).unwrap();
    assert_eq!(targets.len(), 2);
    assert!(targets
        .iter()
        .all(|target| target.profile_id.starts_with("hyperion-mp35p")));
    assert!(targets
        .iter()
        .all(|target| target.test_id.contains("KRN-PERF-001")));
    assert!(targets
        .iter()
        .all(|target| target.test_id.contains("KRN-PERF-002")));

    let mut perf = PerfAccumulator::new();
    perf.record(PerfStage::OdaRsa, 100).unwrap();
    perf.record(PerfStage::OdaEcc, 200).unwrap();
    perf.record(PerfStage::TlvParsing, 30).unwrap();
    perf.record(PerfStage::ApduOverhead, 20).unwrap();

    assert_eq!(perf.stage_micros(PerfStage::OdaRsa), 100);
    assert_eq!(perf.stage_micros(PerfStage::OdaEcc), 200);
    assert_eq!(perf.stage_micros(PerfStage::TlvParsing), 30);
    assert_eq!(perf.stage_micros(PerfStage::ApduOverhead), 20);
    assert!(perf.within_target(&targets[0]).unwrap());
}

#[test]
fn rtm_promotes_performance_profile_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let buckets = csv_row_for_requirement(csv, "KRN-PERF-001").expect("RTM row exists");
        assert!(
            !buckets.contains("pending implementation evidence"),
            "KRN-PERF-001 should cite concrete performance bucket evidence"
        );
        assert!(buckets.contains("records_oda_crypto_tlv_and_apdu_buckets_separately"));
        assert!(buckets.contains("performance_profile_defines_product_targets_and_buckets"));
        assert!(buckets.contains("rtm_promotes_performance_profile_evidence"));

        let targets = csv_row_for_requirement(csv, "KRN-PERF-002").expect("RTM row exists");
        assert!(
            !targets.contains("pending implementation evidence"),
            "KRN-PERF-002 should cite concrete product profile target evidence"
        );
        assert!(targets.contains("validates_product_performance_profile_targets"));
        assert!(targets.contains("performance_profile_defines_product_targets_and_buckets"));
        assert!(targets.contains("rtm_promotes_performance_profile_evidence"));
    }
}

#[test]
fn rtm_promotes_certification_evidence_boundaries() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-CERT-002").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-CERT-002 should cite concrete illustrative-evidence rejection"
        );
        assert!(
            row.contains("profile_loader_rejects_example_only_profiles_for_certification_policy")
        );
        assert!(row.contains("validates_complete_vector_syntax_and_rejects_placeholders"));
        assert!(row.contains(
            "certification_package_rejects_illustrative_profiles_and_placeholder_vectors"
        ));
        assert!(row.contains("rtm_promotes_certification_evidence_boundaries"));

        let pen = csv_row_for_requirement(csv, "KRN-CERT-004").expect("RTM row exists");
        assert!(
            !pen.contains("Pen test report") && !pen.contains("Penetration test report"),
            "KRN-CERT-004 should cite executable security regression evidence"
        );
        assert!(pen.contains("krn_cert_004_penetration_rejects_apdu_injection_and_state_bypass"));
        assert!(pen.contains("replay_rejects_structurally_invalid_command_apdus"));
        assert!(pen.contains("external third-party security assessment"));
        assert!(pen.contains("rtm_promotes_certification_evidence_boundaries"));
    }
}

#[test]
fn both_rtms_cover_dynamic_oda_rows_independently() {
    for krn_id in [
        "KRN-GAC-010",
        "KRN-TAA-007",
        "KRN-ODA-008",
        "KRN-DDA-001",
        "KRN-DDA-002",
        "KRN-ODATV-001",
    ] {
        assert!(CURRENT_RTM.contains(krn_id), "current RTM missing {krn_id}");
        assert!(LEGACY_RTM.contains(krn_id), "legacy RTM missing {krn_id}");
    }
}

#[test]
fn both_rtms_cover_pin_and_cvm_results_rows_independently() {
    for krn_id in [
        "KRN-CVMRES-001",
        "KRN-CVMCAP-001",
        "KRN-PIN-001",
        "KRN-PIN-002",
        "KRN-PIN-003",
        "KRN-PINAPI-001",
        "KRN-PINAPI-002",
    ] {
        assert!(CURRENT_RTM.contains(krn_id), "current RTM missing {krn_id}");
        assert!(LEGACY_RTM.contains(krn_id), "legacy RTM missing {krn_id}");
    }
}

#[test]
fn both_rtms_cover_terminal_capability_rows_independently() {
    for krn_id in ["KRN-TERMCAP-001", "KRN-TTQ-001"] {
        assert!(CURRENT_RTM.contains(krn_id), "current RTM missing {krn_id}");
        assert!(LEGACY_RTM.contains(krn_id), "legacy RTM missing {krn_id}");
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
fn lab_manifest_and_provenance_cover_reproducible_build_artifacts() {
    assert!(LAB_SUBMISSION_MANIFEST.contains("Reproducible build provenance"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("krn_build_manifest"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("every kernel source module"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("abi_conformance_statement.json"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("krn_abi_conformance_statement"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("Certification open-issues register"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("Public standards watch"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("standards_watch.md"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("requirements-traceability-matrix.csv"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("prelab_apdu_trace_pack.jsonl"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("krn_prelab_trace_pack"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("prelab_quality_gates.json"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("krn_prelab_quality_gates"));

    let expected_build_manifest_command = "cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json docs/certification_open_issues.md docs/standards_watch.md examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs";
    assert!(PRELAB_QUALITY_GATES.contains(expected_build_manifest_command));

    let mut input_paths = vec![
        "Cargo.lock".to_string(),
        "Cargo.toml".to_string(),
        "docs/abi_conformance_statement.json".to_string(),
        "docs/bitmap_catalogue.csv".to_string(),
        "docs/certification_open_issues.md".to_string(),
        "docs/lab_submission_manifest.md".to_string(),
        "docs/oda_test_vectors.json".to_string(),
        "docs/performance_profile.csv".to_string(),
        "docs/prelab_apdu_trace_pack.jsonl".to_string(),
        "docs/prelab_quality_gates.json".to_string(),
        "docs/requirements-traceability-matrix.csv".to_string(),
        "docs/requirements_traceability.csv".to_string(),
        "docs/scheme_profiles.cert.json".to_string(),
        "docs/spec.md".to_string(),
        "docs/standards_watch.md".to_string(),
        "docs/state_machine.csv".to_string(),
        "docs/tlv_catalogue.csv".to_string(),
        "examples/krn_abi_conformance_statement.rs".to_string(),
        "examples/krn_build_manifest.rs".to_string(),
        "examples/krn_prelab_quality_gates.rs".to_string(),
        "examples/krn_prelab_trace_pack.rs".to_string(),
    ];
    let mut source_paths = fs::read_dir("src")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    source_paths.sort();
    input_paths.extend(source_paths.iter().cloned());

    let owned_inputs = input_paths
        .iter()
        .map(|path| (path.clone(), fs::read(path).unwrap()))
        .collect::<Vec<_>>();
    let artifacts = owned_inputs
        .iter()
        .map(|(name, bytes)| Artifact {
            name: name.as_str(),
            bytes: bytes.as_slice(),
        })
        .collect::<Vec<_>>();
    let manifest = build_provenance_manifest(KRN_ABI_VERSION, &artifacts).unwrap();

    let names = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.name.as_str())
        .collect::<Vec<_>>();
    let name_set = names.iter().copied().collect::<BTreeSet<_>>();
    for required in [
        "Cargo.lock",
        "Cargo.toml",
        "docs/abi_conformance_statement.json",
        "docs/bitmap_catalogue.csv",
        "docs/certification_open_issues.md",
        "docs/lab_submission_manifest.md",
        "docs/oda_test_vectors.json",
        "docs/performance_profile.csv",
        "docs/prelab_apdu_trace_pack.jsonl",
        "docs/prelab_quality_gates.json",
        "docs/requirements-traceability-matrix.csv",
        "docs/requirements_traceability.csv",
        "docs/scheme_profiles.cert.json",
        "docs/spec.md",
        "docs/standards_watch.md",
        "docs/state_machine.csv",
        "docs/tlv_catalogue.csv",
        "examples/krn_abi_conformance_statement.rs",
        "examples/krn_build_manifest.rs",
        "examples/krn_prelab_quality_gates.rs",
        "examples/krn_prelab_trace_pack.rs",
    ] {
        assert!(
            name_set.contains(required),
            "provenance manifest missing required artifact {required}"
        );
    }
    let manifest_sources = names
        .iter()
        .copied()
        .filter(|name| name.starts_with("src/"))
        .collect::<BTreeSet<_>>();
    let expected_sources = source_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        manifest_sources, expected_sources,
        "build provenance must cover every kernel source module"
    );
    let scheme_digest = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "docs/scheme_profiles.cert.json")
        .unwrap();
    assert_eq!(
        to_hex(&scheme_digest.sha256),
        to_hex(&sha256(SCHEME_PROFILES.as_bytes()))
    );

    let json = manifest.canonical_json();
    assert!(json.starts_with("{\"type\":\"build-provenance\""));
    assert!(json.contains("\"kernel_name\":\"hyperion-emv\""));
    assert!(json.contains(&format!("\"abi_version\":{KRN_ABI_VERSION}")));
    assert!(json.contains("\"name\":\"docs/scheme_profiles.cert.json\""));
    assert!(json.contains("\"sha256\":\""));
    assert!(!json.contains("placeholder"));
}

#[test]
fn lab_manifest_leaves_unattached_external_reports_unchecked() {
    for line in LAB_SUBMISSION_MANIFEST.lines() {
        if line.contains("[to be attached]") {
            assert!(
                line.starts_with("- [ ]"),
                "pending external artifact is incorrectly checked: {line}"
            );
        }
    }

    for attached in [
        "Conformance statement (ABI JSON)",
        "Reproducible build provenance",
        "Trace identity metadata",
        "Pre-lab APDU trace fixture",
        "Pre-lab quality gate manifest",
    ] {
        assert!(
            LAB_SUBMISSION_MANIFEST.contains(&format!("- [x] {attached}")),
            "locally generated artifact should remain checked: {attached}"
        );
    }

    for pending in [
        "Unit test report",
        "Integration test report",
        "Static analysis report",
        "Fuzzing report",
        "PCI PTS integration statement",
        "Conformance statement (signed EMVCo/lab template)",
        "APDU trace logs",
    ] {
        assert!(
            LAB_SUBMISSION_MANIFEST.contains(&format!("- [ ] {pending}")),
            "external artifact should remain unchecked: {pending}"
        );
    }

    for overstatement in [
        "**EMV Level 2 Contact:** Yes",
        "**EMV Level 2 Contactless (C‑8):** Yes",
        "**PCI PTS POI v7.0 alignment:** Yes",
        "certified contactless readers",
        "All artifacts are structurally complete",
        "has been developed in accordance",
    ] {
        assert!(
            !LAB_SUBMISSION_MANIFEST.contains(overstatement),
            "manifest must not claim approval while external evidence is unattached: {overstatement}"
        );
    }

    for scoped_claim in [
        "EMV Level 2 Contact:** In scope for pre-certification hardening",
        "final claim requires lab execution, signed approval evidence",
        "EMV Level 2 Contactless (C‑8):** In scope for pre-certification hardening",
        "final claim requires the unified kernel approval package and lab-supplied profile data",
        "PCI PTS POI v7.0 alignment:** Alignment target pending PED integration statement",
        "Target Device:** Hyperion MP35P terminal and contactless readers pending device/L1 certification evidence",
        "Repository-controlled artifacts marked complete are structurally complete",
        "subject to licensed review, scheme validation, and laboratory approval",
    ] {
        assert!(
            LAB_SUBMISSION_MANIFEST.contains(scoped_claim),
            "manifest missing bounded scope statement: {scoped_claim}"
        );
    }

    assert!(include_str!("../docs/eng_notes.md")
        .contains("repository-controlled artifacts such as source code"));
    assert!(include_str!("../docs/eng_notes.md")
        .contains("device evidence, and approval artifacts are still external"));
}

#[test]
fn certification_open_issues_register_tracks_external_blockers() {
    assert!(CERTIFICATION_OPEN_ISSUES.contains("# Certification Open-Issues Register"));
    assert!(include_str!("../docs/eng_notes.md").contains("docs/certification_open_issues.md"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("certification_open_issues.md"));

    for id in 1..=12 {
        let issue_id = format!("CERT-OPEN-{id:03}");
        assert!(
            CERTIFICATION_OPEN_ISSUES.contains(&issue_id),
            "open-issues register missing {issue_id}"
        );
    }

    for blocker in [
        "EMVCo/scheme laboratory execution",
        "signed approval or LoA",
        "Lab/scheme/acquirer-signed AID",
        "Scheme/acquirer-approved CAPK set",
        "Lab-supplied SDA, DDA, and CDA cryptographic vectors",
        "C-8 approval package",
        "licensed v1.0/v1.1 and SB 325 reconciliation",
        "Target terminal, contact interface, contactless reader",
        "PCI PTS POI integration statement",
        "Penetration test report",
        "Unit coverage report",
        "Static-analysis report",
        "Signed EMVCo/lab conformance statement template",
        "Masked APDU traces",
    ] {
        assert!(
            CERTIFICATION_OPEN_ISSUES.contains(blocker),
            "open-issues register missing blocker: {blocker}"
        );
    }

    let rows = CERTIFICATION_OPEN_ISSUES
        .lines()
        .filter(|line| line.starts_with("| CERT-OPEN-"))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 12);
    assert!(
        rows.iter().all(|row| row.contains("| Open |")),
        "external certification blockers must remain open until evidence is attached"
    );
    assert!(CERTIFICATION_OPEN_ISSUES.contains("pre-lab quality gate manifest does not close"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("accepted report attachments"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("ABI JSON statement does not close"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("pre-lab fixture does not close"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("Full lab trace pack is attached"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("lab-selected C-8 version/bulletin set"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("C-8 v1.1 / SB 325"));
    assert!(STANDARDS_WATCH.contains("Book C-8 Kernel Specification v1.1"));
    assert!(STANDARDS_WATCH.contains("SB 325"));
    assert!(STANDARDS_WATCH.contains("Public Approval-Process Check"));
    assert!(STANDARDS_WATCH.contains("approval can be pursued as one element"));
    assert!(STANDARDS_WATCH.contains("full contactless acceptance"));
    assert!(STANDARDS_WATCH.contains("standalone kernel"));
    assert!(STANDARDS_WATCH.contains("approved-kernel integration"));
    assert!(STANDARDS_WATCH.contains("implementation conformance statement"));
    assert!(STANDARDS_WATCH.contains("Letter of Approval"));
    assert!(STANDARDS_WATCH.contains("Do not replace this with repository"));
    assert!(STANDARDS_WATCH.contains("Do not close `CERT-OPEN-005`"));
    assert!(STANDARDS_WATCH.contains("exact Contactless Kernel 8 approval path"));
    assert!(STANDARDS_WATCH.contains("laboratory test reports"));
}

#[test]
fn krn_ref_001_conformance_statement_declares_normative_hierarchy() {
    assert!(RTM.contains("KRN-REF-001"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("abi_conformance_statement.json"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("cargo run --example krn_abi_conformance_statement"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("krn_get_conformance_statement_json"));

    unsafe {
        let mut len = 0usize;
        assert_eq!(
            krn_get_conformance_statement_json(ptr::null_mut(), &mut len),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut json = vec![0u8; len];
        assert_eq!(
            krn_get_conformance_statement_json(json.as_mut_ptr(), &mut len),
            hyperion_emv::KernelError::Ok.code()
        );
        let json = String::from_utf8(json).unwrap();
        let generated = baseline_conformance_statement(KRN_ABI_VERSION).canonical_json();

        assert_eq!(ABI_CONFORMANCE_STATEMENT, format!("{generated}\n"));
        assert_eq!(json, generated);
        assert!(json.contains("\"type\":\"conformance-statement\""));
        assert!(json.contains("\"kernel_name\":\"Hyperion EMV Level 2 Kernel\""));
        assert!(json.contains(&format!("\"abi_version\":{KRN_ABI_VERSION}")));
        assert!(json.contains("\"status\":\"engineering-baseline-pending-licensed-review\""));
        assert!(json.contains("\"normative_hierarchy\":\"licensed_external_standards_prevail\""));
        for required in [
            "docs/spec.md",
            "docs/lab_submission_manifest.md",
            "docs/certification_open_issues.md",
            "docs/standards_watch.md",
            "docs/prelab_apdu_trace_pack.jsonl",
            "docs/prelab_quality_gates.json",
            "docs/scheme_profiles.cert.json",
            "EMV-B1",
            "EMV-B2",
            "EMV-B3",
            "EMV-B4",
            "EMV-C8",
            "PCI-PTS-POI",
            "SIGNED-SCHEME-PROFILES",
            "LAB-TEST-PLANS",
            "Licensed external standards prevail",
            "docs/oda_test_vectors.json is a structural fixture annex unless vector_class is CERTIFICATION",
            "docs/certification_open_issues.md remains the controlling register for external blockers",
            "docs/standards_watch.md records public standards drift but does not replace licensed review",
            "Repository ABI JSON does not close CERT-OPEN-011 signed EMVCo/lab conformance template requirement",
        ] {
            assert!(
                json.contains(required),
                "conformance statement missing {required}"
            );
        }
    }
    assert!(CERTIFICATION_OPEN_ISSUES.contains("repository ABI JSON statement does not close"));
}

#[test]
fn rtm_promotes_reference_config_log_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let reference = csv_row_for_requirement(csv, "KRN-REF-001").expect("RTM row exists");
        assert!(
            !reference.contains("Conformance statement"),
            "KRN-REF-001 should cite executable conformance statement evidence"
        );
        assert!(reference.contains("conformance_statement_json_is_deterministic_and_scoped"));
        assert!(
            reference.contains("krn_ref_001_conformance_statement_declares_normative_hierarchy")
        );
        assert!(reference.contains("rtm_promotes_reference_config_log_evidence"));

        let profile_class = csv_row_for_requirement(csv, "KRN-CFG-004").expect("RTM row exists");
        assert!(
            !profile_class.contains("Signed profile class validation"),
            "KRN-CFG-004 should cite executable profile class rejection evidence"
        );
        assert!(
            profile_class.contains("rejects_example_profile_in_certification_or_production_mode")
        );
        assert!(profile_class
            .contains("profile_loader_rejects_example_only_profiles_for_certification_policy"));
        assert!(profile_class.contains(
            "certification_package_rejects_illustrative_profiles_and_placeholder_vectors"
        ));
        assert!(profile_class.contains("rtm_promotes_reference_config_log_evidence"));

        let log_policy = csv_row_for_requirement(csv, "KRN-LOG-001").expect("RTM row exists");
        assert!(
            !log_policy.contains("Log config audit")
                && !log_policy.contains("Logging configuration + audit"),
            "KRN-LOG-001 should cite executable log policy evidence"
        );
        assert!(log_policy.contains("krn_log_001_masks_sensitive_tlv_and_gac_trace_values"));
        assert!(log_policy.contains("krn_log_001_exposes_masked_apdu_trace_json_via_abi"));
        assert!(log_policy
            .contains("production_policy_never_emits_full_apdu_data_even_if_misconfigured"));
        assert!(log_policy.contains("rtm_promotes_logging_policy_evidence"));
        assert!(log_policy.contains("rtm_promotes_reference_config_log_evidence"));
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
        "KRN-DPL-001",
        "KRN-DPL-002",
        "KRN-DPL-003",
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
        "KRN-DDA-001",
        "KRN-DDA-002",
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
fn scheme_profile_annex_uses_certification_provenance() {
    for key in [
        "\"profile_class\": \"CERTIFICATION\"",
        "\"owner\": \"Hyperion-X Certification\"",
        "\"owner\": \"Visa\"",
        "\"owner\": \"Mastercard\"",
        "\"document\": \"signed_certification_profile_bundle\"",
        "\"document\": \"signed_certification_capk_bundle\"",
        "\"verification\": \"external_signature_required\"",
    ] {
        assert!(
            SCHEME_PROFILES.contains(key),
            "scheme profile annex missing provenance key {key}"
        );
    }

    for forbidden in [
        "l2emv_public_capkey_viewer",
        "Public reference value",
        "certification builds must use",
        "scheme_or_acquirer",
    ] {
        assert!(
            !SCHEME_PROFILES.contains(forbidden),
            "scheme profile annex still contains non-certification provenance {forbidden}"
        );
    }
}

#[test]
fn scheme_profile_annex_declares_bundled_and_lab_supplied_scope() {
    for key in [
        "\"certification_scope\"",
        "\"bundled_scheme_profiles\": [\"Visa\", \"Mastercard\"]",
        "\"lab_supplied_scheme_profiles_required\": [\"Amex\", \"Discover\"]",
        "\"contactless_kernel_profile\": \"C-8 lab approval package\"",
        "\"profile_material_status\": \"certification_format_fixture_pending_lab_signature\"",
        "\"capk_material_status\": \"deterministic_public_fixture_values_must_be_replaced_by_lab_signed_capks\"",
        "\"production_profile_bundle_required\": true",
    ] {
        assert!(
            SCHEME_PROFILES.contains(key),
            "scheme profile annex missing scope key {key}"
        );
    }

    assert!(LAB_SUBMISSION_MANIFEST
        .contains("In scope for pre-certification hardening (Visa, Mastercard)"));
    assert!(LAB_SUBMISSION_MANIFEST
        .contains("lab-supplied signed profiles before any Amex or Discover claim"));
    assert!(LAB_SUBMISSION_MANIFEST
        .contains("final claim requires the unified kernel approval package"));
}

#[test]
fn supported_contactless_profiles_use_c8_certification_scope() {
    assert!(
        SCHEME_PROFILES.contains("\"contactless_kernel_profile\": \"C-8 lab approval package\"")
    );
    assert!(LAB_SUBMISSION_MANIFEST
        .contains("final claim requires the unified kernel approval package"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("lab-supplied profile data"));

    let profiles = load_profile_set(SCHEME_PROFILES.as_bytes(), &certification_policy()).unwrap();
    assert_eq!(profiles.profile_class, ProfileClass::Certification);
    assert!(profiles
        .schemes
        .iter()
        .all(|scheme| scheme.aids.iter().any(|aid| aid
            .interfaces
            .iter()
            .any(|interface| interface == "contactless"))));

    for scheme in &profiles.schemes {
        assert_eq!(scheme.kernel_type, "c8_contactless");
        assert_ne!(
            scheme.contact_kernel_type.as_deref(),
            Some("c8_contactless")
        );
    }
}

#[test]
fn scheme_profile_annex_declares_capk_checksum_derivation() {
    let algorithm = "\"checksum_algorithm\": \"sha1(rid || key_index || modulus || exponent)\"";
    assert_eq!(SCHEME_PROFILES.matches(algorithm).count(), 2);
    assert_eq!(
        SCHEME_PROFILES
            .matches(
                "\"checksum_scope\": [\"rid\", \"key_index\", \"modulus_hex\", \"exponent_hex\"]"
            )
            .count(),
        2
    );
}

#[test]
fn scheme_profile_annex_excludes_synthetic_c8_payment_profile() {
    assert!(!SCHEME_PROFILES.contains("A000000999"));
    assert!(!SCHEME_PROFILES.contains("A000000999C8"));
}

#[test]
fn spec_status_matches_non_certification_oda_fixture_gate() {
    let spec = include_str!("../docs/spec.md");

    assert!(spec.contains("Engineering baseline pending licensed review and laboratory evidence"));
    assert!(spec.contains("controlled pre-certification engineering baseline"));
    assert!(spec.contains("Licensed"));
    assert!(spec.contains("approval artifacts"));
    assert!(spec.contains("engineering baseline pending licensed review"));
    assert!(spec.contains("vector_class = \"CERTIFICATION\""));
    assert!(spec.contains("lab-supplied ODA vectors"));
    assert!(!spec.contains("(Final)"));
    assert!(!spec.contains("complete artifact set"));
    assert!(!spec.contains("complete controlled certification baseline"));
    assert!(!spec.contains("fully correct, complete, and certifiable"));
    assert!(!spec.contains("ready for implementation and EMVCo Level"));
}

#[test]
fn spec_delegates_lab_manifest_state_to_executable_manifest() {
    let spec = include_str!("../docs/spec.md");

    assert!(spec.contains("The executable lab submission manifest is"));
    assert!(spec.contains("docs/lab_submission_manifest.md"));
    assert!(spec.contains("authoritative manifest for"));
    assert!(spec.contains("artifact attachment state"));
    assert!(spec.contains("SHALL NOT mark an item complete while its row still says"));
    assert!(spec.contains("Bundled ODA vectors remain structural fixtures"));
    assert!(spec.contains("vector_class = \"CERTIFICATION\""));
    assert!(!spec.contains("All test vectors and configuration profiles are authentic"));
    assert!(!spec.contains("EMV Level 2 Contact:** Yes (Visa, Mastercard, Amex, Discover)"));
}

#[test]
fn certification_package_rejects_illustrative_profiles_and_placeholder_vectors() {
    load_profile_set(SCHEME_PROFILES.as_bytes(), &certification_policy()).unwrap();

    let illustrative_profile = SCHEME_PROFILES.replace(
        "\"profile_class\": \"CERTIFICATION\"",
        "\"profile_class\": \"EXAMPLE_ONLY\"",
    );
    assert_eq!(
        load_profile_set(illustrative_profile.as_bytes(), &certification_policy()).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    assert!(ODA_VECTORS.contains("\"vector_class\": \"STRUCTURAL_FIXTURE\""));
    assert_eq!(
        validate_oda_vector_annex(ODA_VECTORS.as_bytes(), true).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
    validate_oda_vector_annex(ODA_VECTORS.as_bytes(), false).unwrap();
    assert!(LAB_SUBMISSION_MANIFEST.contains("deterministic unit fixtures"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("lab-supplied SDA/DDA/CDA vectors"));
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
    assert_eq!(profiles.profile_class, ProfileClass::Certification);
    assert_eq!(
        profiles.profile_source.document,
        "signed_certification_profile_bundle"
    );
    assert_eq!(
        profiles.profile_source.verification,
        "external_signature_required"
    );
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
        profiles.schemes[0].capks[0].source.document,
        "signed_certification_capk_bundle"
    );
    assert_eq!(
        profiles.schemes[0].capks[0].source.verification,
        "external_signature_required"
    );
    assert_eq!(
        profiles.schemes[0].aids[0]
            .trm_profile()
            .unwrap()
            .random_selection_percent,
        5
    );
    assert_eq!(profiles.schemes[0].capks[0].key_index, 9);
    assert!(profiles.schemes[0].capks[0].modulus.len() >= 64);
    assert_eq!(
        profiles.schemes[0].capks[0].checksum,
        hex("1FF80A40173F52D7D27E0F26A146A1C8CCB29046")
    );
    assert_eq!(profiles.schemes[1].capks[0].key_index, 6);
    assert_eq!(
        profiles.schemes[1].capks[0].checksum,
        hex("F910A1504D5FFB793D94F3B500765E1ABCAD72D9")
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
fn krn_sec_003_oda_001_cert_profile_loader_rejects_capk_checksum_drift() {
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

    let tampered_checksum = SCHEME_PROFILES.replace(
        "\"checksum_hex\": \"1FF80A40173F52D7D27E0F26A146A1C8CCB29046\"",
        "\"checksum_hex\": \"1FF80A40173F52D7D27E0F26A146A1C8CCB29047\"",
    );
    assert_eq!(
        load_profile_set(tampered_checksum.as_bytes(), &policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let tampered_algorithm = SCHEME_PROFILES.replace(
        "\"checksum_algorithm\": \"sha1(rid || key_index || modulus || exponent)\"",
        "\"checksum_algorithm\": \"sha1(modulus || exponent)\"",
    );
    assert_eq!(
        load_profile_set(tampered_algorithm.as_bytes(), &policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
}

#[test]
fn krn_sec_003_oda_002_capks_retain_signed_public_provenance() {
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

    for scheme in &profiles.schemes {
        for capk in &scheme.capks {
            assert_eq!(capk.source.owner, scheme.scheme_name);
            assert_ne!(capk.source.owner, "scheme_or_acquirer");
            assert_eq!(capk.source.document, "signed_certification_capk_bundle");
            assert_eq!(capk.source.version, "2");
            assert_eq!(capk.source.verification, "external_signature_required");
            assert!(capk.modulus.len() >= 64);
            assert_eq!(capk.checksum.len(), 20);
        }
    }

    let missing_capk_source = br#"{
      "profile_class": "CERTIFICATION",
      "profile_source": {
        "owner": "scheme_or_acquirer",
        "document": "signed_certification_profile_bundle",
        "version": "2",
        "verification": "external_signature_required"
      },
      "scheme_profiles": [{
        "scheme_name": "Visa",
        "rid": "A000000003",
        "kernel_type": "c8_contactless",
        "contact_kernel_type": "legacy_visa",
        "taa_fallback_when_offline_unable_online": "AAC",
        "taa_no_match_default_when_online_capable": "ARQC",
        "taa_no_match_default_when_offline_only": "AAC",
        "aids": [{
          "aid": "A0000000031010",
          "priority": 10,
          "partial_selection": true,
          "interfaces": ["contact", "contactless"],
          "tac_online": "E0F8C80000",
          "tac_denial": "0000000000",
          "tac_default": "8000000000",
          "iac_online": "0000000000",
          "iac_denial": "0000000000",
          "iac_default": "0000000000",
          "floor_limit": 0,
          "cvm_limit_contact": 5000,
          "random_selection_percent": 5,
          "contactless_transaction_limit": 5000,
          "contactless_cvm_limit": 3000,
          "cdcvm_supported": true,
          "cda_supported": true,
          "cda_request_encoding": "CDOL1_bit"
        }],
        "capks": [{
          "key_index": 1,
          "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
          "exponent_hex": "010001",
          "expiry": "2030-12-31",
          "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5",
          "checksum_algorithm": "sha1(rid || key_index || modulus || exponent)",
          "checksum_scope": ["rid", "key_index", "modulus_hex", "exponent_hex"]
        }]
      }]
    }"#;
    assert_eq!(
        load_profile_set(missing_capk_source, &policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
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
fn rtm_promotes_signed_profile_and_capk_validation_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-ANNEX-004",
            "KRN-CAPK-001",
            "KRN-CAPK-002",
            "KRN-CFG-001",
            "KRN-CFG-003",
            "KRN-PROFILE-001",
            "KRN-PROFILE-002",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete profile/CAPK validation evidence"
            );
        }

        let signature = csv_row_for_requirement(csv, "KRN-CFG-001").unwrap();
        assert!(signature.contains("rejects_unsigned_certification_profile_rollback_and_replay"));
        assert!(signature
            .contains("profile_loader_requires_verified_signature_and_extracts_capk_tac_limits"));

        let rollback = csv_row_for_requirement(csv, "KRN-CFG-003").unwrap();
        assert!(rollback.contains("profile_loader_rejects_rollback_placeholders_and_expired_capks"));
        assert!(rollback.contains("krn_dpl_001_002_003_profile_updates_are_monotonic_and_atomic"));

        for id in ["KRN-ANNEX-004", "KRN-PROFILE-001"] {
            let placeholders = csv_row_for_requirement(csv, id).unwrap();
            assert!(placeholders.contains("rejects_placeholder_and_bad_hex_material"));
            assert!(placeholders
                .contains("profile_loader_rejects_rollback_placeholders_and_expired_capks"));
        }

        let capk_integrity = csv_row_for_requirement(csv, "KRN-CAPK-001").unwrap();
        assert!(capk_integrity
            .contains("rejects_certification_capk_checksum_mismatch_or_metadata_drift"));
        assert!(capk_integrity.contains("rejects_invalid_capk_public_key_components"));
        assert!(capk_integrity
            .contains("krn_sec_003_oda_001_cert_profile_loader_rejects_capk_checksum_drift"));
        assert!(
            capk_integrity.contains("krn_capk_001_002_lookup_requires_verified_profile_integrity")
        );

        let capk_expiry = csv_row_for_requirement(csv, "KRN-CAPK-002").unwrap();
        assert!(capk_expiry.contains("rejects_expired_capk"));
        assert!(capk_expiry.contains("krn_capk_001_002_lookup_requires_verified_profile_integrity"));

        let capk_hex = csv_row_for_requirement(csv, "KRN-PROFILE-002").unwrap();
        assert!(capk_hex.contains("loads_profile_annex_when_signature_is_verified"));
        assert!(capk_hex.contains("rejects_certification_capk_checksum_mismatch_or_metadata_drift"));
        assert!(capk_hex.contains("rejects_invalid_capk_public_key_components"));
        assert!(capk_hex.contains("krn_sec_003_oda_002_capks_retain_signed_public_provenance"));
    }
}

#[test]
fn rtm_promotes_cfg_schema_and_terminal_param_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-CFG-002").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-CFG-002 should cite concrete configuration rejection evidence"
        );
        assert!(row.contains("rejects_cfg_002_profile_schema_and_field_failures"));
        assert!(row.contains("rejects_profile_json_depth_limit_overflow"));
        assert!(row.contains("rejects_profile_json_node_limit_overflow"));
        assert!(row.contains("rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces"));
        assert!(row.contains("rejects_aids_outside_scheme_rid_namespace"));
        assert!(row.contains("rejects_duplicate_scheme_rids"));
        assert!(row.contains("rejects_duplicate_profile_aids_and_capk_indexes"));
        assert!(row.contains("rejects_expired_capk"));
        assert!(row.contains("rejects_invalid_capk_public_key_components"));
        assert!(row.contains("transaction_params_bind_minor_units_to_currency_exponent"));
        assert!(row.contains("krn_api_001_002_rejects_bad_abi_before_optional_fields"));
        assert!(row.contains("rtm_promotes_cfg_schema_and_terminal_param_evidence"));
    }
}

#[test]
fn rtm_promotes_terminal_capability_and_ttq_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let termcap = csv_row_for_requirement(csv, "KRN-TERMCAP-001").expect("RTM row exists");
        assert!(
            !termcap.contains("PDOL and online handoff evidence"),
            "KRN-TERMCAP-001 should cite executable 9F33 PDOL and handoff evidence"
        );
        assert!(termcap.contains("krn_termcap_001_supplies_9f33_to_pdol_and_online_handoff"));
        assert!(termcap.contains("rtm_promotes_terminal_capability_and_ttq_evidence"));

        let ttq = csv_row_for_requirement(csv, "KRN-TTQ-001").expect("RTM row exists");
        assert!(
            !ttq.contains("Contactless PDOL and online handoff evidence"),
            "KRN-TTQ-001 should cite executable 9F66 contactless PDOL evidence"
        );
        assert!(ttq.contains("krn_ttq_001_supplies_9f66_to_contactless_pdol_and_online_handoff"));
        assert!(ttq.contains("rtm_promotes_terminal_capability_and_ttq_evidence"));
    }
}

#[test]
fn rtm_promotes_tlv_catalogue_and_dol_classification_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-ANNEX-003",
            "KRN-TLV-001",
            "KRN-TLV-002",
            "KRN-TLV-003",
            "KRN-TLV-004",
            "KRN-TLV-005",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete TLV catalogue evidence"
            );
        }

        let parser = csv_row_for_requirement(csv, "KRN-TLV-001").unwrap();
        assert!(parser.contains("parses_nested_fci_template"));
        assert!(parser.contains("finds_unique_direct_values_without_descending"));
        assert!(parser.contains("tlv_parser_is_deterministic_for_valid_and_truncated_inputs"));

        let annex = csv_row_for_requirement(csv, "KRN-ANNEX-003").unwrap();
        assert!(annex.contains("parses_and_builds_pdol_deterministically"));
        assert!(annex.contains("krn_dda_001_internal_authenticate_uses_ddol_values"));

        let dol = csv_row_for_requirement(csv, "KRN-TLV-002").unwrap();
        assert!(dol.contains("parses_and_builds_pdol_deterministically"));
        assert!(dol.contains("krn_dda_001_internal_authenticate_uses_ddol_values"));
        assert!(dol.contains("tlv_catalogue_uses_required_schema_and_profile_defined_markers"));

        let catalogue = csv_row_for_requirement(csv, "KRN-TLV-004").unwrap();
        assert!(
            catalogue.contains("tlv_catalogue_uses_required_schema_and_profile_defined_markers")
        );
        assert!(catalogue.contains("tlv_catalogue_contains_required_foundation_tags"));

        let scheme_defined = csv_row_for_requirement(csv, "KRN-TLV-005").unwrap();
        assert!(scheme_defined
            .contains("tlv_catalogue_uses_required_schema_and_profile_defined_markers"));

        let malformed = csv_row_for_requirement(csv, "KRN-TLV-003").unwrap();
        assert!(malformed.contains("rejects_indefinite_lengths_for_fuzzability"));
        assert!(malformed.contains("tlv::tests::rejects_invalid_tag_field_bytes"));
        assert!(malformed.contains("dol::tests::rejects_invalid_tag_field_bytes"));
        assert!(malformed.contains("tlv::tests::rejects_zero_prefixed_high_tag_numbers"));
        assert!(malformed.contains("dol::tests::rejects_zero_prefixed_high_tag_numbers"));
        assert!(malformed.contains("rejects_overlong_tags_and_configured_value_length_overflow"));
        assert!(malformed.contains("rejects_tlv_node_limit_overflow"));
        assert!(malformed.contains("rejects_tlv_depth_limit_overflow"));
        assert!(malformed.contains("rejects_truncated_values_without_panicking"));
    }
}

#[test]
fn rtm_promotes_dol_construction_policy_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-DOL-001", "KRN-DOL-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete DOL construction evidence"
            );
            assert!(row
                .contains("krn_dol_001_002_builds_requested_lengths_with_explicit_padding_policy"));
        }

        let exact_lengths = csv_row_for_requirement(csv, "KRN-DOL-001").unwrap();
        assert!(exact_lengths.contains("parses_and_builds_pdol_deterministically"));
        assert!(exact_lengths.contains("rejects_dol_lists_above_entry_limit"));
        assert!(exact_lengths.contains("builds_gpo_with_tag_83_pdol_values"));
        assert!(exact_lengths.contains("builds_internal_authenticate_from_ddol_values"));

        let padding_policy = csv_row_for_requirement(csv, "KRN-DOL-002").unwrap();
        assert!(padding_policy.contains("zero_padding_policy_is_explicit_and_deterministic"));
        assert!(padding_policy.contains("exact_value_policy_rejects_missing_or_short_dol_sources"));
        assert!(padding_policy.contains("dol_output_cap_applies_before_padding_policy"));
    }
}

#[test]
fn rtm_promotes_dda_internal_authenticate_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-DDA-001", "KRN-DDA-002", "KRN-ODA-006"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete DDA evidence"
            );
            assert!(
                row.contains("rtm_promotes_dda_internal_authenticate_evidence"),
                "{id} should cite this RTM guard"
            );
        }

        let internal_authenticate = csv_row_for_requirement(csv, "KRN-DDA-001").unwrap();
        assert!(internal_authenticate.contains("builds_internal_authenticate_from_ddol_values"));
        assert!(internal_authenticate
            .contains("runtime_oda_executes_dda_internal_authenticate_success"));
        assert!(
            internal_authenticate.contains("krn_dda_001_internal_authenticate_uses_ddol_values")
        );

        let signed_dynamic_data = csv_row_for_requirement(csv, "KRN-DDA-002").unwrap();
        assert!(
            signed_dynamic_data.contains("recovers_parses_and_verifies_signed_application_data")
        );
        assert!(
            signed_dynamic_data.contains("rejects_internal_authenticate_without_response_template")
        );
        assert!(
            signed_dynamic_data.contains("rejects_nested_or_duplicate_internal_authenticate_data")
        );
        assert!(
            signed_dynamic_data.contains("runtime_oda_executes_dda_internal_authenticate_success")
        );
        assert!(signed_dynamic_data.contains("runtime_oda_maps_bad_dda_signature_to_tvr_failure"));
        assert!(signed_dynamic_data
            .contains("krn_dda_002_oda_006_requires_signed_dynamic_application_data"));

        let dda_failure = csv_row_for_requirement(csv, "KRN-ODA-006").unwrap();
        assert!(dda_failure.contains("runtime_oda_maps_bad_dda_signature_to_tvr_failure"));
        assert!(dda_failure
            .contains("krn_oda_005_006_007_recovers_and_verifies_signed_application_data"));
    }
}

#[test]
fn rtm_promotes_oda_capk_tvr_cda_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-ODA-001",
            "KRN-ODA-002",
            "KRN-ODA-003",
            "KRN-ODA-004",
            "KRN-ODA-005",
            "KRN-ODA-006",
            "KRN-ODA-007",
            "KRN-ODA-008",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("CAPK checksum validation evidence")
                    && !row.contains("Config signature")
                    && !row.contains("TVR after failure")
                    && !row.contains("TVR after ODA failure")
                    && !row.contains("TVR after recovery failure")
                    && !row.contains("TVR trace")
                    && !row.contains("TVR + fallback test")
                    && !row.contains("CDA vector"),
                "{id} should cite executable ODA evidence"
            );
            assert!(row.contains("rtm_promotes_oda_capk_tvr_cda_evidence"));
        }

        let capk_hash = csv_row_for_requirement(csv, "KRN-ODA-001").unwrap();
        assert!(
            capk_hash.contains("rejects_certification_capk_checksum_mismatch_or_metadata_drift")
        );
        assert!(capk_hash
            .contains("krn_sec_003_oda_001_cert_profile_loader_rejects_capk_checksum_drift"));
        assert!(capk_hash.contains("krn_capk_001_002_lookup_requires_verified_profile_integrity"));

        let capk_integrity = csv_row_for_requirement(csv, "KRN-ODA-002").unwrap();
        assert!(
            capk_integrity.contains("krn_sec_003_oda_002_capks_retain_signed_public_provenance")
        );
        assert!(capk_integrity.contains("loads_profile_annex_when_signature_is_verified"));
        assert!(capk_integrity
            .contains("profile_loader_requires_verified_signature_and_extracts_capk_tac_limits"));

        for id in ["KRN-ODA-003", "KRN-ODA-004"] {
            let recovery = csv_row_for_requirement(csv, id).unwrap();
            assert!(recovery.contains("krn_oda_003_004_certificate_recovery_failures_set_tvr"));
            assert!(recovery.contains(
                "krn_oda_003_004_public_key_inputs_require_certificates_exponents_and_remainders"
            ));
            assert!(recovery.contains(
                "krn_oda_002_003_004_recovered_certificates_reconstruct_public_key_material"
            ));
        }

        let sda = csv_row_for_requirement(csv, "KRN-ODA-005").unwrap();
        assert!(sda.contains("runtime_oda_maps_bad_sda_signature_to_tvr_failure"));
        assert!(sda.contains(
            "krn_oda_001_005_006_007_selects_method_and_sets_tvr_tsi_without_cda_fallback"
        ));
        assert!(sda.contains("rejects_malformed_static_authentication_tag_list"));
        assert!(sda.contains("rejects_static_authentication_tag_lists_above_limit"));
        assert!(sda.contains("krn_oda_005_static_authentication_data_uses_afl_order_and_tag_list"));
        assert!(sda.contains("krn_oda_005_006_007_recovers_and_verifies_signed_application_data"));

        let dda = csv_row_for_requirement(csv, "KRN-ODA-006").unwrap();
        assert!(dda.contains("runtime_oda_maps_bad_dda_signature_to_tvr_failure"));
        assert!(dda.contains("rtm_promotes_dda_internal_authenticate_evidence"));

        let cda = csv_row_for_requirement(csv, "KRN-ODA-007").unwrap();
        assert!(cda.contains("runtime_cda_failure_sets_tvr_without_falling_back_to_dda"));
        assert!(cda.contains("runtime_cda_missing_signed_dynamic_data_sets_tvr_for_online_handoff"));
        assert!(
            cda.contains("selects_strongest_allowed_oda_method_without_fallback_after_cda_failure")
        );
        assert!(cda.contains(
            "krn_oda_001_005_006_007_selects_method_and_sets_tvr_tsi_without_cda_fallback"
        ));

        let cda_exact = csv_row_for_requirement(csv, "KRN-ODA-008").unwrap();
        assert!(cda_exact.contains("runtime_cda_verifies_first_gac_signed_dynamic_data"));
        assert!(cda_exact
            .contains("runtime_cda_missing_signed_dynamic_data_sets_tvr_for_online_handoff"));
        assert!(cda_exact.contains("validates_complete_vector_syntax_and_rejects_placeholders"));
        assert!(
            cda_exact.contains("krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode")
        );
    }
}

#[test]
fn rtm_promotes_fsm_annex_replay_and_error_transition_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-FSM-001", "KRN-FSM-002", "KRN-FSM-003", "KRN-FSM-004"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete FSM evidence"
            );
        }

        let annex = csv_row_for_requirement(csv, "KRN-FSM-001").unwrap();
        assert!(annex.contains("validates_machine_readable_state_annex"));
        assert!(annex.contains("krn_fsm_001_002_004_validates_annex_and_error_transitions"));

        let fatal_vs_risk = csv_row_for_requirement(csv, "KRN-FSM-002").unwrap();
        assert!(
            fatal_vs_risk.contains("distinguishes_fatal_errors_from_tvr_mediated_risk_conditions")
        );
        assert!(fatal_vs_risk.contains("processing_restrictions_mutate_only_defined_tvr_bits"));

        let replay = csv_row_for_requirement(csv, "KRN-FSM-003").unwrap();
        assert!(replay.contains("replay_is_exact_order_and_evidence_is_masked"));
        assert!(replay.contains("replay_rejects_step_count_overflow"));
        assert!(replay.contains("replay_rejects_apdu_payloads_above_max_bytes"));
        assert!(replay.contains("generic_response_trace_rejects_malformed_tlv_payloads"));
        assert!(replay.contains("deterministic_replay_matches_script_order_and_emits_masked_jsonl"));

        let async_failures = csv_row_for_requirement(csv, "KRN-FSM-004").unwrap();
        assert!(async_failures.contains("asynchronous_failures_are_explicit_error_transitions"));
        assert!(async_failures
            .contains("krn_api_007_err_002_preserves_callback_error_codes_fail_closed"));
    }
}

#[test]
fn rtm_promotes_logging_policy_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-LOG-002", "KRN-LOG-003", "KRN-LOG-004"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete logging policy evidence"
            );
            assert!(row.contains("rtm_promotes_logging_policy_evidence"));
        }

        let production = csv_row_for_requirement(csv, "KRN-LOG-002").unwrap();
        assert!(production
            .contains("production_policy_never_emits_full_apdu_data_even_if_misconfigured"));
        assert!(production.contains("replay_is_exact_order_and_evidence_is_masked"));

        let crash_dump = csv_row_for_requirement(csv, "KRN-LOG-003").unwrap();
        assert!(crash_dump.contains("command_apdu_debug_redacts_payload_bytes"));
        assert!(crash_dump.contains("contactless_debug_redacts_outcome_and_relay_records"));
        assert!(crash_dump.contains("profile_debug_redacts_capk_and_profile_material"));
        assert!(crash_dump.contains("offline_pin_debug_redacts_ped_handle_values"));
        assert!(crash_dump.contains("datastore_debug_redacts_values_for_crash_safety"));
        assert!(crash_dump.contains("online_authorization_debug_redacts_cryptograms_and_card_data"));
        assert!(
            crash_dump.contains("host_response_debug_redacts_issuer_authentication_and_scripts")
        );
        assert!(crash_dump.contains("oda_debug_redacts_recovered_authentication_material"));
        assert!(crash_dump.contains("tlv_debug_redacts_parsed_values"));
        assert!(crash_dump.contains("mask_tlv_stream_rejects_trace_field_overflow"));
        assert!(crash_dump.contains("apdu_trace_debug_redacts_masked_payloads_for_crash_safety"));
        assert!(crash_dump.contains("replay_debug_redacts_raw_apdu_bytes_for_crash_safety"));
        assert!(crash_dump.contains("replay_rejects_pin_verify_payload_custody"));

        let identity = csv_row_for_requirement(csv, "KRN-LOG-004").unwrap();
        assert!(identity
            .contains("replay_trace_identity_records_profile_version_without_unmasking_data"));
        assert!(
            identity.contains("deterministic_replay_matches_script_order_and_emits_masked_jsonl")
        );
    }
}

#[test]
fn rtm_promotes_gac_cdol_encoding_and_response_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-GAC-001",
            "KRN-GAC-002",
            "KRN-GAC-003",
            "KRN-GAC-004",
            "KRN-GAC1-001",
            "KRN-GAC1-002",
            "KRN-GAC1-003",
            "KRN-GAC1-004",
            "KRN-GAC1-005",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete GAC evidence"
            );
        }

        let cdol = csv_row_for_requirement(csv, "KRN-GAC-001").unwrap();
        assert!(cdol.contains("krn_gac_001_gac1_002_cdol_data_matches_active_dol_definitions"));

        let p1 = csv_row_for_requirement(csv, "KRN-GAC-002").unwrap();
        assert!(p1.contains("encodes_generate_ac_type_bits_without_cda_collision"));
        assert!(p1.contains("krn_gac_008_009_cda_control_never_changes_type_bits"));

        let no_first_gac_flag = csv_row_for_requirement(csv, "KRN-GAC-003").unwrap();
        assert!(no_first_gac_flag.contains("krn_gac_008_009_cda_control_never_changes_type_bits"));

        let response = csv_row_for_requirement(csv, "KRN-GAC-004").unwrap();
        assert!(response.contains("parses_generate_ac_format_1_template_80"));
        assert!(response.contains("parses_generate_ac_format_2_template_77"));
        assert!(response.contains("rejects_generate_ac_without_single_supported_response_template"));
        assert!(response.contains("rejects_nested_or_duplicate_generate_ac_format_2_data"));
        assert!(response.contains("decodes_cryptogram_type_with_0xc0_mask"));

        let cdol1 = csv_row_for_requirement(csv, "KRN-GAC1-002").unwrap();
        assert!(cdol1.contains("krn_gac_001_gac1_002_cdol_data_matches_active_dol_definitions"));

        let cdol_defaults = csv_row_for_requirement(csv, "KRN-GAC1-001").unwrap();
        assert!(cdol_defaults.contains("first_gac_uses_profile_default_cdol1_when_card_omits_8c"));
        assert!(cdol_defaults.contains("rejects_malformed_default_cdol1"));

        let taa_request = csv_row_for_requirement(csv, "KRN-GAC1-003").unwrap();
        assert!(taa_request.contains(
            "krn_taa_001_002_003_004_005_006_007_uses_iac_tac_order_and_profile_fallbacks"
        ));

        let format = csv_row_for_requirement(csv, "KRN-GAC1-004").unwrap();
        assert!(format.contains("gac_parsing_uses_card_returned_cryptogram_for_online_handoff"));
        assert!(format.contains("rejects_generate_ac_without_single_supported_response_template"));
        assert!(format.contains("rejects_nested_or_duplicate_generate_ac_format_2_data"));

        let cda = csv_row_for_requirement(csv, "KRN-GAC1-005").unwrap();
        assert!(cda.contains("runtime_cda_verifies_first_gac_signed_dynamic_data"));
        assert!(cda.contains("runtime_cda_failure_sets_tvr_without_falling_back_to_dda"));
        assert!(cda.contains("runtime_cda_missing_signed_dynamic_data_sets_tvr_for_online_handoff"));
    }
}

#[test]
fn rtm_promotes_trm_floor_random_and_tsi_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-TRM-001", "KRN-TRM-002", "KRN-TRM-004"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete TRM evidence"
            );
            assert!(row.contains("trm_sets_floor_random_velocity_exception_and_tsi_bits"));
        }

        let floor = csv_row_for_requirement(csv, "KRN-TRM-001").unwrap();
        assert!(floor.contains("evaluates_floor_exception_velocity_random_and_merchant_bits"));
        assert!(floor
            .contains("ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac"));

        let random = csv_row_for_requirement(csv, "KRN-TRM-002").unwrap();
        assert!(random.contains("random_selection_is_deterministic_from_external_sample"));
        assert!(random.contains("rejects_invalid_profile_percent"));

        let tsi = csv_row_for_requirement(csv, "KRN-TRM-004").unwrap();
        assert!(tsi.contains("evaluates_floor_exception_velocity_random_and_merchant_bits"));
    }
}

#[test]
fn rtm_promotes_nonvolatile_offline_counter_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let counters = csv_row_for_requirement(csv, "KRN-TRM-003").expect("RTM row exists");
        assert!(
            !counters.contains("pending implementation evidence"),
            "KRN-TRM-003 should cite concrete non-volatile counter evidence"
        );
        assert!(counters
            .contains("requires_nonvolatile_offline_counter_when_velocity_limits_are_active"));
        assert!(counters.contains("trm_003_requires_nonvolatile_counter_for_velocity_limits"));
        assert!(counters.contains("krn_set_nonvolatile_offline_counter"));
        assert!(counters.contains("rtm_promotes_nonvolatile_offline_counter_evidence"));
    }
}

#[test]
fn rtm_promotes_tsi_phase_gating_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-TSI-002").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-TSI-002 should cite concrete phase-gated TSI evidence"
        );
        assert!(row.contains("tsi_bits_are_set_only_after_corresponding_processing"));
        assert!(
            row.contains("ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac")
        );
        assert!(row.contains("issuer_authentication_failure_sets_tvr_and_reaches_scripts"));
        assert!(row.contains("issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final"));
        assert!(row.contains("rtm_promotes_tsi_phase_gating_evidence"));
    }
}

#[test]
fn rtm_promotes_processing_restriction_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-REST-001", "KRN-REST-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete processing-restriction evidence"
            );
            assert!(row.contains("restriction_checks_follow_emv_order_and_use_standard_tvr_bits"));
            assert!(row.contains("processing_restrictions_mutate_only_defined_tvr_bits"));
            assert!(row.contains("rtm_promotes_processing_restriction_evidence"));
        }

        let order = csv_row_for_requirement(csv, "KRN-REST-001").unwrap();
        assert!(order.contains("evaluates_version_dates_auc_and_new_card_bits"));

        let non_standard = csv_row_for_requirement(csv, "KRN-REST-002").unwrap();
        assert!(non_standard.contains("does_not_set_non_standard_bits_for_allowed_transaction"));
    }
}

#[test]
fn rtm_promotes_pin_verify_warning_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-PIN-004").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-PIN-004 should cite concrete VERIFY warning evidence"
        );
        assert!(row.contains("verify_and_script_status_words_keep_their_own_meaning"));
        assert!(row.contains("offline_pin_verify_status_updates_cvm_results_and_tvr_bits"));
        assert!(row.contains("krn_pin_004_verify_63cx_updates_try_counter_tvr_and_cvm_results"));
        assert!(row.contains("rtm_promotes_pin_verify_warning_evidence"));
    }
}

#[test]
fn rtm_promotes_ped_handle_boundary_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-PINAPI-001").expect("RTM row exists");
        assert!(
            !row.contains("pending implementation evidence"),
            "KRN-PINAPI-001 should cite concrete PED handle boundary evidence"
        );
        assert!(row.contains("offline_pin_requires_ped_owned_opaque_handle"));
        assert!(row.contains("offline_pin_debug_redacts_ped_handle_values"));
        assert!(row.contains("krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles"));
        assert!(row.contains("rtm_promotes_ped_handle_boundary_evidence"));
    }
}

#[test]
fn rtm_promotes_api_abi_and_callback_validation_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-API-001", "KRN-API-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete ABI validation evidence"
            );
            assert!(row.contains("krn_api_001_002_rejects_bad_abi_before_optional_fields"));
            assert!(
                row.contains("krn_api_001_002_004_006_runtime_callbacks_are_versioned_and_bounded")
            );
        }

        let callbacks = csv_row_for_requirement(csv, "KRN-API-002").unwrap();
        assert!(callbacks
            .contains("ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac"));

        let amount_currency = csv_row_for_requirement(csv, "KRN-API-003").unwrap();
        assert!(
            !amount_currency.contains("pending implementation evidence"),
            "KRN-API-003 should cite minor-unit and currency exponent evidence"
        );
        assert!(
            amount_currency.contains("transaction_params_bind_minor_units_to_currency_exponent")
        );

        let caller_buffers = csv_row_for_requirement(csv, "KRN-API-005").unwrap();
        assert!(
            !caller_buffers.contains("Memory analysis"),
            "KRN-API-005 should cite executable caller-owned buffer evidence"
        );
        assert!(caller_buffers.contains(
            "krn_api_005_caller_owned_output_buffers_are_probeable_and_not_partially_written"
        ));
        assert!(caller_buffers.contains("ffi_builds_select_into_caller_buffer"));
        assert!(caller_buffers.contains("ffi_reports_buffer_size_without_writing"));
        assert!(caller_buffers.contains("ffi_write_output_handles_empty_outputs_without_buffer"));
        assert!(caller_buffers.contains("rtm_promotes_api_abi_and_callback_validation_evidence"));
    }
}

#[test]
fn rtm_promotes_api_error_boundary_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let reentrant = csv_row_for_requirement(csv, "KRN-API-004").expect("RTM row exists");
        assert!(
            !reentrant.contains("Concurrency test"),
            "KRN-API-004 should cite executable reentrancy evidence"
        );
        assert!(reentrant.contains("krn_api_004_rejects_reentrant_mutating_entrypoints"));
        assert!(reentrant
            .contains("krn_api_001_002_004_006_runtime_callbacks_are_versioned_and_bounded"));
        assert!(reentrant.contains("rtm_promotes_api_error_boundary_evidence"));

        let callbacks = csv_row_for_requirement(csv, "KRN-API-006").expect("RTM row exists");
        assert!(
            !callbacks.contains("Callback timeout trace"),
            "KRN-API-006 should cite executable callback timeout and runtime evidence"
        );
        assert!(callbacks
            .contains("krn_api_001_002_004_006_runtime_callbacks_are_versioned_and_bounded"));
        assert!(callbacks.contains(
            "krn_api_006_007_run_transaction_entrypoint_errors_without_runtime_callbacks"
        ));
        assert!(
            callbacks.contains("krn_api_007_err_002_preserves_callback_error_codes_fail_closed")
        );
        assert!(callbacks.contains("rtm_promotes_api_error_boundary_evidence"));

        let last_error = csv_row_for_requirement(csv, "KRN-API-007").expect("RTM row exists");
        assert!(
            !last_error.contains("Last-error ABI query"),
            "KRN-API-007 should cite executable last-error evidence"
        );
        assert!(last_error.contains(
            "krn_api_006_007_run_transaction_entrypoint_errors_without_runtime_callbacks"
        ));
        assert!(
            last_error.contains("krn_api_007_err_002_preserves_callback_error_codes_fail_closed")
        );
        assert!(last_error.contains("krn_err_001_exposes_stable_abi_error_table"));
        assert!(last_error.contains("rtm_promotes_api_error_boundary_evidence"));

        let error_table = csv_row_for_requirement(csv, "KRN-ERR-001").expect("RTM row exists");
        assert!(
            !error_table.contains("ABI error table query"),
            "KRN-ERR-001 should cite executable stable error table evidence"
        );
        assert!(error_table.contains("krn_err_001_exposes_stable_abi_error_table"));
        assert!(error_table.contains("ffi_exposes_stable_error_table"));
        assert!(error_table.contains("rtm_promotes_api_error_boundary_evidence"));

        let fail_closed = csv_row_for_requirement(csv, "KRN-ERR-002").expect("RTM row exists");
        assert!(
            !fail_closed.contains("Callback failure injection"),
            "KRN-ERR-002 should cite executable fail-closed callback evidence"
        );
        assert!(
            fail_closed.contains("krn_api_007_err_002_preserves_callback_error_codes_fail_closed")
        );
        assert!(fail_closed.contains("asynchronous_failures_are_explicit_error_transitions"));
        assert!(fail_closed.contains("rtm_promotes_api_error_boundary_evidence"));
    }
}

#[test]
fn krn_dpl_001_002_003_profile_updates_are_monotonic_and_atomic() {
    unsafe {
        let ctx = krn_context_new();
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

        let mut version = 0u64;
        assert_eq!(
            krn_get_profile_version(ctx, &mut version),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(version, 2);

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
            hyperion_emv::KernelError::InvalidProfile.code()
        );
        assert_eq!(
            krn_get_profile_version(ctx, &mut version),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(version, 2);

        assert_eq!(
            krn_load_profiles_verified(
                ctx,
                SCHEME_PROFILES.as_ptr(),
                SCHEME_PROFILES.len(),
                2,
                2,
                26,
                5,
                21,
            ),
            hyperion_emv::KernelError::InvalidProfile.code()
        );
        assert_eq!(
            krn_get_profile_version(ctx, &mut version),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(version, 2);

        let malformed = br#"{"profile_class":"CERTIFICATION","scheme_profiles":[]}"#;
        assert_eq!(
            krn_load_profiles_verified(ctx, malformed.as_ptr(), malformed.len(), 2, 3, 26, 5, 21,),
            hyperion_emv::KernelError::InvalidProfile.code()
        );
        assert_eq!(
            krn_get_profile_version(ctx, &mut version),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(version, 2);

        assert_eq!(
            krn_load_profiles_verified(
                ctx,
                SCHEME_PROFILES.as_ptr(),
                SCHEME_PROFILES.len(),
                2,
                3,
                26,
                5,
                21,
            ),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            krn_get_profile_version(ctx, &mut version),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(version, 3);
        krn_context_free(ctx);
    }
}

#[test]
fn rtm_promotes_deployment_profile_update_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let signed_update = csv_row_for_requirement(csv, "KRN-DPL-001").expect("RTM row exists");
        assert!(
            !signed_update.contains("Verified profile update trace"),
            "KRN-DPL-001 should cite executable signed profile update evidence"
        );
        assert!(signed_update.contains("loads_profile_annex_when_signature_is_verified"));
        assert!(
            signed_update.contains("rejects_unsigned_certification_profile_rollback_and_replay")
        );
        assert!(
            signed_update.contains("krn_dpl_001_002_003_profile_updates_are_monotonic_and_atomic")
        );
        assert!(signed_update.contains("rtm_promotes_deployment_profile_update_evidence"));

        let rollback = csv_row_for_requirement(csv, "KRN-DPL-002").expect("RTM row exists");
        assert!(
            !rollback.contains("Monotonic version check"),
            "KRN-DPL-002 should cite executable rollback and replay evidence"
        );
        assert!(rollback.contains("rejects_unsigned_certification_profile_rollback_and_replay"));
        assert!(rollback.contains("profile_loader_rejects_rollback_placeholders_and_expired_capks"));
        assert!(rollback.contains("krn_dpl_001_002_003_profile_updates_are_monotonic_and_atomic"));
        assert!(rollback.contains("rtm_promotes_deployment_profile_update_evidence"));

        let atomic_update = csv_row_for_requirement(csv, "KRN-DPL-003").expect("RTM row exists");
        assert!(
            !atomic_update.contains("Failed update preservation test"),
            "KRN-DPL-003 should cite executable atomic update evidence"
        );
        assert!(
            atomic_update.contains("krn_dpl_001_002_003_profile_updates_are_monotonic_and_atomic")
        );
        assert!(atomic_update.contains("rtm_promotes_deployment_profile_update_evidence"));

        let trace_identity = csv_row_for_requirement(csv, "KRN-DPL-004").expect("RTM row exists");
        assert!(
            !trace_identity.contains("Trace identity metadata"),
            "KRN-DPL-004 should cite executable profile identity evidence"
        );
        assert!(trace_identity.contains("ffi_reports_loaded_profile_version_for_log_identity"));
        assert!(trace_identity
            .contains("replay_trace_identity_records_profile_version_without_unmasking_data"));
        assert!(trace_identity
            .contains("deterministic_replay_matches_script_order_and_emits_masked_jsonl"));
        assert!(trace_identity.contains("rtm_promotes_deployment_profile_update_evidence"));
    }
}

#[test]
fn profile_loader_rejects_example_only_profiles_for_certification_policy() {
    let example_profile = br#"{
      "profile_class": "EXAMPLE_ONLY",
      "profile_source": {
        "owner": "engineering",
        "document": "example_profile",
        "version": "1",
        "verification": "test_only"
      },
      "scheme_profiles": [{
        "scheme_name": "Visa",
        "rid": "A000000003",
        "kernel_type": "c8_contactless",
        "contact_kernel_type": "legacy_visa",
        "taa_fallback_when_offline_unable_online": "AAC",
        "taa_no_match_default_when_online_capable": "ARQC",
        "taa_no_match_default_when_offline_only": "AAC",
        "aids": [{
          "aid": "A0000000031010",
          "priority": 10,
          "partial_selection": true,
          "interfaces": ["contact"],
          "tac_online": "E0F8C80000",
          "tac_denial": "0000000000",
          "tac_default": "8000000000",
          "iac_online": "0000000000",
          "iac_denial": "0000000000",
          "iac_default": "0000000000",
          "floor_limit": 0,
          "cvm_limit_contact": 0,
          "random_selection_percent": 0,
          "contactless_transaction_limit": 0,
          "contactless_cvm_limit": 0,
          "cdcvm_supported": false,
          "cda_supported": false
        }],
        "capks": [{
          "key_index": 1,
          "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
          "exponent_hex": "010001",
          "expiry": "2030-12-31",
          "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5"
        }]
      }]
    }"#;
    let cert_policy = ConfigLoadPolicy {
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
    assert_eq!(
        load_profile_set(example_profile, &cert_policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let test_policy = ConfigLoadPolicy {
        mode: BuildMode::Test,
        signature_status: SignatureStatus::NotPresent,
        ..cert_policy
    };
    let profiles = load_profile_set(example_profile, &test_policy).unwrap();
    assert_eq!(profiles.profile_class, ProfileClass::ExampleOnly);
}

#[test]
fn tlv_catalogue_contains_required_foundation_tags() {
    for row_prefix in [
        "5F36,", "84,", "94,", "95,", "9B,", "9F26,", "9F27,", "9F37,",
    ] {
        assert!(
            TLV_CATALOGUE
                .lines()
                .any(|line| line.starts_with(row_prefix)),
            "missing TLV catalogue row {row_prefix}"
        );
    }
}

#[test]
fn bitmap_catalogue_defines_tvr_tsi_symbols_and_rfu_masks() {
    let expected_header = [
        "indicator",
        "byte",
        "bit",
        "mask",
        "symbol",
        "meaning",
        "set_by",
        "test_id",
    ];
    let mut lines = BITMAP_CATALOGUE.lines();
    let header = lines.next().expect("bitmap catalogue header");
    assert_eq!(header.split(',').collect::<Vec<_>>(), expected_header);
    assert!(LAB_SUBMISSION_MANIFEST.contains("bitmap_catalogue.csv"));

    let rows = lines
        .map(|line| line.split(',').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 56);
    let mut keys = BTreeSet::new();
    let mut tvr_masks = [0u8; 5];
    let mut tsi_masks = [0u8; 2];

    for row in &rows {
        assert_eq!(
            row.len(),
            expected_header.len(),
            "invalid bitmap row {row:?}"
        );
        assert!(matches!(row[0], "TVR" | "TSI"));
        assert_eq!(row[7], "KRN-BIT-001");
        assert!(
            keys.insert((row[0], row[1], row[2])),
            "duplicate row {row:?}"
        );

        let byte = row[1].parse::<usize>().unwrap();
        let bit = row[2].parse::<u8>().unwrap();
        let mask = u8::from_str_radix(row[3].trim_start_matches("0x"), 16).unwrap();
        assert!((1..=8).contains(&bit));
        assert_eq!(mask, 1u8 << (bit - 1));
        assert!(!row[4].is_empty());

        if !row[4].starts_with("RFU_") {
            match row[0] {
                "TVR" => tvr_masks[byte - 1] |= mask,
                "TSI" => tsi_masks[byte - 1] |= mask,
                _ => unreachable!(),
            }
        }
    }

    assert_eq!(tvr_masks, Tvr::ALLOWED_MASKS);
    assert_eq!(tsi_masks, Tsi::ALLOWED_MASKS);

    for symbol in [
        "B1_OFFLINE_DATA_AUTH_NOT_PERFORMED",
        "B1_SDA_FAILED",
        "B1_ICC_DATA_MISSING",
        "B1_CARD_ON_EXCEPTION_FILE",
        "B1_DDA_FAILED",
        "B1_CDA_FAILED",
        "B2_DIFFERENT_APPLICATION_VERSIONS",
        "B2_EXPIRED_APPLICATION",
        "B2_APPLICATION_NOT_YET_EFFECTIVE",
        "B2_REQUESTED_SERVICE_NOT_ALLOWED",
        "B2_NEW_CARD",
        "B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL",
        "B3_UNRECOGNIZED_CVM",
        "B3_PIN_TRY_LIMIT_EXCEEDED",
        "B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING",
        "B3_PIN_NOT_ENTERED",
        "B3_ONLINE_PIN_ENTERED",
        "B4_FLOOR_LIMIT_EXCEEDED",
        "B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED",
        "B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED",
        "B4_RANDOM_TRANSACTION_SELECTION_PERFORMED",
        "B4_MERCHANT_FORCED_TRANSACTION_ONLINE",
        "B5_ISSUER_AUTHENTICATION_FAILED",
        "B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC",
        "B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC",
        "OFFLINE_DATA_AUTHENTICATION_PERFORMED",
        "CARDHOLDER_VERIFICATION_PERFORMED",
        "CARD_RISK_MANAGEMENT_PERFORMED",
        "ISSUER_AUTHENTICATION_PERFORMED",
        "TERMINAL_RISK_MANAGEMENT_PERFORMED",
        "SCRIPT_PROCESSING_PERFORMED",
    ] {
        assert!(
            rows.iter().any(|row| row[4] == symbol),
            "bitmap catalogue missing {symbol}"
        );
    }
}

#[test]
fn implementation_uses_symbolic_bitmap_setters() {
    for entry in fs::read_dir("src").unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs")
            || path.file_name().and_then(|name| name.to_str()) == Some("state.rs")
        {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        for forbidden in ["tvr.set((", "tsi.set((", "tvr.is_set((", "tsi.is_set(("] {
            assert!(
                !source.contains(forbidden),
                "{} contains raw bitmap access pattern {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn tlv_catalogue_uses_required_schema_and_profile_defined_markers() {
    let expected_header = [
        "Tag",
        "Name",
        "Type",
        "Length Rule",
        "Source",
        "Interface Applicability",
        "Scheme Applicability",
        "Presence Rule",
        "Sensitive Data Classification",
        "Test IDs",
    ];
    let mut lines = TLV_CATALOGUE.lines();
    let header = lines.next().expect("TLV catalogue header");
    assert_eq!(header.split(',').collect::<Vec<_>>(), expected_header);
    assert!(include_str!("../docs/spec.md").contains(&expected_header.join(",")));
    assert!(LAB_SUBMISSION_MANIFEST.contains("required 10-column schema"));

    let rows = lines
        .map(|line| line.split(',').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 59);
    for row in &rows {
        assert_eq!(row.len(), expected_header.len(), "invalid TLV row {row:?}");
        assert!(row[0].chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(!row[9].is_empty(), "missing test IDs for {}", row[0]);
    }

    for tag in ["8C", "8D", "9F49"] {
        let row = rows.iter().find(|row| row[0] == tag).unwrap();
        assert_eq!(row[2], "Data Object List");
        assert_eq!(row[3], "tag-length pairs");
    }

    for tag in ["5F5A", "5F5D", "9F10", "9F5A", "9F6C", "9F66", "9F6E"] {
        let row = rows.iter().find(|row| row[0] == tag).unwrap();
        assert_eq!(row[6], "PROFILE-DEFINED");
        assert_ne!(row[8], "non-sensitive");
    }

    for tag in ["57", "5A", "5F20", "5F34"] {
        let row = rows.iter().find(|row| row[0] == tag).unwrap();
        assert_eq!(row[8], "cardholder-data");
    }
}

#[test]
fn krn_dol_001_002_builds_requested_lengths_with_explicit_padding_policy() {
    let entries = parse_dol(&[0x9f, 0x37, 0x04, 0x95, 0x05, 0x5f, 0x2a, 0x02]).unwrap();
    let mut data = DataStore::new();
    data.put(&[0x9f, 0x37], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        .unwrap();
    data.put(&[0x95], &[0x80, 0x00, 0x00]).unwrap();

    assert_eq!(
        build_dol_with_policy(&entries, &data, DolPaddingPolicy::ZeroPadMissingAndShort).unwrap(),
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]
    );
    assert_eq!(
        build_dol_with_policy(&entries, &data, DolPaddingPolicy::RequireExactValues).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );

    data.put(&[0x95], &[0x80, 0x00, 0x00, 0x00, 0x00]).unwrap();
    data.put(&[0x5f, 0x2a], &[0x08, 0x40]).unwrap();
    let exact =
        build_dol_with_policy(&entries, &data, DolPaddingPolicy::RequireExactValues).unwrap();
    assert_eq!(
        exact,
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0x80, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40]
    );

    let command = generate_ac(
        CryptogramRequest::Arqc,
        &exact,
        CdaRequestControl::NotRequested,
    )
    .unwrap();
    assert_eq!(command.data, exact);
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
fn krn_gac_001_gac1_002_cdol_data_matches_active_dol_definitions() {
    let cdol1 = parse_dol(&[
        0x9f, 0x37, 0x04, 0x95, 0x05, 0x9f, 0x02, 0x06, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x1a, 0x02,
        0x9f, 0x34, 0x03,
    ])
    .unwrap();
    let mut data = DataStore::new();
    data.put(&[0x9f, 0x37], &[0x01, 0x02, 0x03, 0x04]).unwrap();
    data.put(&[0x95], &[0x80, 0x00, 0x00, 0x00, 0x00]).unwrap();
    data.put(&[0x9f, 0x02], &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00])
        .unwrap();
    data.put(&[0x9a], &[0x26, 0x05, 0x21]).unwrap();
    data.put(&[0x9c], &[0x00]).unwrap();
    data.put(&[0x9f, 0x1a], &[0x08, 0x40]).unwrap();
    data.put(&[0x9f, 0x34], &[0x01, 0x00, 0x02]).unwrap();

    let cdol1_values =
        build_dol_with_policy(&cdol1, &data, DolPaddingPolicy::RequireExactValues).unwrap();
    assert_eq!(
        cdol1_values,
        hex("010203048000000000000000000100260521000840010002")
    );
    let first_gac = generate_ac(
        CryptogramRequest::Arqc,
        &cdol1_values,
        CdaRequestControl::NotRequested,
    )
    .unwrap();
    assert_eq!(first_gac.p1, 0x80);
    assert_eq!(first_gac.data, cdol1_values);

    let cdol2 = parse_dol(&[0x8a, 0x02, 0x91, 0x0a, 0x95, 0x05, 0x9b, 0x02]).unwrap();
    data.put(&[0x8a], b"00").unwrap();
    data.put(
        &[0x91],
        &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04],
    )
    .unwrap();
    data.put(&[0x9b], &[0xe8, 0x00]).unwrap();

    let cdol2_values =
        build_dol_with_policy(&cdol2, &data, DolPaddingPolicy::RequireExactValues).unwrap();
    assert_eq!(cdol2_values, hex("3030AABBCCDDEEFF010203048000000000E800"));
    let final_gac = generate_ac(
        CryptogramRequest::Tc,
        &cdol2_values,
        CdaRequestControl::NotRequested,
    )
    .unwrap();
    assert_eq!(final_gac.p1, 0x40);
    assert_eq!(final_gac.data, cdol2_values);
}

#[test]
fn krn_gac_010_cda_request_is_profile_defined_or_unsupported() {
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
    let visa_aid = &profiles.schemes[0].aids[0];
    assert_eq!(
        visa_aid.cda_request_encoding,
        Some(CdaRequestEncoding::InCdolData)
    );
    assert!(visa_aid.cda_allowed_by_profile());
    let mastercard_aid = &profiles.schemes[1].aids[0];
    assert_eq!(
        mastercard_aid.cda_request_encoding,
        Some(CdaRequestEncoding::P1LowBits(0x10))
    );
    assert!(mastercard_aid.cda_allowed_by_profile());

    let missing_encoding = br#"{
      "profile_class": "CERTIFICATION",
      "profile_source": {
        "owner": "scheme_or_acquirer",
        "document": "signed_certification_profile_bundle",
        "version": "2",
        "verification": "external_signature_required"
      },
      "scheme_profiles": [{
        "scheme_name": "Visa",
        "rid": "A000000003",
        "kernel_type": "c8_contactless",
        "contact_kernel_type": "legacy_visa",
        "taa_fallback_when_offline_unable_online": "AAC",
        "taa_no_match_default_when_online_capable": "ARQC",
        "taa_no_match_default_when_offline_only": "AAC",
        "aids": [{
          "aid": "A0000000031010",
          "priority": 10,
          "partial_selection": true,
          "interfaces": ["contact", "contactless"],
          "tac_online": "E0F8C80000",
          "tac_denial": "0000000000",
          "tac_default": "8000000000",
          "iac_online": "0000000000",
          "iac_denial": "0000000000",
          "iac_default": "0000000000",
          "floor_limit": 0,
          "cvm_limit_contact": 5000,
          "random_selection_percent": 5,
          "contactless_transaction_limit": 5000,
          "contactless_cvm_limit": 3000,
          "cdcvm_supported": true,
          "cda_supported": true
        }],
        "capks": [{
          "key_index": 1,
          "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
          "exponent_hex": "010001",
          "expiry": "2030-12-31",
          "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5",
          "checksum_algorithm": "sha1(rid || key_index || modulus || exponent)",
          "checksum_scope": ["rid", "key_index", "modulus_hex", "exponent_hex"],
          "source": {
            "owner": "scheme_or_acquirer",
            "document": "signed_certification_capk_bundle",
            "version": "2",
            "verification": "external_signature_required"
          }
        }]
      }]
    }"#;
    let profiles = load_profile_set(missing_encoding, &policy).unwrap();
    let aid = &profiles.schemes[0].aids[0];
    assert!(aid.cda_supported);
    assert!(!aid.cda_allowed_by_profile());

    let colliding_encoding = br#"{
      "profile_class": "CERTIFICATION",
      "profile_source": {
        "owner": "scheme_or_acquirer",
        "document": "signed_certification_profile_bundle",
        "version": "2",
        "verification": "external_signature_required"
      },
      "scheme_profiles": [{
        "scheme_name": "Visa",
        "rid": "A000000003",
        "kernel_type": "c8_contactless",
        "taa_fallback_when_offline_unable_online": "AAC",
        "taa_no_match_default_when_online_capable": "ARQC",
        "taa_no_match_default_when_offline_only": "AAC",
        "aids": [{
          "aid": "A0000000031010",
          "priority": 10,
          "partial_selection": true,
          "interfaces": ["contact"],
          "tac_online": "E0F8C80000",
          "tac_denial": "0000000000",
          "tac_default": "8000000000",
          "iac_online": "0000000000",
          "iac_denial": "0000000000",
          "iac_default": "0000000000",
          "floor_limit": 0,
          "cvm_limit_contact": 0,
          "random_selection_percent": 0,
          "contactless_transaction_limit": 0,
          "contactless_cvm_limit": 0,
          "cdcvm_supported": false,
          "cda_supported": true,
          "cda_request_encoding": "P1_low_bits_0x40"
        }],
        "capks": [{
          "key_index": 1,
          "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
          "exponent_hex": "010001",
          "expiry": "2030-12-31",
          "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5",
          "source": {
            "owner": "scheme_or_acquirer",
            "document": "signed_certification_capk_bundle",
            "version": "2",
            "verification": "external_signature_required"
          }
        }]
      }]
    }"#;
    assert_eq!(
        load_profile_set(colliding_encoding, &policy).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
}

#[test]
fn krn_cid_001_002_decodes_type_and_preserves_non_type_bits() {
    assert_eq!(Cid::new(0x8f).cryptogram_type(), CryptogramType::Arqc);
    assert_eq!(Cid::new(0x47).cryptogram_type(), CryptogramType::Tc);
    assert_eq!(Cid::new(0x0f).cryptogram_type(), CryptogramType::Aac);

    let cid = Cid::new(0x8f);
    assert_eq!(cid.raw(), 0x8f);
    assert_eq!(cid.cryptogram_type(), Cid::new(0x80).cryptogram_type());
    assert!(cid.advice_required());
    assert_eq!(cid.reason_advice_code(), 0x07);

    let response = parse_generate_ac_response(&hex(
        "771A9F27018F9F360200099F260811121314151617189F1003AABBCC",
    ))
    .unwrap();
    assert_eq!(response.cid.raw(), 0x8f);
    assert_eq!(response.cid.cryptogram_type(), CryptogramType::Arqc);

    let package = build_online_authorization_package(&response, &DataStore::new());
    let cid_object = package
        .objects
        .iter()
        .find(|object| object.tag == hex("9F27"))
        .expect("online package preserves CID object");
    assert_eq!(cid_object.value, vec![0x8f]);

    assert_eq!(
        parse_generate_ac_response(&hex("7716A5149F27018F9F360200099F26081112131415161718"))
            .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_generate_ac_response(&hex(
            "771F9F27018F9F360200099F260811121314151617189F26082021222324252627"
        ))
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
}

#[test]
fn rtm_promotes_cid_decode_and_preservation_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-CID-001", "KRN-CID-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete CID evidence"
            );
            assert!(row.contains("krn_cid_001_002_decodes_type_and_preserves_non_type_bits"));
        }

        let decode = csv_row_for_requirement(csv, "KRN-CID-001").unwrap();
        assert!(decode.contains("decodes_cryptogram_type_with_0xc0_mask"));

        let preserve = csv_row_for_requirement(csv, "KRN-CID-002").unwrap();
        assert!(
            preserve.contains("preserves_non_type_bits_without_changing_cryptogram_classification")
        );
        assert!(
            preserve.contains("builds_online_authorization_package_without_generating_cryptograms")
        );
    }
}

#[test]
fn rtm_promotes_legacy_gac_cda_control_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let p1 = csv_row_for_requirement(csv, "KRN-GAC-008").expect("RTM row exists");
        assert!(
            !p1.contains("APDU logs"),
            "KRN-GAC-008 should cite executable GENERATE AC P1 evidence"
        );
        assert!(p1.contains("encodes_generate_ac_type_bits_without_cda_collision"));
        assert!(p1.contains("krn_gac_008_009_cda_control_never_changes_type_bits"));
        assert!(p1.contains("rtm_promotes_legacy_gac_cda_control_evidence"));

        let cda_bits = csv_row_for_requirement(csv, "KRN-GAC-009").expect("RTM row exists");
        assert!(
            !cda_bits.contains("APDU + profile") && !cda_bits.contains("APDU logs"),
            "KRN-GAC-009 should cite executable CDA bit-control evidence"
        );
        assert!(cda_bits.contains("encodes_generate_ac_type_bits_without_cda_collision"));
        assert!(cda_bits.contains("cda_request_encoding_is_profile_defined_and_non_colliding"));
        assert!(cda_bits.contains("first_gac_cda_request_control_is_profile_defined"));
        assert!(cda_bits.contains("krn_gac_008_009_cda_control_never_changes_type_bits"));
        assert!(cda_bits.contains("rtm_promotes_legacy_gac_cda_control_evidence"));

        let cda_profile = csv_row_for_requirement(csv, "KRN-GAC-010").expect("RTM row exists");
        assert!(
            !cda_profile.contains("Profile validation"),
            "KRN-GAC-010 should cite executable profile-defined CDA evidence"
        );
        assert!(cda_profile.contains("cda_request_encoding_is_profile_defined_and_non_colliding"));
        assert!(cda_profile.contains("first_gac_cda_request_control_is_profile_defined"));
        assert!(cda_profile.contains("krn_gac_010_cda_request_is_profile_defined_or_unsupported"));
        assert!(cda_profile.contains("rtm_promotes_legacy_gac_cda_control_evidence"));
    }
}

#[test]
fn rtm_promotes_online_boundary_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-ONL-001", "KRN-ONL-002"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete online boundary evidence"
            );
            assert!(row.contains("rtm_promotes_online_boundary_evidence"));
        }

        let handoff = csv_row_for_requirement(csv, "KRN-ONL-001").unwrap();
        assert!(
            handoff.contains("builds_online_authorization_package_without_generating_cryptograms")
        );
        assert!(handoff.contains("online_authorization_package_rejects_tlv_output_above_limit"));
        assert!(handoff
            .contains("ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac"));

        let host = csv_row_for_requirement(csv, "KRN-ONL-002").unwrap();
        assert!(host.contains("parses_arpc_arc_and_issuer_scripts"));
        assert!(host.contains("rejects_malformed_issuer_authentication_data"));
        assert!(host.contains("rejects_nested_or_duplicate_host_response_auth_objects"));
        assert!(host.contains("apply_host_response_rejects_empty_or_oversize_payload"));
        assert!(host.contains("host_response_extracts_arpc_and_phase_specific_script_results"));
    }
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
    assert_eq!(
        parse_fci_candidate_aids(&hex("4F07A0000000031010")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert!(
        parse_fci_candidate_aids(&hex("6F0EA50CBF0C094F07A0000000031010"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        parse_fci_candidate_aids(&hex("6F17A515BF0C1261104F07A00000000310104F05A000000003"))
            .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_fci_candidate_aids(&hex(
            "6F1BA519BF0C1661094F07A000000003101061094F07A0000000031010"
        ))
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );

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
    assert_eq!(
        parse_pdol_from_fci(&hex("9F38039F3704")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert!(parse_pdol_from_fci(&hex("6F0BA509BF0C069F38039F3704"))
        .unwrap()
        .is_empty());
    assert_eq!(
        parse_pdol_from_fci(&hex("6F128407A0000000031010A5079F38009F38019F")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );

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
    assert_eq!(
        parse_gpo_response(&hex("770CA50A82021800940410010100")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert_eq!(
        parse_gpo_response(&hex("770E8202180082022000940410010100")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
}

#[test]
fn krn_dda_001_internal_authenticate_uses_ddol_values() {
    let ddol = parse_dol(&[0x9f, 0x37, 0x04, 0x9f, 0x4c, 0x02]).unwrap();
    let mut data = DataStore::new();
    data.put(&[0x9f, 0x37], &[0x21, 0x22, 0x23, 0x24]).unwrap();

    assert_eq!(
        internal_authenticate_from_ddol(&ddol, &data)
            .unwrap()
            .encode()
            .unwrap(),
        [0x00, 0x88, 0x00, 0x00, 0x06, 0x21, 0x22, 0x23, 0x24, 0x00, 0x00, 0x00]
    );

    unsafe {
        let ctx = krn_context_new();
        let ddol_values = [0x21, 0x22, 0x23, 0x24, 0x00, 0x00];
        let mut len = 0usize;
        assert_eq!(
            krn_build_internal_authenticate(
                ctx,
                ddol_values.as_ptr(),
                ddol_values.len(),
                ptr::null_mut(),
                &mut len,
            ),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut apdu = vec![0u8; len];
        assert_eq!(
            krn_build_internal_authenticate(
                ctx,
                ddol_values.as_ptr(),
                ddol_values.len(),
                apdu.as_mut_ptr(),
                &mut len,
            ),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            apdu,
            [0x00, 0x88, 0x00, 0x00, 0x06, 0x21, 0x22, 0x23, 0x24, 0x00, 0x00, 0x00]
        );
        krn_context_free(ctx);
    }
}

#[test]
fn krn_dda_002_oda_006_requires_signed_dynamic_application_data() {
    let response =
        parse_internal_authenticate_response(&hex("77129F4B08A1A2A3A4A5A6A7A89F4C0401020304"))
            .unwrap();
    assert_eq!(
        response.signed_dynamic_application_data,
        hex("A1A2A3A4A5A6A7A8")
    );
    assert_eq!(response.icc_dynamic_number, Some(hex("01020304")));

    assert_eq!(
        parse_internal_authenticate_response(&hex("77069F4C03010203")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert_eq!(
        parse_internal_authenticate_response(&hex("9F4B02AABB")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert_eq!(
        parse_internal_authenticate_response(&hex("9F4B08A1A2A3A4A5A6A7A8")).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert_eq!(
        parse_internal_authenticate_response(&hex("770DA50B9F4B08A1A2A3A4A5A6A7A8")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_internal_authenticate_response(&hex(
            "771D9F4B08A1A2A3A4A5A6A7A89F4C020102A50B9F4B08B1B2B3B4B5B6B7B8"
        ))
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_internal_authenticate_response(&hex(
            "77169F4B08A1A2A3A4A5A6A7A89F4B08B1B2B3B4B5B6B7B8"
        ))
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
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
            currency_exponent: 2,
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
fn krn_api_001_002_rejects_bad_abi_before_optional_fields() {
    unsafe {
        let mut ctx = ptr::null_mut();
        let bad_config = KrnConfigBlob {
            abi_version: KRN_ABI_VERSION + 1,
            struct_size: core::mem::size_of::<KrnConfigBlob>() as u32,
            bytes: ptr::null(),
            len: 1,
        };
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(&bad_config, &runtime, &mut ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert!(ctx.is_null());

        let bad_runtime_abi = KrnRuntime {
            abi_version: KRN_ABI_VERSION + 1,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: None,
            get_unpredictable_number: None,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(ptr::null(), &bad_runtime_abi, &mut ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert!(ctx.is_null());

        let short_runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: 0,
            transmit_apdu: None,
            get_unpredictable_number: None,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(ptr::null(), &short_runtime, &mut ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert!(ctx.is_null());

        let missing_callbacks = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: None,
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(ptr::null(), &missing_callbacks, &mut ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert!(ctx.is_null());

        assert_eq!(
            krn_init(ptr::null(), &runtime, &mut ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        let bad_params = KrnTxnParams {
            struct_size: 0,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 1,
        };
        assert_eq!(
            krn_set_transaction_params(ctx, &bad_params),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        krn_context_free(ctx);
    }
}

#[test]
fn krn_api_005_caller_owned_output_buffers_are_probeable_and_not_partially_written() {
    unsafe {
        let ctx = krn_context_new();

        let mut probe_len = 0usize;
        assert_eq!(
            krn_build_select_environment(ctx, false, ptr::null_mut(), &mut probe_len),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        assert_eq!(probe_len, 20);

        let mut short = [0xa5u8; 8];
        let mut short_len = short.len();
        assert_eq!(
            krn_build_select_environment(ctx, false, short.as_mut_ptr(), &mut short_len),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        assert_eq!(short_len, 20);
        assert_eq!(short, [0xa5u8; 8]);
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );

        let mut exact = [0u8; 20];
        let mut exact_len = exact.len();
        assert_eq!(
            krn_build_select_environment(ctx, false, exact.as_mut_ptr(), &mut exact_len),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(exact_len, exact.len());
        assert_eq!(
            exact.as_slice(),
            hex("00A404000E315041592E5359532E444446303100").as_slice()
        );
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::Ok.code()
        );

        assert_eq!(
            krn_build_select_environment(ctx, false, exact.as_mut_ptr(), ptr::null_mut()),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );

        krn_context_free(ctx);
    }
}

#[test]
fn krn_cert_004_penetration_rejects_apdu_injection_and_state_bypass() {
    unsafe {
        let mut ctx = ptr::null_mut();
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
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S0.code());

        let host_response = hex("8A023030");
        assert_eq!(
            krn_apply_host_response(ctx, host_response.as_ptr(), host_response.len()),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S0.code());

        let cdol_values = [0x00u8; 8];
        let mut out = [0u8; 32];
        let mut out_len = out.len();
        assert_eq!(
            krn_build_generate_ac(
                ctx,
                2,
                cdol_values.as_ptr(),
                cdol_values.len(),
                0x40,
                out.as_mut_ptr(),
                &mut out_len,
            ),
            hyperion_emv::KernelError::InvalidProfile.code()
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S0.code());

        IT_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        for bypass in [
            krn_process_issuer_authentication(ctx),
            krn_process_issuer_scripts(ctx),
            krn_process_final_generate_ac(ctx),
            krn_process_post_final_issuer_scripts(ctx),
        ] {
            assert_eq!(bypass, hyperion_emv::KernelError::InvalidArgument.code());
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S0.code());
        }
        assert_eq!(IT_TRANSMIT_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        krn_context_free(ctx);
    }
}

#[test]
fn krn_api_007_err_002_preserves_callback_error_codes_fail_closed() {
    unsafe {
        let mut ctx = ptr::null_mut();
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_host_timeout_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: ptr::null_mut(),
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
        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
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

        assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::HostTimeout.code()
        );
        assert_eq!(
            IT_TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst),
            hyperion_emv::ffi::APDU_TRANSMIT_TIMEOUT_MS
        );
        assert_eq!(krn_get_fsm_state(ctx), FsmState::Se.code());

        krn_context_free(ctx);

        let mut unknown_ctx = ptr::null_mut();
        let unknown_runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_unknown_error_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            krn_init(ptr::null(), &unknown_runtime, &mut unknown_ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            krn_load_profiles_verified(
                unknown_ctx,
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
        assert_eq!(
            krn_set_transaction_params(unknown_ctx, &params),
            hyperion_emv::KernelError::Ok.code()
        );

        assert_eq!(krn_run_transaction(unknown_ctx), KrnOutcome::Error as i32);
        assert_eq!(
            krn_get_last_error(unknown_ctx),
            hyperion_emv::KernelError::InternalError.code()
        );
        assert_eq!(krn_get_fsm_state(unknown_ctx), FsmState::Se.code());

        krn_context_free(unknown_ctx);
    }
}

#[test]
fn krn_pin_001_002_003_pinapi_001_002_cvmres_001_use_ped_owned_handles() {
    unsafe {
        let counter = AtomicUsize::new(0);
        let mut ctx = ptr::null_mut();
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_offline_pin_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: &counter as *const AtomicUsize as *mut c_void,
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
        assert_eq!(
            krn_set_offline_pin_handle(ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 0),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(
            krn_set_offline_pin_handle(ctx, 0xff, 42),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
        assert_eq!(
            krn_set_offline_pin_handle(ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 42),
            hyperion_emv::KernelError::Ok.code()
        );
        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
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
        assert_eq!(
            krn_set_offline_pin_handle(ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 42),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            krn_set_offline_pin_handle(ctx, KRN_PIN_METHOD_OFFLINE_ENCIPHERED, 43),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            krn_set_offline_pin_handle(ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 42),
            hyperion_emv::KernelError::Ok.code()
        );

        assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired as i32);
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
            tlv::find_first(&auth_tlvs, &[0x9f, 0x34]),
            Some(&[0x01, 0x00, 0x02][..])
        );
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        krn_context_free(ctx);

        let enciphered_only = CvmPinHandles::with_offline_enciphered(PedPinHandle::new(7).unwrap());
        let cvm_list = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00]).unwrap();
        let context = CvmContext {
            amount_authorized: 1_500,
            transaction_currency_matches_application: true,
            interface: CvmInterface::Contact,
            offline_pin_supported: true,
            online_pin_supported: true,
            signature_supported: false,
            cdcvm_performed: false,
        };
        assert_eq!(
            evaluate_cvm(&cvm_list, context, enciphered_only),
            CvmOutcome::Failed {
                cvm_results: [0x01, 0x00, 0x01],
                tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
            }
        );
    }
}

#[test]
fn krn_pin_004_verify_63cx_updates_try_counter_tvr_and_cvm_results() {
    let rule = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00])
        .unwrap()
        .rules[0];

    let warning = apply_offline_pin_verify_status(rule, StatusWord::new(0x63, 0xc2)).unwrap();
    assert_eq!(warning.cvm_results, [0x01, 0x00, 0x01]);
    assert_eq!(warning.tries_remaining, Some(2));
    assert_eq!(
        warning.tvr_bit,
        Some(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL)
    );

    let exhausted = apply_offline_pin_verify_status(rule, StatusWord::new(0x63, 0xc0)).unwrap();
    assert_eq!(exhausted.cvm_results, [0x01, 0x00, 0x01]);
    assert_eq!(exhausted.tries_remaining, Some(0));
    assert_eq!(exhausted.tvr_bit, Some(Tvr::B3_PIN_TRY_LIMIT_EXCEEDED));

    let success = apply_offline_pin_verify_status(rule, StatusWord::new(0x90, 0x00)).unwrap();
    assert_eq!(success.cvm_results, [0x01, 0x00, 0x02]);
    assert_eq!(success.tries_remaining, None);
    assert_eq!(success.tvr_bit, None);

    assert_eq!(
        classify(ApduContext::Verify, StatusWord::new(0x63, 0xc3)),
        StatusAction::PinFailed { tries_remaining: 3 }
    );
}

unsafe fn run_cvm_capability_transaction(
    cvm_code: u8,
    online_pin_supported: u8,
    signature_supported: u8,
    cdcvm_performed: u8,
    interface_preference: u8,
) -> Vec<u8> {
    let script = CvmMethodScript {
        counter: AtomicUsize::new(0),
        cvm_code,
    };
    let mut ctx = ptr::null_mut();
    let runtime = KrnRuntime {
        abi_version: KRN_ABI_VERSION,
        struct_size: core::mem::size_of::<KrnRuntime>() as u32,
        transmit_apdu: Some(it_cvm_method_transmit_apdu),
        get_unpredictable_number: Some(it_unpredictable_number),
        contactless_outcome: None,
        user_data: &script as *const CvmMethodScript as *mut c_void,
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
    let params = KrnTxnParams {
        struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
        amount_authorised_minor: 1_500,
        amount_other_minor: 0,
        currency_code: 840,
        currency_exponent: 2,
        terminal_country_code: 840,
        transaction_type: 0,
        terminal_type: 0x22,
        merchant_category_code: [0x53, 0x11],
        interface_preference,
        merchant_name_location: ptr::null(),
        merchant_name_location_len: 0,
    };
    assert_eq!(
        krn_set_transaction_params(ctx, &params),
        hyperion_emv::KernelError::Ok.code()
    );
    assert_eq!(
        krn_set_cvm_capabilities(ctx, 2, 0, 0),
        hyperion_emv::KernelError::InvalidArgument.code()
    );
    assert_eq!(
        krn_set_cvm_capabilities(
            ctx,
            online_pin_supported,
            signature_supported,
            cdcvm_performed,
        ),
        hyperion_emv::KernelError::Ok.code()
    );
    assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired as i32);

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
    auth.truncate(auth_len);
    krn_context_free(ctx);
    auth
}

#[test]
fn krn_cvmcap_001_uses_terminal_cvm_capabilities_from_abi() {
    unsafe {
        assert_eq!(
            krn_set_cvm_capabilities(ptr::null_mut(), 0, 0, 0),
            hyperion_emv::KernelError::InvalidArgument.code()
        );

        let online_auth = run_cvm_capability_transaction(0x02, 1, 0, 0, 1);
        let online_tlvs = tlv::parse_many(&online_auth).unwrap();
        assert_eq!(
            tlv::find_first(&online_tlvs, &[0x9f, 0x34]),
            Some(&[0x02, 0x00, 0x02][..])
        );
        assert!(tlv::find_first(&online_tlvs, &[0x95])
            .is_some_and(|tvr| tvr.len() == 5 && tvr[2] & 0x04 != 0));

        let signature_auth = run_cvm_capability_transaction(0x06, 0, 1, 0, 1);
        let signature_tlvs = tlv::parse_many(&signature_auth).unwrap();
        assert_eq!(
            tlv::find_first(&signature_tlvs, &[0x9f, 0x34]),
            Some(&[0x06, 0x00, 0x02][..])
        );

        let cdcvm_auth = run_cvm_capability_transaction(0x20, 0, 0, 1, 2);
        let cdcvm_tlvs = tlv::parse_many(&cdcvm_auth).unwrap();
        assert_eq!(
            tlv::find_first(&cdcvm_tlvs, &[0x9f, 0x34]),
            Some(&[0x20, 0x00, 0x02][..])
        );
    }
}

#[test]
fn krn_termcap_001_supplies_9f33_to_pdol_and_online_handoff() {
    unsafe {
        assert_eq!(
            krn_set_terminal_capabilities(ptr::null_mut(), 0xe0, 0xb0, 0xc8),
            hyperion_emv::KernelError::InvalidArgument.code()
        );

        let script = TerminalCapabilitiesScript {
            counter: AtomicUsize::new(0),
            commands: Mutex::new(Vec::new()),
        };
        let mut ctx = ptr::null_mut();
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_terminal_capabilities_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: &script as *const TerminalCapabilitiesScript as *mut c_void,
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
        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
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
        assert_eq!(
            krn_set_terminal_capabilities(ctx, 0xe0, 0xb0, 0xc8),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired as i32);

        let commands = script.commands.lock().unwrap();
        assert!(
            commands
                .iter()
                .any(|command| command == &hex("80A80000098307E0B0C80102030400")),
            "GPO command did not include 9F33 PDOL bytes"
        );
        drop(commands);

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
            tlv::find_first(&auth_tlvs, &[0x9f, 0x33]),
            Some(&[0xe0, 0xb0, 0xc8][..])
        );
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        krn_context_free(ctx);
    }
}

#[test]
fn krn_ttq_001_supplies_9f66_to_contactless_pdol_and_online_handoff() {
    unsafe {
        assert_eq!(
            krn_set_terminal_transaction_qualifiers(ptr::null_mut(), 0x36, 0x00, 0x40, 0x00),
            hyperion_emv::KernelError::InvalidArgument.code()
        );

        let script = TerminalCapabilitiesScript {
            counter: AtomicUsize::new(0),
            commands: Mutex::new(Vec::new()),
        };
        let mut ctx = ptr::null_mut();
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_terminal_qualifiers_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: &script as *const TerminalCapabilitiesScript as *mut c_void,
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
        let params = KrnTxnParams {
            struct_size: core::mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_500,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 0,
        };
        assert_eq!(
            krn_set_transaction_params(ctx, &params),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(
            krn_set_terminal_transaction_qualifiers(ctx, 0x36, 0x00, 0x40, 0x00),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired as i32);

        let commands = script.commands.lock().unwrap();
        assert!(
            commands
                .iter()
                .any(|command| command == &hex("80A800000A8308360040000102030400")),
            "GPO command did not include 9F66 TTQ PDOL bytes"
        );
        drop(commands);

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
            tlv::find_first(&auth_tlvs, &[0x9f, 0x66]),
            Some(&[0x36, 0x00, 0x40, 0x00][..])
        );
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
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

        let script = TerminalCapabilitiesScript {
            counter: AtomicUsize::new(0),
            commands: Mutex::new(Vec::new()),
        };
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: core::mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(it_transmit_apdu),
            get_unpredictable_number: Some(it_unpredictable_number),
            contactless_outcome: None,
            user_data: &script as *const TerminalCapabilitiesScript as *mut c_void,
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
            currency_exponent: 2,
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
        assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired as i32);
        assert_eq!(script.counter.load(Ordering::SeqCst), 5);
        {
            let commands = script.commands.lock().unwrap();
            let command = commands.last().unwrap();
            assert_eq!(command[1], 0xae);
            assert_eq!(command.len(), 30);
        }
        assert!(IT_TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst) > 0);
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S11.code());
        assert_eq!(
            krn_get_last_error(ctx),
            hyperion_emv::KernelError::Ok.code()
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
        assert_eq!(script.counter.load(Ordering::SeqCst), 6);
        {
            let commands = script.commands.lock().unwrap();
            let command = commands.last().unwrap();
            assert_eq!(command[1], 0x82);
            assert_eq!(command.len(), 13);
        }
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S13.code());
        assert_eq!(
            krn_process_issuer_scripts(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(script.counter.load(Ordering::SeqCst), 7);
        {
            let commands = script.commands.lock().unwrap();
            let command = commands.last().unwrap();
            assert_eq!(command[1], 0xda);
            assert_eq!(command.len(), 6);
        }
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
        assert_eq!(script.counter.load(Ordering::SeqCst), 8);
        {
            let commands = script.commands.lock().unwrap();
            let command = commands.last().unwrap();
            assert_eq!(command[1], 0xae);
            assert_eq!(command.len(), 23);
        }
        assert_eq!(krn_get_fsm_state(ctx), FsmState::S15.code());
        assert_eq!(
            krn_get_final_outcome(ctx),
            KrnOutcome::ApprovedOnline as i32
        );
        assert_eq!(
            krn_process_post_final_issuer_scripts(ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(script.counter.load(Ordering::SeqCst), 9);
        {
            let commands = script.commands.lock().unwrap();
            let command = commands.last().unwrap();
            assert_eq!(command[1], 0xe2);
            assert_eq!(command.len(), 6);
        }
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
            currency_exponent: 2,
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
        IT_RNG_CALLBACK_COUNT.store(0, Ordering::SeqCst);
        let valid_apdu_counter = AtomicUsize::new(0);
        let valid_ctx = init_with_rng(it_counted_unpredictable_number, &valid_apdu_counter);
        set_params(valid_ctx);
        assert_eq!(
            krn_run_transaction(valid_ctx),
            KrnOutcome::OnlineRequired as i32
        );
        assert_eq!(
            krn_get_last_error(valid_ctx),
            hyperion_emv::KernelError::Ok.code()
        );
        assert_eq!(IT_RNG_CALLBACK_COUNT.load(Ordering::SeqCst), 1);
        krn_context_free(valid_ctx);

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
        assert_eq!(
            krn_run_transaction(repeated_ctx),
            KrnOutcome::OnlineRequired as i32
        );
        assert_eq!(
            krn_get_last_error(repeated_ctx),
            hyperion_emv::KernelError::Ok.code()
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
fn krn_log_001_exposes_masked_apdu_trace_json_via_abi() {
    unsafe {
        let verify_pin = hex("0020008008241234FFFFFFFFFF");
        let mut len = 0usize;
        assert_eq!(
            krn_mask_apdu_command_json(
                verify_pin.as_ptr(),
                verify_pin.len(),
                true,
                ptr::null_mut(),
                &mut len
            ),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut json = vec![0u8; len];
        assert_eq!(
            krn_mask_apdu_command_json(
                verify_pin.as_ptr(),
                verify_pin.len(),
                true,
                json.as_mut_ptr(),
                &mut len,
            ),
            hyperion_emv::KernelError::Ok.code()
        );
        let json = String::from_utf8(json).unwrap();
        assert!(json.contains("\"direction\":\"command\""));
        assert!(json.contains("\"ins\":\"20\""));
        assert!(json.contains("pin-verify-data"));
        assert!(!json.contains("241234"));

        let gac = hex("771A9F2701809F360200099F260811121314151617189F1003AABBCC");
        let mut len = 0usize;
        assert_eq!(
            krn_mask_apdu_response_json(
                1,
                gac.as_ptr(),
                gac.len(),
                0x90,
                0x00,
                false,
                ptr::null_mut(),
                &mut len,
            ),
            hyperion_emv::KernelError::BufferTooSmall.code()
        );
        let mut json = vec![0u8; len];
        assert_eq!(
            krn_mask_apdu_response_json(
                1,
                gac.as_ptr(),
                gac.len(),
                0x90,
                0x00,
                false,
                json.as_mut_ptr(),
                &mut len,
            ),
            hyperion_emv::KernelError::Ok.code()
        );
        let json = String::from_utf8(json).unwrap();
        assert!(json.contains("\"context\":\"generate-ac-response\""));
        assert!(json.contains("\"tag\":\"9f26\""));
        assert!(json.contains("transaction-cryptogram"));
        assert!(!json.contains("1112131415161718"));

        assert_eq!(
            krn_mask_apdu_response_json(
                9,
                gac.as_ptr(),
                gac.len(),
                0x90,
                0x00,
                false,
                ptr::null_mut(),
                &mut len,
            ),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
    }
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
fn prelab_apdu_trace_pack_is_replayable_masked_and_scoped() {
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
    let first_gac = ReplayExchange::new(
        &hex("80AE80000301020300"),
        &hex("800B8000091112131415161718"),
        [0x90, 0x00],
        ApduTraceContext::GenerateAcResponse,
    )
    .unwrap();
    let script = ReplayScript::new(vec![select, record, first_gac]).unwrap();
    let identity = TraceIdentity::current(KRN_ABI_VERSION, 2);
    let generated = format!(
        "{}{}",
        "{\"type\":\"trace-pack-metadata\",\"trace_pack_id\":\"PRELAB-MASKED-APDU-001\",\"scope\":\"repository-controlled pre-lab fixture\",\"case_id\":\"prelab.masking.generate-ac\",\"does_not_close\":\"CERT-OPEN-012\"}\n",
        script
            .masked_jsonl_with_trace_identity(LogPolicy::production(), &identity)
            .unwrap()
    );

    assert_eq!(PRELAB_APDU_TRACE_PACK, generated);
    assert!(PRELAB_APDU_TRACE_PACK.starts_with("{\"type\":\"trace-pack-metadata\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"trace_pack_id\":\"PRELAB-MASKED-APDU-001\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"case_id\":\"prelab.masking.generate-ac\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"does_not_close\":\"CERT-OPEN-012\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"type\":\"trace-identity\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"abi_version\":2"));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"profile_version\":2"));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"log_build_mode\":\"production\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"support_authorization_verified\":false"));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"reason\":\"full-apdu-disabled\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"value\":\"***********2345\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"context\":\"generate-ac-response\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"tag\":\"9f26\""));
    assert!(PRELAB_APDU_TRACE_PACK.contains("\"reason\":\"transaction-cryptogram\""));
    assert!(!PRELAB_APDU_TRACE_PACK.contains("123456789012345"));
    assert!(!PRELAB_APDU_TRACE_PACK.contains("010203"));
    assert!(!PRELAB_APDU_TRACE_PACK.contains("1112131415161718"));

    assert!(LAB_SUBMISSION_MANIFEST.contains("Pre-lab APDU trace fixture"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("cargo run --example krn_prelab_trace_pack"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("full lab/test-tool trace pack remains pending"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("- [ ] APDU trace logs (masked) for all test cases"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("CERT-OPEN-012"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("pre-lab fixture does not close"));
}

#[test]
fn prelab_quality_gates_are_reproducible_and_do_not_close_external_reports() {
    let generated = prelab_quality_gates_json(KRN_ABI_VERSION);

    assert_eq!(PRELAB_QUALITY_GATES, generated);
    assert!(PRELAB_QUALITY_GATES.contains("\"type\":\"prelab-quality-gates\""));
    assert!(PRELAB_QUALITY_GATES.contains("\"abi_version\":2"));
    assert!(PRELAB_QUALITY_GATES.contains("repository-controlled engineering gates only"));
    for command in [
        "cargo run --quiet --example krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json -",
        "cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -",
        "cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -",
        "cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json docs/certification_open_issues.md docs/standards_watch.md examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs",
        "cargo test",
        "cargo test --examples",
        "cargo fmt --check",
        "cargo clippy --all-targets --all-features",
        "git diff --check",
    ] {
        assert!(
            PRELAB_QUALITY_GATES.contains(command),
            "pre-lab quality gate manifest missing command: {command}"
        );
    }
    for blocker in ["CERT-OPEN-009", "CERT-OPEN-010"] {
        assert!(
            PRELAB_QUALITY_GATES.contains(blocker),
            "pre-lab quality gate manifest must preserve {blocker}"
        );
    }
    for pending_report in [
        "Unit coverage report >=95%",
        "Full EMV test-plan integration report",
        "Static-analysis report accepted for the submission context",
        "Fuzzing/no-crash report with tool versions and corpus",
    ] {
        assert!(
            PRELAB_QUALITY_GATES.contains(pending_report),
            "pre-lab quality gate manifest missing pending external report: {pending_report}"
        );
    }

    assert!(LAB_SUBMISSION_MANIFEST.contains("Pre-lab quality gate manifest"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("cargo run --example krn_prelab_quality_gates"));
    assert!(LAB_SUBMISSION_MANIFEST.contains(
        "formal coverage, integration, static-analysis, and fuzzing reports remain pending"
    ));
    assert!(LAB_SUBMISSION_MANIFEST.contains("- [ ] Unit test report"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("- [ ] Integration test report"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("- [ ] Static analysis report"));
    assert!(LAB_SUBMISSION_MANIFEST.contains("- [ ] Fuzzing report"));
    assert!(CERTIFICATION_OPEN_ISSUES.contains("pre-lab quality gate manifest does not close"));
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
fn rtm_promotes_contactless_entry_outcome_limit_and_cdcvm_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-CLESS-001",
            "KRN-CLESS-002",
            "KRN-CLESS-003",
            "KRN-CLESS-004",
            "KRN-CVM-004",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete contactless evidence"
            );
        }

        let entry = csv_row_for_requirement(csv, "KRN-CLESS-001").unwrap();
        assert!(entry.contains("builds_exact_contact_pse_and_contactless_ppse_selects"));
        assert!(entry.contains("krn_c8_001_002_003_uses_structured_contactless_only_outcomes"));

        let outcome = csv_row_for_requirement(csv, "KRN-CLESS-002").unwrap();
        assert!(outcome.contains("outcome_model_preserves_structured_records_for_callback"));
        assert!(outcome.contains("outcome_model_rejects_inconsistent_c8_instruction_tuples"));
        assert!(outcome.contains("ffi_emits_structured_contactless_outcome_callback"));
        assert!(outcome.contains("ffi_rejects_inconsistent_contactless_outcome_tuples"));

        let limits = csv_row_for_requirement(csv, "KRN-CLESS-003").unwrap();
        assert!(limits.contains("contactless_limits_are_profile_driven_and_deterministic"));
        assert!(limits.contains("contactless_limit_processing_uses_profile_limits_and_ctq_cdcvm"));
        assert!(limits.contains("krn_cless_003_limits_are_signed_profile_inputs"));

        for id in ["KRN-CLESS-004", "KRN-CVM-004"] {
            let cdcvm = csv_row_for_requirement(csv, id).unwrap();
            assert!(cdcvm.contains("contactless_scheme_specific_cdcvm_is_profile_context_driven"));
            assert!(
                cdcvm.contains("contactless_limit_processing_uses_profile_limits_and_ctq_cdcvm")
            );
            assert!(cdcvm.contains("contactless_cdcvm_is_not_hardcoded_to_cvm_code_0x05"));
        }
    }
}

#[test]
fn rtm_promotes_c8_kernel_outcome_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let kernel = csv_row_for_requirement(csv, "KRN-C8-001").expect("RTM row exists");
        assert!(
            !kernel.contains("Outcome logs") && !kernel.contains("Contactless outcome logs"),
            "KRN-C8-001 should cite executable C-8 outcome evidence"
        );
        assert!(kernel.contains("krn_c8_001_002_003_uses_structured_contactless_only_outcomes"));
        assert!(kernel.contains("outcome_model_preserves_structured_records_for_callback"));
        assert!(kernel.contains("outcome_model_rejects_inconsistent_c8_instruction_tuples"));
        assert!(kernel.contains("rtm_promotes_c8_kernel_outcome_evidence"));

        let callback = csv_row_for_requirement(csv, "KRN-C8-002").expect("RTM row exists");
        assert!(
            !callback.contains("Callback trace"),
            "KRN-C8-002 should cite executable contactless callback evidence"
        );
        assert!(callback.contains("outcome_model_preserves_structured_records_for_callback"));
        assert!(callback.contains("outcome_model_rejects_inconsistent_c8_instruction_tuples"));
        assert!(callback.contains("ffi_emits_structured_contactless_outcome_callback"));
        assert!(callback.contains("ffi_rejects_inconsistent_contactless_outcome_tuples"));
        assert!(callback.contains("krn_c8_001_002_003_uses_structured_contactless_only_outcomes"));
        assert!(callback.contains("rtm_promotes_c8_kernel_outcome_evidence"));

        let interface = csv_row_for_requirement(csv, "KRN-C8-003").expect("RTM row exists");
        assert!(
            !interface.contains("Interface test")
                && !interface.contains("Interface selection test"),
            "KRN-C8-003 should cite executable contact/contactless separation evidence"
        );
        assert!(interface.contains("krn_c8_001_002_003_uses_structured_contactless_only_outcomes"));
        assert!(interface.contains("selected_kernel_mapping_is_interface_specific"));
        assert!(interface.contains("rejects_contact_kernel_type_that_reuses_c8"));
        assert!(
            interface.contains("rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces")
        );
        assert!(interface.contains("rtm_promotes_c8_kernel_outcome_evidence"));
    }
}

#[test]
fn rtm_promotes_interface_kernel_mapping_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in ["KRN-INT-001", "KRN-INT-002", "KRN-INT-003", "KRN-INT-004"] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete interface/kernel mapping evidence"
            );
            assert!(row.contains("selected_kernel_mapping_is_interface_specific"));
            assert!(
                row.contains("rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces")
            );
            assert!(row.contains("rtm_promotes_interface_kernel_mapping_evidence"));
        }
        assert!(csv_row_for_requirement(csv, "KRN-INT-001")
            .unwrap()
            .contains("loads_profile_annex_when_signature_is_verified"));
        assert!(csv_row_for_requirement(csv, "KRN-INT-002")
            .unwrap()
            .contains("rejects_contact_kernel_type_that_reuses_c8"));
        assert!(csv_row_for_requirement(csv, "KRN-INT-003")
            .unwrap()
            .contains("supported_contactless_profiles_use_c8_certification_scope"));
        assert!(csv_row_for_requirement(csv, "KRN-INT-004")
            .unwrap()
            .contains("rejects_contact_kernel_type_that_reuses_c8"));
    }
}

#[test]
fn krn_cless_005_relay_resistance_is_profile_required_and_traced() {
    let profile = RelayResistanceProfile::new(
        hex("80CA9F7A00"),
        50,
        hex("9000"),
        RelayResistanceFailureOutcome::AlternateInterface,
    )
    .unwrap();
    assert_eq!(
        evaluate_relay_resistance(&profile, &hex("9000"), 50),
        RelayResistanceDecision::Passed
    );
    assert_eq!(
        evaluate_relay_resistance(&profile, &hex("9000"), 51),
        RelayResistanceDecision::Failed(RelayResistanceFailureOutcome::AlternateInterface)
    );
    let failure_outcome =
        outcome_from_relay_resistance_failure(RelayResistanceFailureOutcome::AlternateInterface)
            .unwrap();
    assert_eq!(
        failure_outcome.outcome_code,
        ContactlessOutcomeCode::AlternateInterface
    );
    assert_eq!(
        failure_outcome.alternate_interface,
        AlternateInterface::Contact
    );
    assert!(!SCHEME_PROFILES.contains("relay_resistance"));

    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-CLESS-005").expect("RTM row exists");
        assert!(!row.contains("pending implementation evidence"));
        assert!(row.contains("relay_resistance_is_profile_gated_and_deterministic"));
        assert!(row.contains("parses_profile_defined_relay_resistance_policy"));
        assert!(row.contains("contactless_relay_resistance_is_profile_required"));
    }
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
fn krn_oda_003_004_certificate_recovery_failures_set_tvr() {
    let (tvr, tsi) = apply_oda_outcome(
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
        OdaOutcome::Failed {
            method: OdaMethod::Sda,
            failure: OdaFailure::IssuerCertificateRecovery,
        },
    );
    assert!(tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    assert!(tvr.is_set(Tvr::B1_SDA_FAILED));
    assert!(tsi.is_set(hyperion_emv::state::Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));

    let (tvr, tsi) = apply_oda_outcome(
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
        OdaOutcome::Failed {
            method: OdaMethod::Dda,
            failure: OdaFailure::IccCertificateRecovery,
        },
    );
    assert!(tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    assert!(tvr.is_set(Tvr::B1_DDA_FAILED));
    assert!(tsi.is_set(hyperion_emv::state::Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));

    let (tvr, _) = apply_oda_outcome(
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
        OdaOutcome::Failed {
            method: OdaMethod::Cda,
            failure: OdaFailure::CdaSignature,
        },
    );
    assert!(!tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    assert!(tvr.is_set(Tvr::B1_CDA_FAILED));
}

#[test]
fn krn_oda_003_004_public_key_inputs_require_certificates_exponents_and_remainders() {
    let mut data = DataStore::new();
    data.put(&[0x90], &hex("6A02030405060708090A0B0C0D0E0FBC"))
        .unwrap();
    data.put(&[0x92], &hex("313233")).unwrap();
    data.put(&[0x9f, 0x32], &hex("03")).unwrap();
    data.put(&[0x9f, 0x46], &hex("6A1112131415161718191A1B1C1D1EBC"))
        .unwrap();
    data.put(&[0x9f, 0x48], &hex("4142")).unwrap();
    data.put(&[0x9f, 0x47], &hex("010001")).unwrap();

    let issuer = validate_issuer_public_key_inputs(&data).unwrap();
    assert_eq!(issuer.certificate, hex("6A02030405060708090A0B0C0D0E0FBC"));
    assert_eq!(issuer.remainder, hex("313233"));
    assert_eq!(issuer.exponent, hex("03"));

    let icc = validate_icc_public_key_inputs(&data).unwrap();
    assert_eq!(icc.certificate, hex("6A1112131415161718191A1B1C1D1EBC"));
    assert_eq!(icc.remainder, hex("4142"));
    assert_eq!(icc.exponent, hex("010001"));

    let mut missing_issuer_exponent = data.clone();
    missing_issuer_exponent.put(&[0x9f, 0x32], &[]).unwrap();
    assert_eq!(
        validate_issuer_public_key_inputs(&missing_issuer_exponent).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let mut truncated_icc_certificate = data;
    truncated_icc_certificate
        .put(&[0x9f, 0x46], &hex("6A1112"))
        .unwrap();
    assert_eq!(
        validate_icc_public_key_inputs(&truncated_icc_certificate).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
}

#[test]
fn krn_oda_005_static_authentication_data_uses_afl_order_and_tag_list() {
    let mut data = DataStore::new();
    data.put(&[0x9f, 0x4a], &hex("82")).unwrap();
    data.put(&[0x82], &hex("7800")).unwrap();

    let records = [
        StaticAuthenticationRecord {
            sfi: 2,
            record: 1,
            body: hex("700C5A04123456785F2403261231"),
        },
        StaticAuthenticationRecord {
            sfi: 11,
            record: 1,
            body: hex("70035F2000"),
        },
    ];

    assert_eq!(
        build_static_authentication_data(&records, &data).unwrap(),
        hex("5A04123456785F240326123170035F20007800")
    );

    let issuer_public_key = RecoveredPublicKeyCertificate {
        kind: RecoveredCertificateKind::Issuer,
        identifier: hex10("12345678901234567890"),
        expiration_date: [0x30, 0x12],
        serial_number: [0x01, 0x02, 0x03],
        hash_algorithm_indicator: 0x01,
        public_key_algorithm_indicator: 0x01,
        public_key: hex(
            "B0428067C589A60DDEACFDDF558479E0DB7676E1FFCEBC3B3B55657D5C4E57EA\
             B2D5592AAC2F9B767E0832C473200621",
        ),
        exponent: hex("010001"),
        hash_result: [0x11; 20],
    };
    let signed_static_application_data = hex(
        "6D492A5DB481273D1127EF24D1059B5702AED358BB75A3AD004766DD75157DE9\
         9A517A830517EB821D22CD55E0FF2AE4",
    );
    let mut sda_data = DataStore::new();
    sda_data.put(&[0x9f, 0x4a], &hex("82")).unwrap();
    sda_data.put(&[0x82], &hex("CC")).unwrap();
    let sda_records = [
        StaticAuthenticationRecord {
            sfi: 11,
            record: 1,
            body: hex("AA"),
        },
        StaticAuthenticationRecord {
            sfi: 12,
            record: 1,
            body: hex("BB"),
        },
    ];
    let recovered_sda = verify_static_data_authentication(
        &issuer_public_key,
        &signed_static_application_data,
        &sda_records,
        &sda_data,
    )
    .unwrap();
    assert_eq!(recovered_sda.data_authentication_code, Some([0x12, 0x34]));

    let mut missing_tag = DataStore::new();
    missing_tag.put(&[0x9f, 0x4a], &hex("82")).unwrap();
    assert_eq!(
        build_static_authentication_data(&records, &missing_tag).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );

    let mut duplicate_static_tag = data.clone();
    duplicate_static_tag
        .put(&[0x9f, 0x4a], &hex("8282"))
        .unwrap();
    assert_eq!(
        build_static_authentication_data(&records, &duplicate_static_tag).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );

    let mut constructed_static_tag = data.clone();
    constructed_static_tag
        .put(&[0x9f, 0x4a], &hex("A5"))
        .unwrap();
    assert_eq!(
        build_static_authentication_data(&records, &constructed_static_tag).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );

    let mut wrong_authentication_data = sda_data;
    wrong_authentication_data.put(&[0x82], &hex("DD")).unwrap();
    assert_eq!(
        verify_static_data_authentication(
            &issuer_public_key,
            &signed_static_application_data,
            &sda_records,
            &wrong_authentication_data,
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
}

#[test]
fn krn_oda_002_003_004_recovered_certificates_reconstruct_public_key_material() {
    let recovered_block =
        recover_rsa_public_block(&hex("08A7"), &hex("0CA1"), &hex("010001")).unwrap();
    assert_eq!(recovered_block, hex("0042"));
    assert_eq!(
        recover_rsa_public_block(&hex("0CA1"), &hex("0CA1"), &hex("010001")).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let signing_modulus = hex(
        "E818096D661646F609946CBEEF726473A6639B5155FE6C9F5B5F941685E43A75\
         E896E4F401899CF2862D673A0434B6D1",
    );
    let certificate_signature = hex(
        "C4D65E662B5043337656B47BF6400C1DAFBC58EAEC6FD9E2B01EB308C2CA501\
         C2538BD302ADE38BD73E2032AF4B3BB7C",
    );
    let verified_issuer = recover_and_verify_public_key_certificate(
        RecoveredCertificateKind::Issuer,
        &certificate_signature,
        &signing_modulus,
        &hex("010001"),
        &hex("B1B2B3"),
        &hex("03"),
        &[],
    )
    .unwrap();
    assert_eq!(verified_issuer.public_key, hex("A1A2A3A4A5A6B1B2B3"));
    assert_eq!(
        recover_and_verify_public_key_certificate(
            RecoveredCertificateKind::Icc,
            &certificate_signature,
            &signing_modulus,
            &hex("010001"),
            &hex("B1B2B3"),
            &hex("03"),
            &[],
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let issuer_recovered = hex("6A02\
         12345678901234567890\
         3012\
         010203\
         01\
         01\
         09\
         01\
         A1A2A3A4A5A6\
         54E3F6BE991906017C1752CD7BA97BEC321202FC\
         BC");
    let issuer = parse_recovered_public_key_certificate(
        RecoveredCertificateKind::Issuer,
        &issuer_recovered,
        &hex("B1B2B3"),
        &hex("03"),
    )
    .unwrap();
    assert_eq!(issuer.identifier, hex10("12345678901234567890"));
    assert_eq!(issuer.expiration_date, [0x30, 0x12]);
    assert_eq!(issuer.serial_number, [0x01, 0x02, 0x03]);
    assert_eq!(issuer.public_key, hex("A1A2A3A4A5A6B1B2B3"));
    assert_eq!(
        recovered_public_key_certificate_hash_input(&issuer, &[]).unwrap(),
        hex("0212345678901234567890301201020301010901A1A2A3A4A5A6B1B2B303")
    );
    assert!(recovered_public_key_certificate_hash_is_valid(&issuer, &[]).unwrap());

    let icc_recovered = hex("6A04\
         12345678901234567890\
         3012\
         0A0B0C\
         01\
         01\
         08\
         03\
         C1C2C3C4C5\
         840BF276D2DE65ADCBF883B0028C9C26A8B7CCFF\
         BC");
    let icc = parse_recovered_public_key_certificate(
        RecoveredCertificateKind::Icc,
        &icc_recovered,
        &hex("D1D2D3"),
        &hex("010001"),
    )
    .unwrap();
    assert_eq!(icc.kind, RecoveredCertificateKind::Icc);
    assert_eq!(icc.public_key, hex("C1C2C3C4C5D1D2D3"));
    assert_eq!(icc.exponent, hex("010001"));
    assert!(recovered_public_key_certificate_hash_is_valid(&icc, &hex("DEADBEEF")).unwrap());
    assert!(!recovered_public_key_certificate_hash_is_valid(&icc, &[]).unwrap());

    assert_eq!(
        parse_recovered_public_key_certificate(
            RecoveredCertificateKind::Issuer,
            &issuer_recovered,
            &hex("B1"),
            &hex("03"),
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
    assert_eq!(
        parse_recovered_public_key_certificate(
            RecoveredCertificateKind::Issuer,
            &issuer_recovered,
            &hex("B1B2B3"),
            &hex("010001"),
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
}

#[test]
fn krn_oda_005_006_007_recovers_and_verifies_signed_application_data() {
    let static_modulus = hex(
        "B0428067C589A60DDEACFDDF558479E0DB7676E1FFCEBC3B3B55657D5C4E57EA\
         B2D5592AAC2F9B767E0832C473200621",
    );
    let static_signature = hex(
        "6D492A5DB481273D1127EF24D1059B5702AED358BB75A3AD004766DD75157DE9\
         9A517A830517EB821D22CD55E0FF2AE4",
    );
    let static_data = recover_and_verify_signed_application_data(
        RecoveredSignedDataKind::StaticApplicationData,
        &static_signature,
        &static_modulus,
        &hex("010001"),
        &hex("AABBCC"),
    )
    .unwrap();
    assert_eq!(static_data.data_authentication_code, Some([0x12, 0x34]));
    assert_eq!(static_data.icc_dynamic_data, None);
    assert!(recovered_signed_application_data_hash_is_valid(&static_data, &hex("AABBCC")).unwrap());
    assert!(!recovered_signed_application_data_hash_is_valid(&static_data, &[]).unwrap());

    let dynamic_modulus = hex(
        "B706C0C6940601638E89144AEC5D8C229DA65024129CD31CE56F75F4FEC42EC\
         9921572260452EC32BDC7672863BEAA53",
    );
    let dynamic_signature = hex(
        "A826FBA6E8D7C0548D2E05551AFEEE0512C8AB02F33055BC389BECD93026B69F\
         B5ED72B750BE23C27E932C963F820550",
    );
    let dynamic_data = recover_and_verify_signed_application_data(
        RecoveredSignedDataKind::DynamicApplicationData,
        &dynamic_signature,
        &dynamic_modulus,
        &hex("010001"),
        &hex("11223344"),
    )
    .unwrap();
    assert_eq!(dynamic_data.icc_dynamic_data, Some(hex("01020304")));
    assert_eq!(dynamic_data.data_authentication_code, None);
    assert!(
        recovered_signed_application_data_hash_is_valid(&dynamic_data, &hex("11223344")).unwrap()
    );

    assert_eq!(
        recover_and_verify_signed_application_data(
            RecoveredSignedDataKind::StaticApplicationData,
            &dynamic_signature,
            &dynamic_modulus,
            &hex("010001"),
            &hex("11223344"),
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
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
        9,
        policy.evaluation_date,
        CapkIntegrity::Verified,
    )
    .unwrap();
    assert_eq!(capk.rid, rid);
    assert_eq!(capk.key_index, 9);
    assert!(capk_checksum_is_valid(capk));
    assert_eq!(capk_checksum(capk).as_slice(), capk.checksum.as_slice());

    let mut tampered = profiles.clone();
    tampered.schemes[0].capks[0].checksum[19] ^= 0xff;
    assert_eq!(
        select_capk(
            &tampered,
            &rid,
            8,
            policy.evaluation_date,
            CapkIntegrity::Verified,
        )
        .unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
}

#[test]
fn krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        let row = csv_row_for_requirement(csv, "KRN-ODATV-001").unwrap();
        assert!(row.contains("certification_vector_coverage_is_method_specific"));
        assert!(row.contains("validates_complete_vector_syntax_and_rejects_placeholders"));
        assert!(row.contains("krn_odatv_001_rejects_placeholder_oda_annex_in_certification_mode"));
    }

    assert!(ODA_VECTORS.contains("\"vector_class\": \"STRUCTURAL_FIXTURE\""));
    validate_oda_vector_annex(ODA_VECTORS.as_bytes(), false).unwrap();
    assert_eq!(
        validate_oda_vector_annex(ODA_VECTORS.as_bytes(), true).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let relabeled_fixture = ODA_VECTORS.replace(
        "\"vector_class\": \"STRUCTURAL_FIXTURE\"",
        "\"vector_class\": \"CERTIFICATION\"",
    );
    assert_eq!(
        validate_oda_vector_annex(relabeled_fixture.as_bytes(), true).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
    let complete = relabeled_fixture
        .replace("structural fixtures", "certification vectors")
        .replace("parser and evidence plumbing", "lab acceptance");
    validate_oda_vector_annex(complete.as_bytes(), true).unwrap();

    let sda_only = br#"{"vector_class":"CERTIFICATION","test_vectors":[{"id":"SDA","capk":{"rid":"A000000003","key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0","exponent_hex":"010001","checksum_hex":"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"},"issuer_certificate_hex":"6F2A9F103A1B2C3D4E5F60718293A4B5C6D7E8F9A0","static_signature_hex":"ABCD1234567890ABCD","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
    assert_eq!(
        validate_oda_vector_annex(sda_only, true).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
}

#[test]
fn krn_tvr_001_002_tvr_is_symbolic_and_cleared() {
    let mut tvr = Tvr::cleared();
    assert_eq!(tvr.bytes(), [0; 5]);
    tvr.set(Tvr::B1_SDA_FAILED);
    assert_eq!(tvr.bytes(), [0x40, 0, 0, 0, 0]);
}

#[test]
fn krn_tvr_003_tsi_001_state_bits_are_defined_and_rfu_safe() {
    let mut tvr = Tvr::cleared();
    tvr.set((0, 0x03));
    tvr.set((1, 0x07));
    tvr.set((2, 0x03));
    tvr.set((3, 0x07));
    tvr.set((4, 0x8f));
    tvr.set((9, 0xff));
    assert_eq!(tvr.bytes(), [0; 5]);
    assert!(!tvr.has_rfu_bits());

    for bit in [
        Tvr::B1_OFFLINE_DATA_AUTH_NOT_PERFORMED,
        Tvr::B1_SDA_FAILED,
        Tvr::B1_ICC_DATA_MISSING,
        Tvr::B1_CARD_ON_EXCEPTION_FILE,
        Tvr::B1_DDA_FAILED,
        Tvr::B1_CDA_FAILED,
        Tvr::B2_DIFFERENT_APPLICATION_VERSIONS,
        Tvr::B2_EXPIRED_APPLICATION,
        Tvr::B2_APPLICATION_NOT_YET_EFFECTIVE,
        Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED,
        Tvr::B2_NEW_CARD,
        Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL,
        Tvr::B3_UNRECOGNIZED_CVM,
        Tvr::B3_PIN_TRY_LIMIT_EXCEEDED,
        Tvr::B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING,
        Tvr::B3_PIN_NOT_ENTERED,
        Tvr::B3_ONLINE_PIN_ENTERED,
        Tvr::B4_FLOOR_LIMIT_EXCEEDED,
        Tvr::B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED,
        Tvr::B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED,
        Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED,
        Tvr::B4_MERCHANT_FORCED_TRANSACTION_ONLINE,
        Tvr::B5_ISSUER_AUTHENTICATION_FAILED,
        Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC,
        Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC,
    ] {
        tvr.set(bit);
    }
    assert_eq!(tvr.bytes(), Tvr::ALLOWED_MASKS);
    assert!(!tvr.has_rfu_bits());

    let mut tsi = Tsi::cleared();
    tsi.set((0, 0x03));
    tsi.set((1, 0xff));
    tsi.set((4, 0xff));
    assert_eq!(tsi.bytes(), [0; 2]);
    assert!(!tsi.has_rfu_bits());

    for bit in [
        Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED,
        Tsi::CARDHOLDER_VERIFICATION_PERFORMED,
        Tsi::CARD_RISK_MANAGEMENT_PERFORMED,
        Tsi::ISSUER_AUTHENTICATION_PERFORMED,
        Tsi::TERMINAL_RISK_MANAGEMENT_PERFORMED,
        Tsi::SCRIPT_PROCESSING_PERFORMED,
    ] {
        tsi.set(bit);
    }
    assert_eq!(tsi.bytes(), Tsi::ALLOWED_MASKS);
    assert!(!tsi.has_rfu_bits());
}

#[test]
fn krn_taa_001_002_003_004_005_006_007_uses_iac_tac_order_and_profile_fallbacks() {
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

    let mut tvr = Tvr::cleared();
    tvr.set(Tvr::B4_FLOOR_LIMIT_EXCEEDED);
    let iac_online = decide(TaaInput {
        tvr,
        tac: ActionCodes::zeroed(),
        iac: ActionCodes {
            denial: [0; 5],
            online: [0, 0, 0, 0x80, 0],
            default: [0; 5],
        },
        terminal_online_capable: true,
        profile: TaaProfile::spec_defaults(),
    });
    assert_eq!(iac_online.action, TerminalAction::Arqc);

    let mut tvr = Tvr::cleared();
    tvr.set(Tvr::B1_ICC_DATA_MISSING);
    let iac_default = decide(TaaInput {
        tvr,
        tac: ActionCodes::zeroed(),
        iac: ActionCodes {
            denial: [0; 5],
            online: [0; 5],
            default: [0x20, 0, 0, 0, 0],
        },
        terminal_online_capable: false,
        profile: TaaProfile::new(
            TerminalAction::Tc,
            TerminalAction::Arqc,
            TerminalAction::Aac,
        )
        .unwrap(),
    });
    assert_eq!(iac_default.action, TerminalAction::Tc);

    let no_match = decide(TaaInput {
        tvr: Tvr::cleared(),
        tac: ActionCodes::zeroed(),
        iac: ActionCodes::zeroed(),
        terminal_online_capable: true,
        profile: TaaProfile::new(TerminalAction::Aac, TerminalAction::Tc, TerminalAction::Aac)
            .unwrap(),
    });
    assert_eq!(no_match.action, TerminalAction::Tc);

    assert!(!include_str!("../src/taa.rs").contains("default_cryptogram"));
}

#[test]
fn rtm_promotes_issuer_authentication_and_final_gac_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-IAUTH-001",
            "KRN-IAUTH-002",
            "KRN-IAUTH-003",
            "KRN-GAC2-001",
            "KRN-GAC2-002",
            "KRN-GAC2-003",
            "KRN-GAC2-004",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete issuer-auth/final-GAC evidence"
            );
            assert!(row.contains("rtm_promotes_issuer_authentication_and_final_gac_evidence"));
        }

        let issuer_auth = csv_row_for_requirement(csv, "KRN-IAUTH-001").unwrap();
        assert!(issuer_auth.contains("builds_external_authenticate_for_issuer_authentication_data"));
        assert!(issuer_auth.contains("parses_arpc_arc_and_issuer_scripts"));
        assert!(issuer_auth.contains("rejects_nested_or_duplicate_host_response_auth_objects"));

        let issuer_auth_failure = csv_row_for_requirement(csv, "KRN-IAUTH-003").unwrap();
        assert!(issuer_auth_failure
            .contains("issuer_authentication_failure_sets_tvr_and_reaches_scripts"));

        let cdol2 = csv_row_for_requirement(csv, "KRN-GAC2-001").unwrap();
        assert!(cdol2.contains("final_generate_ac_builds_cdol2_from_host_response_and_state"));
        let cdol2_auth = csv_row_for_requirement(csv, "KRN-GAC2-002").unwrap();
        assert!(cdol2_auth.contains("rejects_nested_or_duplicate_host_response_auth_objects"));

        let final_outcome = csv_row_for_requirement(csv, "KRN-GAC2-004").unwrap();
        assert!(final_outcome
            .contains("krn_gac2_004_final_generate_ac_skipped_without_cdol2_honors_host_arc"));
    }
}

#[test]
fn rtm_promotes_issuer_script_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-SCR-001",
            "KRN-SCR-002",
            "KRN-SCR-003",
            "KRN-SCR-004",
            "KRN-SCR-005",
            "KRN-SCR-006",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete issuer-script evidence"
            );
            assert!(
                row.contains("rtm_promotes_issuer_script_evidence"),
                "{id} should cite this RTM guard"
            );
        }

        let parser = csv_row_for_requirement(csv, "KRN-SCR-001").unwrap();
        assert!(parser.contains("parses_arpc_arc_and_issuer_scripts"));
        assert!(parser.contains("rejects_script_templates_without_commands"));
        assert!(parser.contains("rejects_malformed_issuer_script_identifier_lengths"));
        assert!(parser.contains("rejects_malformed_issuer_script_command_apdus"));
        assert!(parser.contains("rejects_nested_or_duplicate_issuer_script_objects"));
        assert!(parser.contains("rejects_cumulative_issuer_script_command_overflow"));
        assert!(parser.contains("host_response_extracts_arpc_and_phase_specific_script_results"));

        let execution = csv_row_for_requirement(csv, "KRN-SCR-002").unwrap();
        assert!(execution
            .contains("issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final"));
        assert!(execution
            .contains("post_final_issuer_script_failure_sets_after_final_tvr_and_completes"));
        assert!(execution.contains("issuer_script_apdus_resolve_get_response_and_retry_le"));

        let results = csv_row_for_requirement(csv, "KRN-SCR-003").unwrap();
        assert!(
            results.contains("issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final")
        );
        assert!(
            results.contains("post_final_issuer_script_failure_sets_after_final_tvr_and_completes")
        );
        assert!(results.contains("critical_issuer_script_failure_records_results_and_enters_error"));

        let before_final_tvr = csv_row_for_requirement(csv, "KRN-SCR-004").unwrap();
        assert!(before_final_tvr.contains("script_results_set_phase_specific_tvr_bits_and_tsi"));
        assert!(before_final_tvr
            .contains("issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final"));

        let after_final_tvr = csv_row_for_requirement(csv, "KRN-SCR-005").unwrap();
        assert!(after_final_tvr.contains("script_results_set_phase_specific_tvr_bits_and_tsi"));
        assert!(after_final_tvr
            .contains("post_final_issuer_script_failure_sets_after_final_tvr_and_completes"));
        assert!(after_final_tvr
            .contains("critical_issuer_script_failure_records_results_and_enters_error"));

        let reporting = csv_row_for_requirement(csv, "KRN-SCR-006").unwrap();
        assert!(reporting
            .contains("ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac"));
        assert!(reporting
            .contains("issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final"));
        assert!(reporting
            .contains("post_final_issuer_script_failure_sets_after_final_tvr_and_completes"));
    }
}

#[test]
fn rtm_promotes_terminal_action_analysis_evidence() {
    for csv in [CURRENT_RTM, LEGACY_RTM] {
        for id in [
            "KRN-TAA-001",
            "KRN-TAA-002",
            "KRN-TAA-003",
            "KRN-TAA-004",
            "KRN-TAA-005",
            "KRN-TAA-006",
            "KRN-TAA-007",
        ] {
            let row = csv_row_for_requirement(csv, id).expect("RTM row exists");
            assert!(
                !row.contains("pending implementation evidence"),
                "{id} should cite concrete TAA evidence"
            );
            assert!(row.contains(
                "krn_taa_001_002_003_004_005_006_007_uses_iac_tac_order_and_profile_fallbacks"
            ));
        }

        let denial = csv_row_for_requirement(csv, "KRN-TAA-001").unwrap();
        assert!(denial.contains("denial_action_codes_take_precedence"));

        let iac = csv_row_for_requirement(csv, "KRN-TAA-002").unwrap();
        assert!(iac.contains("loads_profile_issuer_action_code_fallbacks"));
        assert!(iac.contains("iac_values_participate_in_denial_online_and_default_decisions"));
        assert!(iac.contains("taa_offline_final_state_finishes_from_s16"));
        assert!(iac.contains("taa_uses_profile_iac_fallbacks_when_card_omits_iacs"));
        assert!(iac.contains("card_iac_tags_override_profile_fallbacks"));

        let iac_fetch = csv_row_for_requirement(csv, "KRN-TAA-004").unwrap();
        assert!(iac_fetch.contains("loads_profile_issuer_action_code_fallbacks"));
        assert!(iac_fetch.contains("taa_uses_profile_iac_fallbacks_when_card_omits_iacs"));
        assert!(iac_fetch.contains("card_iac_tags_override_profile_fallbacks"));

        let unconstrained_default = csv_row_for_requirement(csv, "KRN-TAA-003").unwrap();
        assert!(unconstrained_default.contains("invalid_profile_combinations_are_rejected"));
        assert!(unconstrained_default.contains("no_match_defaults_are_profile_driven"));

        let tac = csv_row_for_requirement(csv, "KRN-TAA-005").unwrap();
        assert!(
            tac.contains("profile_loader_requires_verified_signature_and_extracts_capk_tac_limits")
        );
        assert!(tac.contains("online_action_codes_request_arqc_when_online_capable"));

        let order = csv_row_for_requirement(csv, "KRN-TAA-006").unwrap();
        assert!(order.contains("taa_uses_terminal_type_online_capability"));

        let fallback = csv_row_for_requirement(csv, "KRN-TAA-007").unwrap();
        assert!(fallback.contains("scheme_profile_annex_contains_deterministic_taa_keys"));
        assert!(fallback.contains("offline_unable_default_match_uses_profile_fallback"));

        let gac1 = csv_row_for_requirement(csv, "KRN-GAC1-003").unwrap();
        assert!(gac1.contains("taa_uses_terminal_type_online_capability"));
    }
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

    assert_eq!(
        parse_afl(&hex("13010100")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    let overlapping = parse_afl(&hex("1001020010020300")).unwrap();
    assert_eq!(
        record_plan(&overlapping).unwrap_err(),
        hyperion_emv::KernelError::ParseError
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

    assert_eq!(
        parse_read_record_body(&hex("5A08123456789012345F"), &mut data).unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert_eq!(
        parse_read_record_body(
            &hex("700E5A0312345F5A03AABBCC5F240126"),
            &mut DataStore::new()
        )
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_read_record_body(
            &hex("700D5A0312345FA5065F2403261231"),
            &mut DataStore::new()
        )
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_afl(&hex("13010100")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    let overlapping = parse_afl(&hex("1001020010020300")).unwrap();
    assert_eq!(
        read_record_commands(&overlapping).unwrap_err(),
        hyperion_emv::KernelError::ParseError
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
    assert_eq!(
        classify(
            ApduContext::ExternalAuthenticate,
            StatusWord::new(0x69, 0x85)
        ),
        StatusAction::ContinueWithTvr {
            bit: Tvr::B5_ISSUER_AUTHENTICATION_FAILED
        }
    );
}

#[test]
fn krn_cvm_001_002_003_and_sec_004_use_cvm_table_without_clear_pin() {
    for (code, expected) in [
        (0x01, CvmMethod::OfflinePlaintextPin),
        (0x02, CvmMethod::OnlinePin),
        (0x03, CvmMethod::OfflinePlaintextPinAndSignature),
        (0x04, CvmMethod::OfflineEncipheredPin),
        (0x05, CvmMethod::OfflineEncipheredPinAndSignature),
        (0x06, CvmMethod::Signature),
        (0x1e, CvmMethod::FailCvmProcessing),
        (0x1f, CvmMethod::NoCvmRequired),
        (0x20, CvmMethod::SchemeSpecific(0x20)),
        (0x3f, CvmMethod::SchemeSpecific(0x3f)),
    ] {
        assert_eq!(CvmMethod::from_code(code), expected);
    }

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
        evaluate_cvm(&cvm_list, context, CvmPinHandles::none()),
        CvmOutcome::Failed {
            cvm_results: [0x01, 0x00, 0x01],
            tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
        }
    );

    let handle = PedPinHandle::new(42).unwrap();
    assert_eq!(
        evaluate_cvm(
            &cvm_list,
            context,
            CvmPinHandles::with_offline_plaintext(handle),
        ),
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
        evaluate_cvm(&cvm_list, context, CvmPinHandles::none()),
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
            offline_counter: Some(OfflineCounter::non_volatile(5)),
            random_sample_basis_points: Some(499),
            profile: TrmProfile::new(5_000, 5, Some(2), Some(4)).unwrap(),
        },
        Tvr::cleared(),
        hyperion_emv::state::Tsi::cleared(),
    )
    .unwrap();

    assert!(result.force_online);
    assert_eq!(result.tvr.bytes(), [0x10, 0x00, 0x00, 0xf8, 0x00]);
    assert_eq!(result.tsi.bytes(), [0x08, 0x00]);
}

#[test]
fn trm_003_requires_nonvolatile_counter_for_velocity_limits() {
    unsafe {
        assert_eq!(
            krn_set_nonvolatile_offline_counter(ptr::null_mut(), 0),
            hyperion_emv::KernelError::InvalidArgument.code()
        );
    }

    let profile = TrmProfile::new(5_000, 0, Some(2), Some(4)).unwrap();
    let input = |offline_counter| TrmInput {
        amount_authorized: 100,
        exception_file_match: false,
        merchant_forced_online: false,
        offline_counter,
        random_sample_basis_points: None,
        profile,
    };

    assert_eq!(
        evaluate_trm(input(None), Tvr::cleared(), Tsi::cleared()).unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );
    assert_eq!(
        evaluate_trm(
            input(Some(OfflineCounter::volatile(5))),
            Tvr::cleared(),
            Tsi::cleared()
        )
        .unwrap_err(),
        hyperion_emv::KernelError::InvalidProfile
    );

    let result = evaluate_trm(
        input(Some(OfflineCounter::non_volatile(5))),
        Tvr::cleared(),
        Tsi::cleared(),
    )
    .unwrap();
    assert!(result
        .tvr
        .is_set(Tvr::B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED));
    assert!(result
        .tvr
        .is_set(Tvr::B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED));
}

#[test]
fn tsi_bits_are_set_only_after_corresponding_processing() {
    let (tvr, tsi) = apply_oda_outcome(Tvr::cleared(), Tsi::cleared(), OdaOutcome::NotPerformed);
    assert!(tvr.is_set(Tvr::B1_OFFLINE_DATA_AUTH_NOT_PERFORMED));
    assert!(!tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
    assert_eq!(tsi.bytes(), [0x00, 0x00]);

    let (_, tsi) = apply_oda_outcome(
        Tvr::cleared(),
        Tsi::cleared(),
        OdaOutcome::Passed(OdaMethod::Sda),
    );
    assert_eq!(tsi.bytes(), [0x80, 0x00]);

    let no_scripts = apply_script_results(
        ScriptPhase::BeforeFinalGenerateAc,
        &[],
        Tvr::cleared(),
        Tsi::cleared(),
    );
    assert_eq!(no_scripts.tsi.bytes(), [0x00, 0x00]);

    let script = apply_script_results(
        ScriptPhase::BeforeFinalGenerateAc,
        &[ScriptCommandResult {
            sw1: 0x90,
            sw2: 0x00,
        }],
        Tvr::cleared(),
        Tsi::cleared(),
    );
    assert_eq!(script.tsi.bytes(), [0x04, 0x00]);

    let trm = evaluate_trm(
        TrmInput {
            amount_authorized: 100,
            exception_file_match: false,
            merchant_forced_online: false,
            offline_counter: None,
            random_sample_basis_points: Some(9_999),
            profile: TrmProfile::new(5_000, 0, None, None).unwrap(),
        },
        Tvr::cleared(),
        Tsi::cleared(),
    )
    .unwrap();
    assert_eq!(trm.tsi.bytes(), [0x08, 0x00]);
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

    assert_eq!(
        parse_generate_ac_response(&hex("9F2701809F360200099F260811121314151617189F1003AABBCC"))
            .unwrap_err(),
        hyperion_emv::KernelError::MissingMandatoryTag
    );
    assert_eq!(
        parse_generate_ac_response(&hex(
            "772A9F2701809F360200099F26081112131415161718A5149F2701409F3602000A9F26082021222324252627"
        ))
        .unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
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
    assert_eq!(
        parse_host_response(&hex("70048A023030")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_host_response(&hex("700A91081122334455667788")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_host_response(&hex("8A0230308A023035")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_host_response(&hex("9108112233445566778891082122232425262728")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );
    assert_eq!(
        parse_host_response(&hex("7108860600DA000002AA")).unwrap_err(),
        hyperion_emv::KernelError::ParseError
    );

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

fn hex10(input: &str) -> [u8; 10] {
    let bytes = hex(input);
    let mut out = [0u8; 10];
    out.copy_from_slice(&bytes);
    out
}

fn from_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
