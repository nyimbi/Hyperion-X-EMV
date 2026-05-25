use hyperion_emv::c8::KrnContactlessOutcome;
use hyperion_emv::ffi::{
    krn_apply_host_response, krn_context_free, krn_get_callback_timeout_policy,
    krn_get_certification_bundle_sha256, krn_get_final_outcome, krn_get_fsm_state,
    krn_get_last_error, krn_get_online_authorization_data, krn_get_profile_sha256,
    krn_get_profile_version, krn_init, krn_load_certification_bundle_verified,
    krn_process_final_generate_ac, krn_process_issuer_authentication, krn_process_issuer_scripts,
    krn_run_transaction, krn_set_cvm_capabilities, krn_set_terminal_capabilities,
    krn_set_terminal_transaction_qualifiers, krn_set_transaction_params,
    krn_set_trm_random_selection_sample, KrnCallbackTimeoutPolicy, KrnContext, KrnRuntime,
    KrnTxnParams, KRN_ABI_VERSION, KRN_INTERFACE_CONTACTLESS, KRN_PROFILE_SHA256_LEN,
};
use hyperion_emv::provenance::to_hex;
use hyperion_emv::KernelError;
use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::slice;

struct SoftPosSale {
    amount_minor: u64,
    currency_code: u16,
    country_code: u16,
    merchant_category_code: [u8; 2],
    merchant_name_location: &'static [u8],
    wallet_cdcvm_performed: bool,
}

struct ScriptedExchange {
    label: &'static str,
    expected_ins: u8,
    response: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContactlessEvent {
    outcome_code: u8,
    start_signal: u8,
    ui_message_id: u16,
    ui_status: u8,
    restart_required: bool,
    alternate_interface: u8,
    data_record_len: usize,
    discretionary_data_len: usize,
}

struct MobileNfcSession {
    exchanges: Vec<ScriptedExchange>,
    observed_commands: Vec<Vec<u8>>,
    contactless_events: Vec<ContactlessEvent>,
    mismatch: Option<String>,
    unpredictable_number: [u8; 4],
}

struct AcquirerHost;

struct SoftPosSummary {
    initial_outcome: i32,
    final_outcome: i32,
    last_error: i32,
    fsm_state: u8,
    profile_version: u64,
    profile_sha256: [u8; 32],
    certification_bundle_sha256: [u8; 32],
    online_authorization_len: usize,
    apdu_timeout_ms: i32,
    wallet_cdcvm_performed: bool,
    command_flow: Vec<u8>,
    contactless_events: Vec<ContactlessEvent>,
}

struct ContextGuard(*mut KrnContext);

impl Drop for ContextGuard {
    fn drop(&mut self) {
        unsafe {
            krn_context_free(self.0);
        }
    }
}

impl MobileNfcSession {
    fn contactless_visa_arqc_then_tc() -> Self {
        Self {
            exchanges: vec![
                ScriptedExchange {
                    label: "select-ppse",
                    expected_ins: 0xa4,
                    response: ppse_directory_response(),
                },
                ScriptedExchange {
                    label: "select-aid",
                    expected_ins: 0xa4,
                    response: selected_contactless_fci_response(&[
                        0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
                    ]),
                },
                ScriptedExchange {
                    label: "gpo",
                    expected_ins: 0xa8,
                    response: gpo_aip_afl_response(),
                },
                ScriptedExchange {
                    label: "read-record",
                    expected_ins: 0xb2,
                    response: application_record_response(),
                },
                ScriptedExchange {
                    label: "first-generate-ac",
                    expected_ins: 0xae,
                    response: first_gac_arqc_response(),
                },
                ScriptedExchange {
                    label: "external-authenticate",
                    expected_ins: 0x82,
                    response: status_success_response(),
                },
                ScriptedExchange {
                    label: "second-generate-ac",
                    expected_ins: 0xae,
                    response: second_gac_tc_response(),
                },
            ],
            observed_commands: Vec::new(),
            contactless_events: Vec::new(),
            mismatch: None,
            unpredictable_number: [0x51, 0x62, 0x73, 0x84],
        }
    }

    fn observed_ins(&self) -> Vec<u8> {
        self.observed_commands
            .iter()
            .filter_map(|command| command.get(1).copied())
            .collect()
    }
}

impl AcquirerHost {
    fn authorize(&self, _online_authorization_data: &[u8]) -> Vec<u8> {
        vec![
            0x8a, 0x02, b'0', b'0', 0x91, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ]
    }
}

fn main() {
    let sale = SoftPosSale {
        amount_minor: 4_200,
        currency_code: 840,
        country_code: 840,
        merchant_category_code: [0x53, 0x11],
        merchant_name_location: b"DATACRAFT SOFTPOS*NAIROBI",
        wallet_cdcvm_performed: true,
    };
    let mut nfc = MobileNfcSession::contactless_visa_arqc_then_tc();
    let host = AcquirerHost;

    match run_softpos_sale(&sale, &mut nfc, &host) {
        Ok(summary) => println!("{}", summary.to_json()),
        Err(err) => {
            eprintln!("basic SoftPoS sale failed: {err}");
            std::process::exit(1);
        }
    }
}

fn run_softpos_sale(
    sale: &SoftPosSale,
    nfc: &mut MobileNfcSession,
    host: &AcquirerHost,
) -> Result<SoftPosSummary, String> {
    unsafe {
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(nfc_transmit_apdu),
            get_unpredictable_number: Some(nfc_unpredictable_number),
            contactless_outcome: Some(mobile_contactless_outcome),
            user_data: nfc as *mut MobileNfcSession as *mut c_void,
        };
        let mut ctx = ptr::null_mut();
        require_ok(krn_init(ptr::null(), &runtime, &mut ctx), "krn_init")?;
        if ctx.is_null() {
            return Err("krn_init returned null context".to_string());
        }
        let guard = ContextGuard(ctx);

        let bundle = include_bytes!("../docs/certification_data_bundle.json");
        let trust_anchors = include_bytes!("../docs/certification_data_bundle_trust_anchors.json");
        require_ok(
            krn_load_certification_bundle_verified(
                guard.0,
                bundle.as_ptr(),
                bundle.len(),
                trust_anchors.as_ptr(),
                trust_anchors.len(),
                1,
                26,
                5,
                25,
            ),
            "krn_load_certification_bundle_verified",
        )?;

        let mut timeout_policy = KrnCallbackTimeoutPolicy {
            abi_version: KRN_ABI_VERSION,
            struct_size: mem::size_of::<KrnCallbackTimeoutPolicy>() as u32,
            min_timeout_ms: 0,
            max_timeout_ms: 0,
            apdu_transport_timeout_ms: 0,
            host_authorization_timeout_ms: 0,
            pin_entry_timeout_ms: 0,
            contactless_ui_timeout_ms: 0,
        };
        require_ok(
            krn_get_callback_timeout_policy(&mut timeout_policy),
            "krn_get_callback_timeout_policy",
        )?;

        let mut bundle_sha256 = [0u8; KRN_PROFILE_SHA256_LEN];
        let mut bundle_sha256_len = bundle_sha256.len();
        require_ok(
            krn_get_certification_bundle_sha256(
                guard.0,
                bundle_sha256.as_mut_ptr(),
                &mut bundle_sha256_len,
            ),
            "krn_get_certification_bundle_sha256",
        )?;

        let mut profile_version = 0u64;
        require_ok(
            krn_get_profile_version(guard.0, &mut profile_version),
            "krn_get_profile_version",
        )?;
        let mut profile_sha256 = [0u8; KRN_PROFILE_SHA256_LEN];
        let mut profile_sha256_len = profile_sha256.len();
        require_ok(
            krn_get_profile_sha256(
                guard.0,
                profile_sha256.as_mut_ptr(),
                &mut profile_sha256_len,
            ),
            "krn_get_profile_sha256",
        )?;

        let params = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: sale.amount_minor,
            amount_other_minor: 0,
            currency_code: sale.currency_code,
            currency_exponent: 2,
            terminal_country_code: sale.country_code,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: sale.merchant_category_code,
            interface_preference: KRN_INTERFACE_CONTACTLESS,
            merchant_name_location: sale.merchant_name_location.as_ptr(),
            merchant_name_location_len: sale.merchant_name_location.len(),
        };
        require_ok(
            krn_set_transaction_params(guard.0, &params),
            "krn_set_transaction_params",
        )?;
        require_ok(
            krn_set_terminal_capabilities(guard.0, 0xe0, 0xb0, 0xc8),
            "krn_set_terminal_capabilities",
        )?;
        require_ok(
            krn_set_terminal_transaction_qualifiers(guard.0, 0x36, 0x00, 0x40, 0x00),
            "krn_set_terminal_transaction_qualifiers",
        )?;
        require_ok(
            krn_set_cvm_capabilities(guard.0, 0, 0, u8::from(sale.wallet_cdcvm_performed)),
            "krn_set_cvm_capabilities",
        )?;
        require_ok(
            krn_set_trm_random_selection_sample(guard.0, 9_999),
            "krn_set_trm_random_selection_sample",
        )?;

        let initial_outcome = krn_run_transaction(guard.0);
        let online_authorization =
            read_probeable_output(guard.0, krn_get_online_authorization_data)?;
        let host_response = host.authorize(&online_authorization);
        require_ok(
            krn_apply_host_response(guard.0, host_response.as_ptr(), host_response.len()),
            "krn_apply_host_response",
        )?;
        require_ok(
            krn_process_issuer_authentication(guard.0),
            "krn_process_issuer_authentication",
        )?;
        require_ok(
            krn_process_issuer_scripts(guard.0),
            "krn_process_issuer_scripts",
        )?;
        require_ok(
            krn_process_final_generate_ac(guard.0),
            "krn_process_final_generate_ac",
        )?;

        let final_outcome = krn_get_final_outcome(guard.0);
        let last_error = krn_get_last_error(guard.0);
        let fsm_state = krn_get_fsm_state(guard.0);
        if let Some(mismatch) = nfc.mismatch.as_ref() {
            return Err(mismatch.clone());
        }

        Ok(SoftPosSummary {
            initial_outcome,
            final_outcome,
            last_error,
            fsm_state,
            profile_version,
            profile_sha256,
            certification_bundle_sha256: bundle_sha256,
            online_authorization_len: online_authorization.len(),
            apdu_timeout_ms: timeout_policy.apdu_transport_timeout_ms,
            wallet_cdcvm_performed: sale.wallet_cdcvm_performed,
            command_flow: nfc.observed_ins(),
            contactless_events: nfc.contactless_events.clone(),
        })
    }
}

type ProbeFn = unsafe extern "C" fn(*mut KrnContext, *mut u8, *mut usize) -> i32;

unsafe fn read_probeable_output(ctx: *mut KrnContext, f: ProbeFn) -> Result<Vec<u8>, String> {
    let mut len = 0usize;
    let status = f(ctx, ptr::null_mut(), &mut len);
    if status != KernelError::BufferTooSmall.code() {
        require_ok(status, "probe output length")?;
    }
    let mut out = vec![0u8; len];
    let mut out_len = out.len();
    require_ok(f(ctx, out.as_mut_ptr(), &mut out_len), "read output")?;
    out.truncate(out_len);
    Ok(out)
}

fn require_ok(status: i32, operation: &str) -> Result<(), String> {
    if status == KernelError::Ok.code() {
        Ok(())
    } else {
        Err(format!("{operation} returned status {status}"))
    }
}

unsafe extern "C" fn nfc_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    if cmd.is_null() || resp_len.is_null() || user_data.is_null() || cmd_len < 4 || timeout_ms <= 0
    {
        return KernelError::InvalidArgument.code();
    }
    let session = &mut *(user_data as *mut MobileNfcSession);
    let command = slice::from_raw_parts(cmd, cmd_len);
    session.observed_commands.push(command.to_vec());
    let Some(exchange) = session
        .exchanges
        .get(session.observed_commands.len().saturating_sub(1))
    else {
        session.mismatch = Some("kernel sent more NFC APDUs than the script defines".to_string());
        return KernelError::InvalidArgument.code();
    };
    if command[1] != exchange.expected_ins {
        session.mismatch = Some(format!(
            "{} expected INS {:02x}, got {:02x}",
            exchange.label, exchange.expected_ins, command[1]
        ));
        return KernelError::InvalidArgument.code();
    }
    let response = exchange.response.as_slice();
    let capacity = *resp_len;
    *resp_len = response.len();
    if capacity < response.len() || resp.is_null() {
        return KernelError::BufferTooSmall.code();
    }
    ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
    KernelError::Ok.code()
}

unsafe extern "C" fn nfc_unpredictable_number(
    out: *mut u8,
    out_len: usize,
    user_data: *mut c_void,
) -> i32 {
    if out.is_null() || user_data.is_null() || out_len < 4 {
        return KernelError::InvalidArgument.code();
    }
    let session = &*(user_data as *const MobileNfcSession);
    ptr::copy_nonoverlapping(session.unpredictable_number.as_ptr(), out, 4);
    KernelError::Ok.code()
}

unsafe extern "C" fn mobile_contactless_outcome(
    outcome: *const KrnContactlessOutcome,
    user_data: *mut c_void,
) {
    if outcome.is_null() || user_data.is_null() {
        return;
    }
    let session = &mut *(user_data as *mut MobileNfcSession);
    let outcome = &*outcome;
    session.contactless_events.push(ContactlessEvent {
        outcome_code: outcome.outcome_code,
        start_signal: outcome.start_signal,
        ui_message_id: outcome.ui_message_id,
        ui_status: outcome.ui_status,
        restart_required: outcome.restart_required != 0,
        alternate_interface: outcome.alternate_interface,
        data_record_len: outcome.data_record_len,
        discretionary_data_len: outcome.discretionary_data_len,
    });
}

impl SoftPosSummary {
    fn to_json(&self) -> String {
        let command_flow = self
            .command_flow
            .iter()
            .map(|ins| format!("\"{:02x}\"", ins))
            .collect::<Vec<_>>()
            .join(",");
        let contactless_events = self
            .contactless_events
            .iter()
            .map(ContactlessEvent::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"type\":\"basic-softpos-sale\",\"initial_outcome\":{},\"final_outcome\":{},\"last_error\":{},\"fsm_state\":{},\"profile_version\":{},\"profile_sha256\":\"{}\",\"certification_bundle_sha256\":\"{}\",\"online_authorization_len\":{},\"apdu_timeout_ms\":{},\"wallet_cdcvm_performed\":{},\"command_flow\":[{}],\"contactless_events\":[{}]}}",
            self.initial_outcome,
            self.final_outcome,
            self.last_error,
            self.fsm_state,
            self.profile_version,
            to_hex(&self.profile_sha256),
            to_hex(&self.certification_bundle_sha256),
            self.online_authorization_len,
            self.apdu_timeout_ms,
            self.wallet_cdcvm_performed,
            command_flow,
            contactless_events
        )
    }
}

impl ContactlessEvent {
    fn to_json(&self) -> String {
        format!(
            "{{\"outcome_code\":{},\"start_signal\":{},\"ui_message_id\":{},\"ui_status\":{},\"restart_required\":{},\"alternate_interface\":{},\"data_record_len\":{},\"discretionary_data_len\":{}}}",
            self.outcome_code,
            self.start_signal,
            self.ui_message_id,
            self.ui_status,
            self.restart_required,
            self.alternate_interface,
            self.data_record_len,
            self.discretionary_data_len
        )
    }
}

fn ppse_directory_response() -> Vec<u8> {
    vec![
        0x6f, 0x23, 0x84, 0x0e, b'2', b'P', b'A', b'Y', b'.', b'S', b'Y', b'S', b'.', b'D', b'D',
        b'F', b'0', b'1', 0xa5, 0x11, 0xbf, 0x0c, 0x0e, 0x61, 0x0c, 0x4f, 0x07, 0xa0, 0x00, 0x00,
        0x00, 0x03, 0x10, 0x10, 0x87, 0x01, 0x01, 0x90, 0x00,
    ]
}

fn selected_contactless_fci_response(aid: &[u8]) -> Vec<u8> {
    let mut response = vec![0x6f, 0x14, 0x84, aid.len() as u8];
    response.extend_from_slice(aid);
    response.extend_from_slice(&[
        0xa5, 0x09, 0x9f, 0x38, 0x06, 0x9f, 0x66, 0x04, 0x9f, 0x37, 0x04,
    ]);
    response.extend_from_slice(&[0x90, 0x00]);
    response
}

fn gpo_aip_afl_response() -> Vec<u8> {
    vec![
        0x77, 0x0a, 0x82, 0x02, 0x80, 0x00, 0x94, 0x04, 0x10, 0x01, 0x01, 0x00, 0x90, 0x00,
    ]
}

fn application_record_response() -> Vec<u8> {
    vec![
        0x70, 0x67, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f, 0x5f, 0x24, 0x03,
        0x30, 0x12, 0x31, 0x5f, 0x25, 0x03, 0x25, 0x01, 0x01, 0x5f, 0x28, 0x02, 0x08, 0x40, 0x9f,
        0x07, 0x02, 0xff, 0x80, 0x9f, 0x09, 0x02, 0x00, 0x01, 0x8e, 0x0a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x9f, 0x0d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f,
        0x0e, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f, 0x0f, 0x05, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x8c, 0x12, 0x9f, 0x02, 0x06, 0x9f, 0x37, 0x04, 0x95, 0x05, 0x9a, 0x03, 0x9c, 0x01, 0x9f,
        0x1a, 0x02, 0x9f, 0x34, 0x03, 0x8d, 0x08, 0x8a, 0x02, 0x91, 0x08, 0x95, 0x05, 0x9b, 0x02,
        0x90, 0x00,
    ]
}

fn first_gac_arqc_response() -> Vec<u8> {
    vec![
        0x77, 0x1a, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x19, 0x9f, 0x26, 0x08, 0x51,
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x9f, 0x10, 0x03, 0xba, 0xdc, 0x0d, 0x90, 0x00,
    ]
}

fn status_success_response() -> Vec<u8> {
    vec![0x90, 0x00]
}

fn second_gac_tc_response() -> Vec<u8> {
    vec![
        0x77, 0x1a, 0x9f, 0x27, 0x01, 0x40, 0x9f, 0x36, 0x02, 0x00, 0x1a, 0x9f, 0x26, 0x08, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x9f, 0x10, 0x03, 0xac, 0xed, 0x01, 0x90, 0x00,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_emv::ffi::KrnOutcome;

    #[test]
    fn basic_softpos_runs_contactless_sale_from_nfc_to_host_to_final_gac() {
        let sale = SoftPosSale {
            amount_minor: 4_200,
            currency_code: 840,
            country_code: 840,
            merchant_category_code: [0x53, 0x11],
            merchant_name_location: b"DATACRAFT SOFTPOS*NAIROBI",
            wallet_cdcvm_performed: true,
        };
        let mut nfc = MobileNfcSession::contactless_visa_arqc_then_tc();
        let host = AcquirerHost;

        let summary = run_softpos_sale(&sale, &mut nfc, &host).unwrap();

        assert_eq!(summary.initial_outcome, KrnOutcome::OnlineRequired as i32);
        assert_eq!(summary.final_outcome, KrnOutcome::ApprovedOnline as i32);
        assert_eq!(summary.last_error, KernelError::Ok.code());
        assert_eq!(
            summary.command_flow,
            vec![0xa4, 0xa4, 0xa8, 0xb2, 0xae, 0x82, 0xae]
        );
        assert!(summary.online_authorization_len > 0);
        assert!(summary.apdu_timeout_ms > 0);
        assert!(summary.wallet_cdcvm_performed);
        assert_eq!(summary.certification_bundle_sha256.len(), 32);
        assert!(nfc.observed_commands[2]
            .windows(4)
            .any(|window| window == [0x36, 0x00, 0x40, 0x00]));
        assert!(summary
            .to_json()
            .contains("\"type\":\"basic-softpos-sale\""));
        assert!(summary
            .to_json()
            .contains("\"certification_bundle_sha256\":"));
        assert!(summary
            .to_json()
            .contains("\"wallet_cdcvm_performed\":true"));
        assert!(!summary.to_json().contains("123456789012345"));
        assert!(!summary.to_json().contains("DATACRAFT SOFTPOS"));
    }
}
