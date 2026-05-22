use hyperion_emv::ffi::{
    krn_context_free, krn_get_fsm_state, krn_get_last_error, krn_init, krn_load_profiles_verified,
    krn_run_transaction, krn_set_transaction_params, KrnContext, KrnRuntime, KrnTxnParams,
    KRN_ABI_VERSION,
};
use hyperion_emv::KernelError;
use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::slice;

struct ScriptedExchange {
    label: &'static str,
    expected_ins: u8,
    response: Vec<u8>,
}

struct ScriptedApduAdapter {
    exchanges: Vec<ScriptedExchange>,
    observed_commands: Vec<Vec<u8>>,
    timeout_ms: Vec<i32>,
    rng: [u8; 4],
    mismatch: Option<String>,
}

#[derive(Debug)]
struct ScriptRun {
    outcome: i32,
    last_error: i32,
    fsm_state: u8,
    command_count: usize,
    command_ins: Vec<u8>,
}

struct ContextGuard(*mut KrnContext);

impl Drop for ContextGuard {
    fn drop(&mut self) {
        unsafe {
            krn_context_free(self.0);
        }
    }
}

impl ScriptedApduAdapter {
    fn contact_online_fixture() -> Self {
        Self {
            exchanges: vec![
                ScriptedExchange {
                    label: "select-pse",
                    expected_ins: 0xa4,
                    response: pse_directory_response(),
                },
                ScriptedExchange {
                    label: "select-aid",
                    expected_ins: 0xa4,
                    response: selected_fci_response(&[0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]),
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
            ],
            observed_commands: Vec::new(),
            timeout_ms: Vec::new(),
            rng: [0x11, 0x22, 0x33, 0x44],
            mismatch: None,
        }
    }

    fn observed_ins(&self) -> Vec<u8> {
        self.observed_commands
            .iter()
            .filter_map(|command| command.get(1).copied())
            .collect()
    }

    fn consumed_all(&self) -> bool {
        self.observed_commands.len() == self.exchanges.len()
    }
}

fn main() {
    let mut adapter = ScriptedApduAdapter::contact_online_fixture();
    match run_contact_online_script(&mut adapter) {
        Ok(run) => {
            println!(
                "outcome={} last_error={} fsm_state={} commands={} ins={:02x?} complete={}",
                run.outcome,
                run.last_error,
                run.fsm_state,
                run.command_count,
                run.command_ins,
                adapter.consumed_all()
            );
        }
        Err(err) => {
            eprintln!("script failed: {err}");
            std::process::exit(1);
        }
    }
}

fn run_contact_online_script(adapter: &mut ScriptedApduAdapter) -> Result<ScriptRun, String> {
    unsafe {
        let mut ctx = ptr::null_mut();
        let runtime = KrnRuntime {
            abi_version: KRN_ABI_VERSION,
            struct_size: mem::size_of::<KrnRuntime>() as u32,
            transmit_apdu: Some(script_transmit_apdu),
            get_unpredictable_number: Some(script_unpredictable_number),
            contactless_outcome: None,
            user_data: adapter as *mut ScriptedApduAdapter as *mut c_void,
        };
        require_ok(krn_init(ptr::null(), &runtime, &mut ctx), "krn_init")?;
        let guard = ContextGuard(ctx);
        let profiles = include_bytes!("../docs/scheme_profiles.cert.json");
        require_ok(
            krn_load_profiles_verified(guard.0, profiles.as_ptr(), profiles.len(), 1, 2, 26, 5, 21),
            "krn_load_profiles_verified",
        )?;
        let params = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 2_000,
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
        require_ok(
            krn_set_transaction_params(guard.0, &params),
            "krn_set_transaction_params",
        )?;

        let outcome = krn_run_transaction(guard.0);
        let last_error = krn_get_last_error(guard.0);
        let fsm_state = krn_get_fsm_state(guard.0);
        if let Some(mismatch) = adapter.mismatch.as_ref() {
            return Err(mismatch.clone());
        }
        Ok(ScriptRun {
            outcome,
            last_error,
            fsm_state,
            command_count: adapter.observed_commands.len(),
            command_ins: adapter.observed_ins(),
        })
    }
}

fn require_ok(status: i32, operation: &str) -> Result<(), String> {
    if status == KernelError::Ok.code() {
        Ok(())
    } else {
        Err(format!("{operation} returned status {status}"))
    }
}

unsafe extern "C" fn script_transmit_apdu(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32 {
    if cmd.is_null() || resp_len.is_null() || user_data.is_null() || cmd_len < 4 {
        return KernelError::InvalidArgument.code();
    }
    let adapter = &mut *(user_data as *mut ScriptedApduAdapter);
    let command = slice::from_raw_parts(cmd, cmd_len);
    adapter.observed_commands.push(command.to_vec());
    adapter.timeout_ms.push(timeout_ms);
    let Some(exchange) = adapter
        .exchanges
        .get(adapter.observed_commands.len().saturating_sub(1))
    else {
        adapter.mismatch = Some("kernel sent more APDUs than the script defined".to_string());
        return KernelError::InvalidArgument.code();
    };
    if command[1] != exchange.expected_ins {
        adapter.mismatch = Some(format!(
            "{} expected INS {:02x}, got {:02x}",
            exchange.label, exchange.expected_ins, command[1]
        ));
        return KernelError::InvalidArgument.code();
    }

    let response = exchange.response.as_slice();
    let capacity = *resp_len;
    *resp_len = response.len();
    if capacity < response.len() {
        return KernelError::BufferTooSmall.code();
    }
    if !resp.is_null() {
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
    }
    KernelError::Ok.code()
}

unsafe extern "C" fn script_unpredictable_number(
    out: *mut u8,
    out_len: usize,
    user_data: *mut c_void,
) -> i32 {
    if out.is_null() || user_data.is_null() || out_len < 4 {
        return KernelError::InvalidArgument.code();
    }
    let adapter = &*(user_data as *const ScriptedApduAdapter);
    ptr::copy_nonoverlapping(adapter.rng.as_ptr(), out, adapter.rng.len());
    KernelError::Ok.code()
}

fn pse_directory_response() -> Vec<u8> {
    vec![
        0x6f, 0x1b, 0xa5, 0x19, 0xbf, 0x0c, 0x16, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00,
        0x03, 0x10, 0x10, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x90,
        0x00,
    ]
}

fn selected_fci_response(aid: &[u8]) -> Vec<u8> {
    let mut response = vec![0x6f, 0x11, 0x84, aid.len() as u8];
    response.extend_from_slice(aid);
    response.extend_from_slice(&[0xa5, 0x06, 0x9f, 0x38, 0x03, 0x9f, 0x37, 0x04, 0x90, 0x00]);
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
        0x77, 0x1a, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x9f, 0x10, 0x03, 0xaa, 0xbb, 0xcc, 0x90, 0x00,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_emv::ffi::KrnOutcome;
    use hyperion_emv::fsm::FsmState;

    #[test]
    fn script_adapter_drives_contact_transaction_to_online_request() {
        let mut adapter = ScriptedApduAdapter::contact_online_fixture();

        let run = run_contact_online_script(&mut adapter).unwrap();

        assert_eq!(run.outcome, KrnOutcome::OnlineRequired as i32);
        assert_eq!(run.last_error, KernelError::Ok.code());
        assert_eq!(run.fsm_state, FsmState::S11.code());
        assert_eq!(run.command_count, 5);
        assert_eq!(run.command_ins, vec![0xa4, 0xa4, 0xa8, 0xb2, 0xae]);
        assert_eq!(adapter.timeout_ms, vec![500, 500, 500, 500, 500]);
        assert!(adapter.consumed_all());
    }

    #[test]
    fn script_adapter_fails_closed_on_unexpected_apdu() {
        let mut adapter = ScriptedApduAdapter::contact_online_fixture();
        adapter.exchanges[0].expected_ins = 0xb2;

        let err = run_contact_online_script(&mut adapter).unwrap_err();

        assert!(err.contains("select-pse expected INS b2, got a4"));
        assert_eq!(adapter.observed_ins(), vec![0xa4]);
    }
}
