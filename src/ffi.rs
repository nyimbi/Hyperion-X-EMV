use crate::afl::{record_plan, AflEntry};
use crate::apdu::{self, CdaRequestControl, CryptogramRequest, Interface};
use crate::c8::{
    AlternateInterface, ContactlessOutcome, ContactlessOutcomeCode, KrnContactlessOutcome,
    StartSignal, UiRequest, UiStatus,
};
use crate::cid::CryptogramType;
use crate::config::{
    load_profile_set, AidProfile, BuildMode, ConfigLoadPolicy, ProfileSet, SignatureStatus,
};
use crate::cvm::{
    evaluate as evaluate_cvm, parse_cvm_list, CvmAction, CvmContext, CvmOutcome,
    Interface as CvmInterface,
};
use crate::dol::{build_dol, parse_dol, DataStore};
use crate::error::{KernelError, ERROR_TABLE};
use crate::fsm::{self, FsmEvent, FsmState};
use crate::gac::{
    build_online_authorization_package, parse_generate_ac_response, GenerateAcResponse,
    OnlineAuthorizationPackage,
};
use crate::gpo::{parse_gpo_response, parse_pdol_from_fci, GpoResponseFormat};
use crate::issuer::{
    apply_script_results, parse_host_response, HostResponse, ScriptCommandResult, ScriptPhase,
};
use crate::oda::{
    apply_oda_outcome, select_capk, select_oda_method, selection_input_from_aip, CapkIntegrity,
    OdaFailure, OdaMethod, OdaOutcome, OdaSelection,
};
use crate::record::parse_read_record_body;
use crate::restrictions::{
    evaluate as evaluate_restrictions, ApplicationUsageControl, EmvDate, RestrictionInput,
    ServiceType, TransactionRegion,
};
use crate::selection::{
    direct_profile_candidates, match_profile_candidates, parse_fci_candidate_aids,
    SelectionCandidate,
};
use crate::state::{KernelState, Tsi, Tvr};
use crate::sw::{classify, ApduContext, StatusAction, StatusWord};
use crate::taa::{decide as decide_taa, ActionCodes, TaaInput, TerminalAction};
use crate::trm::{evaluate as evaluate_trm, TrmInput};
use core::mem;
use core::ptr;
use std::ffi::c_void;
use std::slice;

pub type KrnContactlessOutcomeCallback =
    unsafe extern "C" fn(outcome: *const KrnContactlessOutcome, user_data: *mut c_void);
pub type KrnTransmitApduCallback = unsafe extern "C" fn(
    cmd: *const u8,
    cmd_len: usize,
    resp: *mut u8,
    resp_len: *mut usize,
    timeout_ms: i32,
    user_data: *mut c_void,
) -> i32;
pub type KrnGetUnpredictableNumberCallback =
    unsafe extern "C" fn(out: *mut u8, out_len: usize, user_data: *mut c_void) -> i32;

pub const KRN_ABI_VERSION: u32 = 1;
pub const MAX_MERCHANT_NAME_LOCATION_LEN: usize = 128;
pub const MAX_APDU_RESPONSE_LEN: usize = 258;
pub const MAX_ONLINE_AUTH_DATA_LEN: usize = 1024;
pub const MAX_HOST_RESPONSE_LEN: usize = 1024;
pub const APDU_TRANSMIT_TIMEOUT_MS: i32 = 500;
const MAX_APDU_FOLLOWUPS: usize = 4;

#[repr(C)]
pub struct KrnConfigBlob {
    pub abi_version: u32,
    pub struct_size: u32,
    pub bytes: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct KrnRuntime {
    pub abi_version: u32,
    pub struct_size: u32,
    pub transmit_apdu: Option<KrnTransmitApduCallback>,
    pub get_unpredictable_number: Option<KrnGetUnpredictableNumberCallback>,
    pub contactless_outcome: Option<KrnContactlessOutcomeCallback>,
    pub user_data: *mut c_void,
}

#[derive(Clone, Copy)]
struct RuntimeCallbacks {
    transmit_apdu: KrnTransmitApduCallback,
    get_unpredictable_number: KrnGetUnpredictableNumberCallback,
    contactless_outcome: Option<KrnContactlessOutcomeCallback>,
    user_data: *mut c_void,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KrnOutcome {
    ApprovedOffline = 0,
    DeclinedOffline = 1,
    ApprovedOnline = 2,
    DeclinedOnline = 3,
    TryAgain = 4,
    AlternateInterface = 5,
    SelectNext = 6,
    Terminated = 7,
    Error = 8,
}

impl KrnOutcome {
    fn code(self) -> i32 {
        self as i32
    }
}

#[repr(C)]
pub struct KrnTxnParams {
    pub struct_size: u32,
    pub amount_authorised_minor: u64,
    pub amount_other_minor: u64,
    pub currency_code: u16,
    pub terminal_country_code: u16,
    pub transaction_type: u8,
    pub terminal_type: u8,
    pub merchant_category_code: [u8; 2],
    pub interface_preference: u8,
    pub merchant_name_location: *const u8,
    pub merchant_name_location_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredTxnParams {
    pub amount_authorised_minor: u64,
    pub amount_other_minor: u64,
    pub currency_code: u16,
    pub terminal_country_code: u16,
    pub transaction_type: u8,
    pub terminal_type: u8,
    pub merchant_category_code: [u8; 2],
    pub interface_preference: u8,
    pub merchant_name_location: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedApplication {
    aid: Vec<u8>,
    scheme_index: usize,
    aid_index: usize,
    aip: Option<[u8; 2]>,
    afl: Vec<AflEntry>,
}

#[repr(C)]
pub struct KrnContext {
    state: KernelState,
    fsm_state: FsmState,
    tvr: Tvr,
    tsi: Tsi,
    last_error: KernelError,
    busy: bool,
    txn_params: Option<StoredTxnParams>,
    profiles: Option<ProfileSet>,
    profile_evaluation_date: Option<EmvDate>,
    selected_application: Option<SelectedApplication>,
    requested_cryptogram: Option<CryptogramRequest>,
    first_gac_response: Option<GenerateAcResponse>,
    final_gac_response: Option<GenerateAcResponse>,
    final_outcome: Option<KrnOutcome>,
    online_authorization_data: Option<Vec<u8>>,
    host_response: Option<HostResponse>,
    issuer_script_results: Vec<ScriptCommandResult>,
    card_data: DataStore,
    last_unpredictable_number: Option<[u8; 4]>,
    runtime: Option<RuntimeCallbacks>,
    contactless_outcome_callback: Option<KrnContactlessOutcomeCallback>,
    contactless_outcome_user_data: *mut c_void,
}

impl KrnContext {
    fn new() -> Self {
        Self {
            state: KernelState::Idle,
            fsm_state: FsmState::S0,
            tvr: Tvr::cleared(),
            tsi: Tsi::cleared(),
            last_error: KernelError::Ok,
            busy: false,
            txn_params: None,
            profiles: None,
            profile_evaluation_date: None,
            selected_application: None,
            requested_cryptogram: None,
            first_gac_response: None,
            final_gac_response: None,
            final_outcome: None,
            online_authorization_data: None,
            host_response: None,
            issuer_script_results: Vec::new(),
            card_data: DataStore::new(),
            last_unpredictable_number: None,
            runtime: None,
            contactless_outcome_callback: None,
            contactless_outcome_user_data: ptr::null_mut(),
        }
    }

    fn reset(&mut self) {
        self.state = KernelState::Idle;
        self.fsm_state = FsmState::S0;
        self.tvr = Tvr::cleared();
        self.tsi = Tsi::cleared();
        self.last_error = KernelError::Ok;
        self.busy = false;
        self.txn_params = None;
        self.selected_application = None;
        self.requested_cryptogram = None;
        self.first_gac_response = None;
        self.final_gac_response = None;
        self.final_outcome = None;
        self.online_authorization_data = None;
        self.host_response = None;
        self.issuer_script_results.clear();
        self.card_data = DataStore::new();
    }

    fn set_result(&mut self, result: Result<usize, KernelError>) -> i32 {
        match result {
            Ok(_) => {
                self.last_error = KernelError::Ok;
                KernelError::Ok.code()
            }
            Err(err) => {
                self.last_error = err;
                err.code()
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn krn_context_new() -> *mut KrnContext {
    Box::into_raw(Box::new(KrnContext::new()))
}

/// Initializes a kernel context from ABI-versioned runtime callbacks.
///
/// # Safety
///
/// `runtime` and `out_kernel` must be valid pointers. `cfg` may be null in the
/// current construction-only profile; when present, its ABI fields are checked
/// and its byte pointer must be non-null for non-zero lengths. The returned
/// context must be freed with [`krn_context_free`].
#[no_mangle]
pub unsafe extern "C" fn krn_init(
    cfg: *const KrnConfigBlob,
    runtime: *const KrnRuntime,
    out_kernel: *mut *mut KrnContext,
) -> i32 {
    if out_kernel.is_null() {
        return KernelError::InvalidArgument.code();
    }
    *out_kernel = ptr::null_mut();
    if let Err(err) = validate_config_blob(cfg) {
        return err.code();
    }
    let callbacks = match read_runtime(runtime) {
        Ok(callbacks) => callbacks,
        Err(err) => return err.code(),
    };
    let mut ctx = KrnContext::new();
    ctx.contactless_outcome_callback = callbacks.contactless_outcome;
    ctx.contactless_outcome_user_data = callbacks.user_data;
    ctx.runtime = Some(callbacks);
    *out_kernel = Box::into_raw(Box::new(ctx));
    KernelError::Ok.code()
}

/// Frees a kernel context allocated by [`krn_context_new`].
///
/// # Safety
///
/// `ctx` must be either null or a pointer returned by `krn_context_new` that
/// has not already been freed. After this call returns, the pointer must not be
/// used again.
#[no_mangle]
pub unsafe extern "C" fn krn_context_free(ctx: *mut KrnContext) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

/// Resets a kernel context to the idle state and clears TVR/TSI/error state.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed pointer returned by
/// `krn_context_new`. Calls for the same context must be serialized by the
/// integration layer.
#[no_mangle]
pub unsafe extern "C" fn krn_reset(ctx: *mut KrnContext) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    ctx.reset();
    KernelError::Ok.code()
}

/// Returns the last kernel error code for a context.
///
/// # Safety
///
/// `ctx` must be null or a valid pointer returned by `krn_context_new`. The
/// function does not take ownership of the pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_get_last_error(ctx: *const KrnContext) -> i32 {
    let Some(ctx) = ctx.as_ref() else {
        return KernelError::InvalidArgument.code();
    };
    ctx.last_error.code()
}

/// Returns the current transaction FSM state code for diagnostics.
///
/// # Safety
///
/// `ctx` must be null or a valid pointer returned by `krn_context_new`. The
/// function does not take ownership of the pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_get_fsm_state(ctx: *const KrnContext) -> u8 {
    let Some(ctx) = ctx.as_ref() else {
        return FsmState::Se.code();
    };
    ctx.fsm_state.code()
}

/// Stores transaction parameters and moves the transaction FSM to S1.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `params` must
/// point to a readable [`KrnTxnParams`] whose `struct_size` exactly matches this
/// ABI version. `merchant_name_location` may be null only when its length is
/// zero, and its contents are copied before the function returns.
#[no_mangle]
pub unsafe extern "C" fn krn_set_transaction_params(
    ctx: *mut KrnContext,
    params: *const KrnTxnParams,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let result = read_transaction_params(params).and_then(|stored| {
        let transition = fsm::transition(FsmState::S0, FsmEvent::SetTransactionParams)?;
        ctx.txn_params = Some(stored);
        ctx.tvr = Tvr::cleared();
        ctx.tsi = Tsi::cleared();
        ctx.selected_application = None;
        ctx.requested_cryptogram = None;
        ctx.first_gac_response = None;
        ctx.online_authorization_data = None;
        ctx.host_response = None;
        ctx.card_data = DataStore::new();
        ctx.state = KernelState::ParamsSet;
        ctx.fsm_state = transition.to;
        Ok(0usize)
    });
    ctx.set_result(result)
}

/// Loads an externally verified scheme profile set into an existing context.
///
/// This function does not perform cryptographic signature verification itself;
/// the caller may only use it after the platform trust layer has verified the
/// profile signature and rollback counter. Certification/production loading is
/// still strict and rejects placeholders, expired CAPKs, rollback versions, and
/// malformed hex material.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `json` must point
/// to `json_len` readable bytes. The profile bytes are parsed and copied before
/// the function returns.
#[no_mangle]
pub unsafe extern "C" fn krn_load_profiles_verified(
    ctx: *mut KrnContext,
    json: *const u8,
    json_len: usize,
    installed_version: u64,
    candidate_version: u64,
    eval_year: u8,
    eval_month: u8,
    eval_day: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let result = readable_slice(json, json_len).and_then(|bytes| {
        let evaluation_date = EmvDate {
            year: eval_year,
            month: eval_month,
            day: eval_day,
        };
        let profiles = load_profile_set(
            bytes,
            &ConfigLoadPolicy {
                mode: BuildMode::Certification,
                signature_status: SignatureStatus::Verified,
                installed_version,
                candidate_version,
                evaluation_date,
            },
        )?;
        ctx.profiles = Some(profiles);
        ctx.profile_evaluation_date = Some(evaluation_date);
        Ok(0usize)
    });
    ctx.set_result(result)
}

/// Runs a transaction through the stable ABI entrypoint.
///
/// The full callback-driven runner is not complete yet. Until mandatory
/// transport/runtime callbacks are registered by a future initialization API,
/// this function fails explicitly and leaves the context in the error state
/// rather than returning a synthetic payment outcome.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. Calls for the same
/// context must be serialized by the integration layer.
#[no_mangle]
pub unsafe extern "C" fn krn_run_transaction(ctx: *mut KrnContext) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KrnOutcome::Error.code();
    };
    if ctx.busy {
        ctx.last_error = KernelError::Busy;
        return KrnOutcome::Error.code();
    }
    ctx.busy = true;
    let outcome = run_transaction(ctx);
    ctx.busy = false;
    outcome.code()
}

/// Builds the contact PSE or contactless PPSE SELECT APDU into a caller buffer.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `out_len` must
/// point to a writable `usize`; on input it contains `out` capacity and on
/// output it receives the required APDU length. `out` may be null only for a
/// size query, otherwise it must point to at least the input capacity bytes.
#[no_mangle]
pub unsafe extern "C" fn krn_build_select_environment(
    ctx: *mut KrnContext,
    contactless: bool,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };

    let interface = if contactless {
        Interface::Contactless
    } else {
        Interface::Contact
    };
    let encoded = apdu::select_environment(interface).encode();
    let result = encoded.and_then(|bytes| write_output(&bytes, out, out_len));
    ctx.set_result(result)
}

/// Builds a GENERATE AC APDU into a caller buffer.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. If `cdol_len` is
/// non-zero, `cdol_values` must point to `cdol_len` readable bytes. `out_len`
/// and `out` follow the same caller-owned buffer contract as
/// `krn_build_select_environment`.
#[no_mangle]
pub unsafe extern "C" fn krn_build_generate_ac(
    ctx: *mut KrnContext,
    request: u8,
    cdol_values: *const u8,
    cdol_len: usize,
    cda_p1_low_bits: u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if cdol_values.is_null() && cdol_len != 0 {
        ctx.last_error = KernelError::InvalidArgument;
        return KernelError::InvalidArgument.code();
    }

    let request = match request {
        0 => CryptogramRequest::Aac,
        1 => CryptogramRequest::Tc,
        2 => CryptogramRequest::Arqc,
        _ => {
            ctx.last_error = KernelError::InvalidArgument;
            return KernelError::InvalidArgument.code();
        }
    };
    let values = if cdol_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(cdol_values, cdol_len)
    };
    let cda_control = if cda_p1_low_bits == 0 {
        CdaRequestControl::NotRequested
    } else {
        CdaRequestControl::P1LowBits(cda_p1_low_bits)
    };
    let encoded = apdu::generate_ac(request, values, cda_control).and_then(|cmd| cmd.encode());
    let result = encoded.and_then(|bytes| write_output(&bytes, out, out_len));
    ctx.set_result(result)
}

/// Copies the encoded online authorization TLV package for Level 3 handoff.
///
/// The package is available after the first GENERATE AC returns ARQC and the
/// transaction FSM reaches S11. The kernel only packages ICC/terminal data; it
/// does not format host messages, validate ARQC, or generate ARPC.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `out_len` must
/// point to a writable `usize`; on input it contains `out` capacity and on
/// output it receives the required payload length. `out` may be null only for a
/// size query.
#[no_mangle]
pub unsafe extern "C" fn krn_get_online_authorization_data(
    ctx: *mut KrnContext,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let result = ctx
        .online_authorization_data
        .as_deref()
        .ok_or(KernelError::InvalidArgument)
        .and_then(|bytes| write_output(bytes, out, out_len));
    ctx.set_result(result)
}

/// Applies a Level 3 host response while the transaction is waiting at S11.
///
/// The input is BER-TLV data containing at least tag `8A` Authorization
/// Response Code. Optional tag `91` issuer authentication data and issuer
/// script templates `71`/`72` are parsed and retained for later kernel phases.
/// This function does not validate ARQC, generate ARPC, or perform host
/// messaging.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `host_response`
/// must point to `host_response_len` readable bytes unless the length is zero,
/// which is rejected.
#[no_mangle]
pub unsafe extern "C" fn krn_apply_host_response(
    ctx: *mut KrnContext,
    host_response: *const u8,
    host_response_len: usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let result = readable_slice(host_response, host_response_len).and_then(|bytes| {
        if bytes.is_empty() || bytes.len() > MAX_HOST_RESPONSE_LEN {
            return Err(KernelError::LengthOverflow);
        }
        apply_host_response(ctx, bytes)?;
        Ok(0usize)
    });
    ctx.set_result(result)
}

/// Processes S12 issuer authentication using host-provided tag `91`.
///
/// This sends EXTERNAL AUTHENTICATE with the issuer authentication data that
/// was previously supplied through `krn_apply_host_response`. The kernel does
/// not generate ARPC or hold issuer keys; it only forwards the host-provided
/// value to the card and records TSI/TVR according to the card response.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. Calls for the same
/// context must be serialized by the integration layer.
#[no_mangle]
pub unsafe extern "C" fn krn_process_issuer_authentication(ctx: *mut KrnContext) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if ctx.busy {
        ctx.last_error = KernelError::Busy;
        return KernelError::Busy.code();
    }
    let Some(runtime) = ctx.runtime else {
        ctx.last_error = KernelError::InvalidArgument;
        return KernelError::InvalidArgument.code();
    };

    ctx.busy = true;
    let result = run_issuer_authentication(ctx, runtime).map(|()| 0usize);
    ctx.busy = false;
    ctx.set_result(result)
}

/// Executes issuer script APDU commands parsed from host response templates.
///
/// Scripts are executed in host-provided order. SW1/SW2 for each command is
/// retained in the context, non-critical failures update TVR/TSI according to
/// the script template phase, and the FSM advances to second GENERATE AC when
/// all Template 71 scripts have been consumed. Template 72 scripts are retained
/// for `krn_process_post_final_issuer_scripts`.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. Calls for the same
/// context must be serialized by the integration layer.
#[no_mangle]
pub unsafe extern "C" fn krn_process_issuer_scripts(ctx: *mut KrnContext) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if ctx.busy {
        ctx.last_error = KernelError::Busy;
        return KernelError::Busy.code();
    }
    let Some(runtime) = ctx.runtime else {
        ctx.last_error = KernelError::InvalidArgument;
        return KernelError::InvalidArgument.code();
    };

    ctx.busy = true;
    let result = run_issuer_scripts(ctx, runtime).map(|()| 0usize);
    ctx.busy = false;
    ctx.set_result(result)
}

/// Executes Template 72 issuer scripts after second GENERATE AC.
///
/// This entry point runs only host-provided post-final-GAC issuer scripts and
/// then advances the FSM to final completion. It does not alter the
/// card-generated final cryptogram or the host authorization decision.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. Calls for the same
/// context must be serialized by the integration layer.
#[no_mangle]
pub unsafe extern "C" fn krn_process_post_final_issuer_scripts(ctx: *mut KrnContext) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if ctx.busy {
        ctx.last_error = KernelError::Busy;
        return KernelError::Busy.code();
    }
    let Some(runtime) = ctx.runtime else {
        ctx.last_error = KernelError::InvalidArgument;
        return KernelError::InvalidArgument.code();
    };

    ctx.busy = true;
    let result = run_post_final_issuer_scripts(ctx, runtime).map(|()| 0usize);
    ctx.busy = false;
    ctx.set_result(result)
}

/// Issues second GENERATE AC from CDOL2 after online authorization.
///
/// The request type is derived from the host authorization response code: `00`
/// requests TC and other response codes request AAC. Cryptograms remain
/// card-generated; the kernel only constructs CDOL2 and parses the response.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. Calls for the same
/// context must be serialized by the integration layer.
#[no_mangle]
pub unsafe extern "C" fn krn_process_final_generate_ac(ctx: *mut KrnContext) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if ctx.busy {
        ctx.last_error = KernelError::Busy;
        return KernelError::Busy.code();
    }
    let Some(runtime) = ctx.runtime else {
        ctx.last_error = KernelError::InvalidArgument;
        return KernelError::InvalidArgument.code();
    };

    ctx.busy = true;
    let result = run_final_generate_ac(ctx, runtime).map(|()| 0usize);
    ctx.busy = false;
    ctx.set_result(result)
}

/// Returns the number of captured issuer script command status words.
///
/// # Safety
///
/// `ctx` must be either null or a valid context pointer. Null returns zero.
#[no_mangle]
pub unsafe extern "C" fn krn_get_issuer_script_result_count(ctx: *const KrnContext) -> usize {
    let Some(ctx) = ctx.as_ref() else {
        return 0;
    };
    ctx.issuer_script_results.len()
}

/// Copies one captured issuer script command SW1/SW2 pair to caller storage.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `sw1` and `sw2`
/// must point to writable bytes.
#[no_mangle]
pub unsafe extern "C" fn krn_get_issuer_script_result(
    ctx: *mut KrnContext,
    index: usize,
    sw1: *mut u8,
    sw2: *mut u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let result = (|| {
        if sw1.is_null() || sw2.is_null() {
            return Err(KernelError::InvalidArgument);
        }
        let result = ctx
            .issuer_script_results
            .get(index)
            .ok_or(KernelError::InvalidArgument)?;
        unsafe {
            *sw1 = result.sw1;
            *sw2 = result.sw2;
        }
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Copies the loaded signed profile version for log/build provenance.
///
/// # Safety
///
/// `ctx` must be a valid context pointer. `profile_version` must point to a
/// writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn krn_get_profile_version(
    ctx: *mut KrnContext,
    profile_version: *mut u64,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let result = (|| {
        if profile_version.is_null() {
            return Err(KernelError::InvalidArgument);
        }
        let profiles = ctx.profiles.as_ref().ok_or(KernelError::InvalidProfile)?;
        unsafe {
            *profile_version = profiles.version;
        }
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Returns the last final transaction outcome recorded by the kernel.
///
/// # Safety
///
/// `ctx` must be either null or a valid context pointer. Null returns
/// `KrnOutcome::Error`.
#[no_mangle]
pub unsafe extern "C" fn krn_get_final_outcome(ctx: *const KrnContext) -> i32 {
    let Some(ctx) = ctx.as_ref() else {
        return KrnOutcome::Error.code();
    };
    ctx.final_outcome.unwrap_or(KrnOutcome::Error).code()
}

/// Registers the contactless outcome callback used by C-8/contactless flows.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `callback`, when
/// non-null, must remain callable until it is replaced or the context is freed.
/// `user_data` is never dereferenced by the kernel and is passed back unchanged.
#[no_mangle]
pub unsafe extern "C" fn krn_set_contactless_outcome_callback(
    ctx: *mut KrnContext,
    callback: Option<KrnContactlessOutcomeCallback>,
    user_data: *mut c_void,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    ctx.contactless_outcome_callback = callback;
    ctx.contactless_outcome_user_data = user_data;
    if let Some(runtime) = ctx.runtime.as_mut() {
        runtime.contactless_outcome = callback;
        runtime.user_data = user_data;
    }
    ctx.last_error = KernelError::Ok;
    KernelError::Ok.code()
}

/// Emits a structured contactless outcome through the registered callback.
///
/// This is the ABI boundary shape used by the transaction runner; the pointer
/// fields in the callback view are valid only for the duration of the callback.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `data_record` and
/// `discretionary_data` may be null only when their corresponding length is
/// zero; otherwise they must point to readable buffers of that length.
#[no_mangle]
pub unsafe extern "C" fn krn_emit_contactless_outcome(
    ctx: *mut KrnContext,
    outcome_code: u8,
    start_signal: u8,
    ui_message_id: u16,
    ui_status: u8,
    hold_time_ms: u16,
    restart_required: u8,
    data_record: *const u8,
    data_record_len: usize,
    discretionary_data: *const u8,
    discretionary_data_len: usize,
    alternate_interface: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    let args = RawContactlessOutcomeArgs {
        outcome_code,
        start_signal,
        ui_message_id,
        ui_status,
        hold_time_ms,
        restart_required,
        data_record,
        data_record_len,
        discretionary_data,
        discretionary_data_len,
        alternate_interface,
    };
    let result = emit_contactless_outcome(ctx, args);
    ctx.set_result(result.map(|_| 0usize))
}

#[no_mangle]
pub extern "C" fn krn_abi_version() -> u32 {
    KRN_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn krn_error_table_len() -> usize {
    ERROR_TABLE.len()
}

/// Copies the stable error code at `index` in the ABI error table.
///
/// # Safety
///
/// `out_code` must point to writable `i32` storage.
#[no_mangle]
pub unsafe extern "C" fn krn_error_code_at(index: usize, out_code: *mut i32) -> i32 {
    if out_code.is_null() {
        return KernelError::InvalidArgument.code();
    }
    let Some(error) = ERROR_TABLE.get(index).copied() else {
        return KernelError::InvalidArgument.code();
    };
    unsafe {
        *out_code = error.code();
    }
    KernelError::Ok.code()
}

/// Copies the symbolic stable name for an ABI error code.
///
/// # Safety
///
/// `out_len` must point to writable `usize` storage. `out` may be null only for
/// length probing; otherwise it must point to `*out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn krn_error_name(error_code: i32, out: *mut u8, out_len: *mut usize) -> i32 {
    let Some(error) = KernelError::from_code(error_code) else {
        return KernelError::InvalidArgument.code();
    };
    match write_output(error.name().as_bytes(), out, out_len) {
        Ok(_) => KernelError::Ok.code(),
        Err(err) => err.code(),
    }
}

/// Copies the stable human-readable description for an ABI error code.
///
/// # Safety
///
/// `out_len` must point to writable `usize` storage. `out` may be null only for
/// length probing; otherwise it must point to `*out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn krn_error_description(
    error_code: i32,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(error) = KernelError::from_code(error_code) else {
        return KernelError::InvalidArgument.code();
    };
    match write_output(error.description().as_bytes(), out, out_len) {
        Ok(_) => KernelError::Ok.code(),
        Err(err) => err.code(),
    }
}

#[no_mangle]
pub extern "C" fn krn_context_as_opaque(ctx: *mut KrnContext) -> *mut c_void {
    ctx.cast::<c_void>()
}

unsafe fn write_output(
    bytes: &[u8],
    out: *mut u8,
    out_len: *mut usize,
) -> Result<usize, KernelError> {
    if out_len.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    let capacity = *out_len;
    *out_len = bytes.len();
    if out.is_null() {
        return Err(KernelError::BufferTooSmall);
    }
    if capacity < bytes.len() {
        return Err(KernelError::BufferTooSmall);
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    Ok(bytes.len())
}

unsafe fn validate_config_blob(cfg: *const KrnConfigBlob) -> Result<(), KernelError> {
    if cfg.is_null() {
        return Ok(());
    }
    let abi_version = ptr::addr_of!((*cfg).abi_version).read_unaligned();
    let struct_size = ptr::addr_of!((*cfg).struct_size).read_unaligned() as usize;
    if abi_version != KRN_ABI_VERSION || struct_size != mem::size_of::<KrnConfigBlob>() {
        return Err(KernelError::InvalidArgument);
    }
    let cfg = cfg.as_ref().ok_or(KernelError::InvalidArgument)?;
    if cfg.len != 0 && cfg.bytes.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

unsafe fn read_runtime(runtime: *const KrnRuntime) -> Result<RuntimeCallbacks, KernelError> {
    if runtime.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    let abi_version = ptr::addr_of!((*runtime).abi_version).read_unaligned();
    let struct_size = ptr::addr_of!((*runtime).struct_size).read_unaligned() as usize;
    if abi_version != KRN_ABI_VERSION || struct_size != mem::size_of::<KrnRuntime>() {
        return Err(KernelError::InvalidArgument);
    }
    let runtime = runtime.as_ref().ok_or(KernelError::InvalidArgument)?;
    Ok(RuntimeCallbacks {
        transmit_apdu: runtime.transmit_apdu.ok_or(KernelError::InvalidArgument)?,
        get_unpredictable_number: runtime
            .get_unpredictable_number
            .ok_or(KernelError::InvalidArgument)?,
        contactless_outcome: runtime.contactless_outcome,
        user_data: runtime.user_data,
    })
}

unsafe fn read_transaction_params(
    params: *const KrnTxnParams,
) -> Result<StoredTxnParams, KernelError> {
    if params.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    let struct_size = ptr::addr_of!((*params).struct_size).read_unaligned() as usize;
    if struct_size != mem::size_of::<KrnTxnParams>() {
        return Err(KernelError::InvalidArgument);
    }
    let params = params.as_ref().ok_or(KernelError::InvalidArgument)?;
    if params.interface_preference > 2 {
        return Err(KernelError::InvalidArgument);
    }
    if params.merchant_name_location_len > MAX_MERCHANT_NAME_LOCATION_LEN {
        return Err(KernelError::LengthOverflow);
    }
    let merchant_name_location = readable_slice(
        params.merchant_name_location,
        params.merchant_name_location_len,
    )?
    .to_vec();

    Ok(StoredTxnParams {
        amount_authorised_minor: params.amount_authorised_minor,
        amount_other_minor: params.amount_other_minor,
        currency_code: params.currency_code,
        terminal_country_code: params.terminal_country_code,
        transaction_type: params.transaction_type,
        terminal_type: params.terminal_type,
        merchant_category_code: params.merchant_category_code,
        interface_preference: params.interface_preference,
        merchant_name_location,
    })
}

fn transaction_data_store(
    params: &StoredTxnParams,
    unpredictable_number: [u8; 4],
    transaction_date: EmvDate,
    tvr: Tvr,
    tsi: Tsi,
) -> Result<DataStore, KernelError> {
    let mut data = DataStore::new();
    data.put(
        &[0x9f, 0x02],
        &numeric_bcd_fixed(params.amount_authorised_minor, 6)?,
    )?;
    data.put(
        &[0x9f, 0x03],
        &numeric_bcd_fixed(params.amount_other_minor, 6)?,
    )?;
    data.put(
        &[0x5f, 0x2a],
        &numeric_bcd_fixed(params.currency_code as u64, 2)?,
    )?;
    data.put(
        &[0x9f, 0x1a],
        &numeric_bcd_fixed(params.terminal_country_code as u64, 2)?,
    )?;
    data.put(&[0x9c], &[params.transaction_type])?;
    data.put(&[0x9a], &emv_date_bcd(transaction_date))?;
    data.put(&[0x9f, 0x35], &[params.terminal_type])?;
    data.put(&[0x9f, 0x15], &params.merchant_category_code)?;
    if !params.merchant_name_location.is_empty() {
        data.put(&[0x9f, 0x4e], &params.merchant_name_location)?;
    }
    data.put(&[0x95], &tvr.bytes())?;
    data.put(&[0x9b], &tsi.bytes())?;
    data.put(&[0x9f, 0x37], &unpredictable_number)?;
    Ok(data)
}

fn request_unpredictable_number(
    runtime: RuntimeCallbacks,
    previous: Option<[u8; 4]>,
) -> Result<[u8; 4], KernelError> {
    let mut unpredictable_number = [0u8; 4];
    let status = unsafe {
        (runtime.get_unpredictable_number)(
            unpredictable_number.as_mut_ptr(),
            unpredictable_number.len(),
            runtime.user_data,
        )
    };
    if status != KernelError::Ok.code() {
        return Err(KernelError::RngFailure);
    }
    if unpredictable_number.iter().all(|byte| *byte == 0) || previous == Some(unpredictable_number)
    {
        return Err(KernelError::RngFailure);
    }
    Ok(unpredictable_number)
}

fn encode_online_authorization_package(
    package: &OnlineAuthorizationPackage,
) -> Result<Vec<u8>, KernelError> {
    let mut out = Vec::new();
    for object in &package.objects {
        append_tlv(&mut out, &object.tag, &object.value)?;
    }
    if out.len() > MAX_ONLINE_AUTH_DATA_LEN {
        return Err(KernelError::LengthOverflow);
    }
    Ok(out)
}

fn append_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) -> Result<(), KernelError> {
    if tag.is_empty() || tag.len() > 4 || value.len() > u16::MAX as usize {
        return Err(KernelError::LengthOverflow);
    }
    let additional_len = tag
        .len()
        .checked_add(encoded_length_size(value.len()))
        .and_then(|len| len.checked_add(value.len()))
        .ok_or(KernelError::LengthOverflow)?;
    if out.len().saturating_add(additional_len) > MAX_ONLINE_AUTH_DATA_LEN {
        return Err(KernelError::LengthOverflow);
    }
    out.extend_from_slice(tag);
    encode_length(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn encoded_length_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= u8::MAX as usize {
        2
    } else {
        3
    }
}

fn encode_length(out: &mut Vec<u8>, len: usize) -> Result<(), KernelError> {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= u8::MAX as usize {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len <= u16::MAX as usize {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        return Err(KernelError::LengthOverflow);
    }
    Ok(())
}

fn emv_date_bcd(date: EmvDate) -> [u8; 3] {
    [
        decimal_bcd(date.year),
        decimal_bcd(date.month),
        decimal_bcd(date.day),
    ]
}

fn decimal_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

fn numeric_bcd_fixed(value: u64, bytes: usize) -> Result<Vec<u8>, KernelError> {
    let digits = bytes.checked_mul(2).ok_or(KernelError::LengthOverflow)?;
    let max = 10u64
        .checked_pow(digits as u32)
        .ok_or(KernelError::LengthOverflow)?;
    if value >= max {
        return Err(KernelError::InvalidArgument);
    }

    let mut out = vec![0u8; bytes];
    let mut remaining = value;
    for index in (0..digits).rev() {
        let digit = (remaining % 10) as u8;
        remaining /= 10;
        let byte = index / 2;
        if index % 2 == 0 {
            out[byte] |= digit << 4;
        } else {
            out[byte] |= digit;
        }
    }
    Ok(out)
}

fn apply_transition(ctx: &mut KrnContext, event: FsmEvent) -> Result<(), KernelError> {
    let transition = fsm::transition(ctx.fsm_state, event)?;
    ctx.fsm_state = transition.to;
    Ok(())
}

fn read_application_records(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
    afl: &[AflEntry],
) -> Result<(), KernelError> {
    let plan = record_plan(afl)?;
    if plan.is_empty() {
        apply_transition(ctx, FsmEvent::EndOfRecords)?;
        ctx.state = KernelState::OfflineDataAuthentication;
        return Ok(());
    }
    for (index, locator) in plan.iter().enumerate() {
        ctx.state = KernelState::ReadRecords;
        let command = apdu::read_record(locator.record, locator.sfi)?.encode()?;
        let response = transmit_apdu(runtime, &command, APDU_TRANSMIT_TIMEOUT_MS)?;
        if response.len() < 2 {
            return Err(KernelError::ParseError);
        }
        let body = &response[..response.len() - 2];
        let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
        match classify(ApduContext::ReadRecord, sw) {
            StatusAction::Success => {
                parse_read_record_body(body, &mut ctx.card_data)?;
                apply_transition(ctx, FsmEvent::RecordRead)?;
                if index + 1 == plan.len() {
                    apply_transition(ctx, FsmEvent::AflComplete)?;
                    ctx.state = KernelState::OfflineDataAuthentication;
                    return Ok(());
                }
                apply_transition(ctx, FsmEvent::MoreAflEntries)?;
            }
            StatusAction::EndOfRecords => {
                if locator.contributes_to_offline_auth {
                    ctx.tvr.set(Tvr::B1_ICC_DATA_MISSING);
                }
                apply_transition(ctx, FsmEvent::EndOfRecords)?;
                ctx.state = KernelState::OfflineDataAuthentication;
                return Ok(());
            }
            StatusAction::ContinueWithTvr { bit } => {
                ctx.tvr.set(bit);
                apply_transition(ctx, FsmEvent::RecordReadFailed)?;
                ctx.state = KernelState::OfflineDataAuthentication;
                return Ok(());
            }
            StatusAction::Fail { error } => return Err(error),
            StatusAction::GetResponse { .. } | StatusAction::RetryWithLe { .. } => {
                return Err(KernelError::InternalError);
            }
            StatusAction::FallbackToDirectAid
            | StatusAction::TryNextAid
            | StatusAction::PinFailed { .. }
            | StatusAction::ContinueAfterNonCriticalScriptFailure => {
                return Err(KernelError::InternalError);
            }
        }
    }
    Ok(())
}

fn run_offline_data_authentication(
    ctx: &mut KrnContext,
    profiles: &ProfileSet,
) -> Result<(), KernelError> {
    let selected = ctx
        .selected_application
        .as_ref()
        .ok_or(KernelError::InvalidArgument)?;
    let aip = selected.aip.ok_or(KernelError::MissingMandatoryTag)?;
    let evaluation_date = ctx
        .profile_evaluation_date
        .ok_or(KernelError::InvalidProfile)?;
    let scheme = profiles
        .schemes
        .get(selected.scheme_index)
        .ok_or(KernelError::InvalidProfile)?;
    let aid = scheme
        .aids
        .get(selected.aid_index)
        .ok_or(KernelError::InvalidProfile)?;

    let selection = select_oda_method(selection_input_from_aip(aip, aid.cda_supported, true));
    let outcome = match selection {
        OdaSelection::NotRequired => {
            apply_transition(ctx, FsmEvent::OdaSuccess)?;
            ctx.state = KernelState::ProcessingRestrictions;
            return Ok(());
        }
        OdaSelection::NotPerformedRequired => OdaOutcome::NotPerformed,
        OdaSelection::Perform(method) => oda_outcome_for_method(
            method,
            profiles,
            &scheme.rid,
            evaluation_date,
            &ctx.card_data,
        ),
    };
    let failed = matches!(
        outcome,
        OdaOutcome::NotPerformed | OdaOutcome::Failed { .. }
    );
    let (tvr, tsi) = apply_oda_outcome(ctx.tvr, ctx.tsi, outcome);
    ctx.tvr = tvr;
    ctx.tsi = tsi;
    apply_transition(
        ctx,
        if failed {
            FsmEvent::OdaFailure
        } else {
            FsmEvent::OdaSuccess
        },
    )?;
    ctx.state = KernelState::ProcessingRestrictions;
    Ok(())
}

fn oda_outcome_for_method(
    method: OdaMethod,
    profiles: &ProfileSet,
    rid: &[u8; 5],
    evaluation_date: EmvDate,
    card_data: &DataStore,
) -> OdaOutcome {
    let Some(key_index) = card_data
        .get(&[0x8f])
        .and_then(|value| value.first())
        .copied()
    else {
        return OdaOutcome::Failed {
            method,
            failure: OdaFailure::MissingCapk,
        };
    };
    if select_capk(
        profiles,
        rid,
        key_index,
        evaluation_date,
        CapkIntegrity::Verified,
    )
    .is_err()
    {
        return OdaOutcome::Failed {
            method,
            failure: OdaFailure::MissingCapk,
        };
    }

    match method {
        OdaMethod::Sda => {
            if card_data.get(&[0x90]).is_none() {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::IssuerCertificateRecovery,
                };
            }
            if card_data.get(&[0x93]).is_none() {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::StaticSignature,
                };
            }
            OdaOutcome::Failed {
                method,
                failure: OdaFailure::StaticSignature,
            }
        }
        OdaMethod::Dda => {
            if card_data.get(&[0x90]).is_none() {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::IssuerCertificateRecovery,
                };
            }
            if card_data.get(&[0x9f, 0x46]).is_none() || card_data.get(&[0x9f, 0x47]).is_none() {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::IccCertificateRecovery,
                };
            }
            OdaOutcome::Failed {
                method,
                failure: OdaFailure::DynamicSignature,
            }
        }
        OdaMethod::Cda => {
            if card_data.get(&[0x90]).is_none() {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::IssuerCertificateRecovery,
                };
            }
            if card_data.get(&[0x9f, 0x46]).is_none() || card_data.get(&[0x9f, 0x47]).is_none() {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::IccCertificateRecovery,
                };
            }
            OdaOutcome::Failed {
                method,
                failure: OdaFailure::CdaSignature,
            }
        }
    }
}

fn run_processing_restrictions(
    ctx: &mut KrnContext,
    params: &StoredTxnParams,
) -> Result<(), KernelError> {
    let transaction_date = ctx
        .profile_evaluation_date
        .ok_or(KernelError::InvalidProfile)?;
    let application_expiration_date =
        EmvDate::from_bcd(required_fixed::<3>(&ctx.card_data, &[0x5f, 0x24])?)?;
    let application_effective_date = optional_fixed::<3>(&ctx.card_data, &[0x5f, 0x25])?
        .map(EmvDate::from_bcd)
        .transpose()?;
    let issuer_country = required_fixed::<2>(&ctx.card_data, &[0x5f, 0x28])?;
    let terminal_country = fixed_numeric_bcd::<2>(params.terminal_country_code as u64)?;
    let auc = ApplicationUsageControl::new(required_fixed::<2>(&ctx.card_data, &[0x9f, 0x07])?);

    let input = RestrictionInput {
        transaction_date,
        application_expiration_date,
        application_effective_date,
        card_application_version: card_application_version(&ctx.card_data)?,
        terminal_application_version: None,
        auc,
        region: if issuer_country == terminal_country {
            TransactionRegion::Domestic
        } else {
            TransactionRegion::International
        },
        service: service_type(params),
        new_card: false,
    };

    let result = evaluate_restrictions(input, ctx.tvr);
    ctx.tvr = result.tvr;
    apply_transition(ctx, FsmEvent::RestrictionsEvaluated)?;
    ctx.state = KernelState::Cvm;
    Ok(())
}

fn required_fixed<const N: usize>(data: &DataStore, tag: &[u8]) -> Result<[u8; N], KernelError> {
    let value = data.get(tag).ok_or(KernelError::MissingMandatoryTag)?;
    fixed_slice(value)
}

fn optional_fixed<const N: usize>(
    data: &DataStore,
    tag: &[u8],
) -> Result<Option<[u8; N]>, KernelError> {
    data.get(tag).map(fixed_slice).transpose()
}

fn card_application_version(data: &DataStore) -> Result<Option<[u8; 2]>, KernelError> {
    match optional_fixed::<2>(data, &[0x9f, 0x09])? {
        Some(version) => Ok(Some(version)),
        None => optional_fixed::<2>(data, &[0x9f, 0x08]),
    }
}

fn fixed_slice<const N: usize>(value: &[u8]) -> Result<[u8; N], KernelError> {
    if value.len() != N {
        return Err(KernelError::ParseError);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(value);
    Ok(out)
}

fn fixed_numeric_bcd<const N: usize>(value: u64) -> Result<[u8; N], KernelError> {
    let encoded = numeric_bcd_fixed(value, N)?;
    fixed_slice(&encoded)
}

fn service_type(params: &StoredTxnParams) -> ServiceType {
    match params.transaction_type {
        0x01 => ServiceType::Cash,
        0x09 | 0x17 => ServiceType::Cashback,
        _ if matches!(params.terminal_type, 0x14 | 0x24) => ServiceType::Atm,
        _ => ServiceType::Goods,
    }
}

fn run_cvm_processing(ctx: &mut KrnContext, params: &StoredTxnParams) -> Result<(), KernelError> {
    let cvm_list = parse_cvm_list(
        ctx.card_data
            .get(&[0x8e])
            .ok_or(KernelError::MissingMandatoryTag)?,
    )?;
    let outcome = evaluate_cvm(
        &cvm_list,
        CvmContext {
            amount_authorized: params.amount_authorised_minor,
            transaction_currency_matches_application: transaction_currency_matches_application(
                &ctx.card_data,
                params,
            )?,
            interface: if params.interface_preference == 2 {
                CvmInterface::Contactless
            } else {
                CvmInterface::Contact
            },
            offline_pin_supported: false,
            online_pin_supported: false,
            signature_supported: false,
            cdcvm_performed: false,
        },
        None,
    );

    let (cvm_results, event) = match outcome {
        CvmOutcome::Selected {
            action,
            cvm_results,
        } => {
            if action == CvmAction::OnlinePin {
                ctx.tvr.set(Tvr::B3_ONLINE_PIN_ENTERED);
            }
            (cvm_results, FsmEvent::CvmSuccess)
        }
        CvmOutcome::Failed {
            cvm_results,
            tvr_bit,
        } => {
            ctx.tvr.set(tvr_bit);
            (cvm_results, FsmEvent::CvmFailureNoRetry)
        }
    };
    ctx.tsi.set(Tsi::CARDHOLDER_VERIFICATION_PERFORMED);
    ctx.card_data.put(&[0x9f, 0x34], &cvm_results)?;
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    apply_transition(ctx, event)?;
    ctx.state = KernelState::TerminalRiskManagement;
    Ok(())
}

fn transaction_currency_matches_application(
    data: &DataStore,
    params: &StoredTxnParams,
) -> Result<bool, KernelError> {
    let Some(application_currency) = optional_fixed::<2>(data, &[0x9f, 0x42])? else {
        return Ok(true);
    };
    let terminal_currency = fixed_numeric_bcd::<2>(params.currency_code as u64)?;
    Ok(application_currency == terminal_currency)
}

fn run_terminal_risk_management(
    ctx: &mut KrnContext,
    profiles: &ProfileSet,
    params: &StoredTxnParams,
) -> Result<(), KernelError> {
    let selected = ctx
        .selected_application
        .as_ref()
        .ok_or(KernelError::InvalidArgument)?;
    let aid = profiles
        .schemes
        .get(selected.scheme_index)
        .and_then(|scheme| scheme.aids.get(selected.aid_index))
        .ok_or(KernelError::InvalidProfile)?;
    let profile = aid.trm_profile().ok_or(KernelError::InvalidProfile)?;

    let result = evaluate_trm(
        TrmInput {
            amount_authorized: params.amount_authorised_minor,
            exception_file_match: false,
            merchant_forced_online: false,
            consecutive_offline_count: None,
            random_sample_basis_points: None,
            profile,
        },
        ctx.tvr,
        ctx.tsi,
    );
    ctx.tvr = result.tvr;
    ctx.tsi = result.tsi;
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    apply_transition(ctx, FsmEvent::TrmEvaluated)?;
    ctx.state = KernelState::TerminalActionAnalysis;
    Ok(())
}

fn run_terminal_action_analysis(
    ctx: &mut KrnContext,
    profiles: &ProfileSet,
) -> Result<(), KernelError> {
    let selected = ctx
        .selected_application
        .as_ref()
        .ok_or(KernelError::InvalidArgument)?;
    let scheme = profiles
        .schemes
        .get(selected.scheme_index)
        .ok_or(KernelError::InvalidProfile)?;
    let aid = scheme
        .aids
        .get(selected.aid_index)
        .ok_or(KernelError::InvalidProfile)?;
    let decision = decide_taa(TaaInput {
        tvr: ctx.tvr,
        tac: aid.action_codes,
        iac: issuer_action_codes(&ctx.card_data)?,
        terminal_online_capable: true,
        profile: scheme.taa,
    });
    let (request, event, state) = match decision.action {
        TerminalAction::Aac => (
            CryptogramRequest::Aac,
            FsmEvent::TaaAac,
            KernelState::FinalOutcome,
        ),
        TerminalAction::Tc => (
            CryptogramRequest::Tc,
            FsmEvent::TaaTc,
            KernelState::FinalOutcome,
        ),
        TerminalAction::Arqc => (
            CryptogramRequest::Arqc,
            FsmEvent::TaaArqc,
            KernelState::FirstGenerateAc,
        ),
    };
    ctx.requested_cryptogram = Some(request);
    apply_transition(ctx, event)?;
    ctx.state = state;
    Ok(())
}

fn run_first_generate_ac(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
) -> Result<(), KernelError> {
    let request = ctx
        .requested_cryptogram
        .ok_or(KernelError::InvalidArgument)?;
    let cdol = parse_dol(
        ctx.card_data
            .get(&[0x8c])
            .ok_or(KernelError::MissingMandatoryTag)?,
    )?;
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    let cdol_values = build_dol(&cdol, &ctx.card_data)?;
    let command =
        apdu::generate_ac(request, &cdol_values, CdaRequestControl::NotRequested)?.encode()?;
    let response = transmit_apdu(runtime, &command, APDU_TRANSMIT_TIMEOUT_MS)?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let body = &response[..response.len() - 2];
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
    match classify(ApduContext::GenerateAc, sw) {
        StatusAction::Success => {}
        StatusAction::Fail { error } => {
            let _ = apply_transition(ctx, FsmEvent::GacFailed);
            return Err(error);
        }
        StatusAction::GetResponse { .. } | StatusAction::RetryWithLe { .. } => {
            return Err(KernelError::InternalError);
        }
        StatusAction::FallbackToDirectAid
        | StatusAction::TryNextAid
        | StatusAction::EndOfRecords
        | StatusAction::ContinueWithTvr { .. }
        | StatusAction::PinFailed { .. }
        | StatusAction::ContinueAfterNonCriticalScriptFailure => {
            return Err(KernelError::InternalError);
        }
    }

    let parsed = parse_generate_ac_response(body)?;
    ctx.card_data.put(&[0x9f, 0x27], &[parsed.cid.raw()])?;
    ctx.card_data
        .put(&[0x9f, 0x26], &parsed.application_cryptogram)?;
    ctx.card_data.put(&[0x9f, 0x36], &parsed.atc)?;
    if !parsed.issuer_application_data.is_empty() {
        ctx.card_data
            .put(&[0x9f, 0x10], &parsed.issuer_application_data)?;
    }
    if let Some(dynamic_number) = parsed.icc_dynamic_number.as_ref() {
        ctx.card_data.put(&[0x9f, 0x4c], dynamic_number)?;
    }

    let (event, state) = match parsed.cid.cryptogram_type() {
        CryptogramType::Arqc => (FsmEvent::GacArqc, KernelState::OnlineAuthorization),
        CryptogramType::Tc => (FsmEvent::GacTc, KernelState::FinalOutcome),
        CryptogramType::Aac => (FsmEvent::GacAac, KernelState::FinalOutcome),
        CryptogramType::ApplicationAuthenticationReferral => {
            return Err(KernelError::InvalidArgument);
        }
    };
    if parsed.cid.cryptogram_type() == CryptogramType::Arqc {
        let package = build_online_authorization_package(&parsed, &ctx.card_data);
        ctx.online_authorization_data = Some(encode_online_authorization_package(&package)?);
    } else {
        ctx.online_authorization_data = None;
    }
    ctx.first_gac_response = Some(parsed);
    apply_transition(ctx, event)?;
    ctx.state = state;
    Ok(())
}

fn apply_host_response(ctx: &mut KrnContext, bytes: &[u8]) -> Result<(), KernelError> {
    if ctx.fsm_state != FsmState::S11 {
        return Err(KernelError::InvalidArgument);
    }
    let response = parse_host_response(bytes)?;
    let authorization_response_code = response
        .authorization_response_code
        .ok_or(KernelError::MissingMandatoryTag)?;
    ctx.card_data.put(&[0x8a], &authorization_response_code)?;
    if let Some(issuer_authentication_data) = response.issuer_authentication_data.as_ref() {
        ctx.card_data.put(&[0x91], issuer_authentication_data)?;
    }
    let event = if response.issuer_authentication_data.is_some() {
        FsmEvent::HostArpc
    } else {
        FsmEvent::HostApprovalNoArpc
    };
    ctx.host_response = Some(response);
    apply_transition(ctx, event)?;
    ctx.state = match ctx.fsm_state {
        FsmState::S12 => KernelState::IssuerAuthentication,
        FsmState::S13 => KernelState::IssuerScripts,
        _ => KernelState::Error,
    };
    Ok(())
}

fn run_issuer_authentication(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
) -> Result<(), KernelError> {
    if ctx.fsm_state != FsmState::S12 {
        return Err(KernelError::InvalidArgument);
    }
    let issuer_authentication_data = ctx
        .host_response
        .as_ref()
        .and_then(|response| response.issuer_authentication_data.as_deref())
        .ok_or(KernelError::InvalidArgument)?;
    let command = apdu::external_authenticate(issuer_authentication_data)?.encode()?;
    let response = transmit_apdu(runtime, &command, APDU_TRANSMIT_TIMEOUT_MS)?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);

    ctx.tsi.set(Tsi::ISSUER_AUTHENTICATION_PERFORMED);
    let event = if sw.is_success() {
        FsmEvent::IssuerAuthenticationSuccess
    } else {
        ctx.tvr.set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED);
        FsmEvent::IssuerAuthenticationFailure
    };
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    apply_transition(ctx, event)?;
    ctx.state = KernelState::IssuerScripts;
    Ok(())
}

fn run_issuer_scripts(ctx: &mut KrnContext, runtime: RuntimeCallbacks) -> Result<(), KernelError> {
    run_issuer_scripts_for_phase(ctx, runtime, ScriptPhase::BeforeFinalGenerateAc)
}

fn run_post_final_issuer_scripts(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
) -> Result<(), KernelError> {
    run_issuer_scripts_for_phase(ctx, runtime, ScriptPhase::AfterFinalGenerateAc)
}

fn run_issuer_scripts_for_phase(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
    phase: ScriptPhase,
) -> Result<(), KernelError> {
    let expected_state = match phase {
        ScriptPhase::BeforeFinalGenerateAc => FsmState::S13,
        ScriptPhase::AfterFinalGenerateAc => FsmState::S15,
    };
    if ctx.fsm_state != expected_state {
        return Err(KernelError::InvalidArgument);
    }
    let scripts = ctx
        .host_response
        .as_ref()
        .map(|response| {
            response
                .scripts
                .iter()
                .filter(|script| script.phase == phase)
                .cloned()
                .collect::<Vec<_>>()
        })
        .ok_or(KernelError::InvalidArgument)?;
    if scripts.is_empty() {
        apply_transition(ctx, FsmEvent::NoMoreScripts)?;
        ctx.state = state_after_script_phase(phase);
        return Ok(());
    }

    for script in scripts {
        apply_transition(ctx, FsmEvent::ScriptAvailable)?;
        let mut script_results = Vec::with_capacity(script.commands.len());
        let mut critical_failure = false;
        for command in &script.commands {
            let critical = issuer_script_command_is_critical(ctx, command)?;
            let script_context = ApduContext::IssuerScript { critical };
            let response = transmit_apdu_with_followups(
                runtime,
                command,
                APDU_TRANSMIT_TIMEOUT_MS,
                script_context,
            )?;
            if response.len() < 2 {
                return Err(KernelError::ParseError);
            }
            let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
            let result = ScriptCommandResult {
                sw1: sw.sw1,
                sw2: sw.sw2,
            };
            script_results.push(result);
            ctx.issuer_script_results.push(result);
            match classify(script_context, sw) {
                StatusAction::Success | StatusAction::ContinueAfterNonCriticalScriptFailure => {}
                StatusAction::Fail { error } => {
                    if error != KernelError::ScriptFailed {
                        return Err(error);
                    }
                    critical_failure = true;
                    break;
                }
                _ => return Err(KernelError::InvalidArgument),
            }
        }

        let summary = apply_script_results(script.phase, &script_results, ctx.tvr, ctx.tsi);
        ctx.tvr = summary.tvr;
        ctx.tsi = summary.tsi;
        ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
        ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
        if critical_failure {
            apply_transition(ctx, FsmEvent::ScriptCriticalFailure)?;
            ctx.state = KernelState::Error;
            return Err(KernelError::ScriptFailed);
        }
        let all_success = script_results
            .iter()
            .all(|result| result.sw1 == 0x90 && result.sw2 == 0x00);
        apply_transition(
            ctx,
            if all_success {
                FsmEvent::ScriptSuccess
            } else {
                FsmEvent::ScriptNonCriticalFailure
            },
        )?;
    }

    apply_transition(ctx, FsmEvent::NoMoreScripts)?;
    ctx.state = state_after_script_phase(phase);
    Ok(())
}

fn selected_aid_profile(ctx: &KrnContext) -> Result<&AidProfile, KernelError> {
    let selected = ctx
        .selected_application
        .as_ref()
        .ok_or(KernelError::InvalidArgument)?;
    let profiles = ctx.profiles.as_ref().ok_or(KernelError::InvalidProfile)?;
    profiles
        .schemes
        .get(selected.scheme_index)
        .and_then(|scheme| scheme.aids.get(selected.aid_index))
        .ok_or(KernelError::InvalidProfile)
}

fn issuer_script_command_is_critical(
    ctx: &KrnContext,
    command: &[u8],
) -> Result<bool, KernelError> {
    let ins = command.get(1).ok_or(KernelError::ParseError)?;
    Ok(selected_aid_profile(ctx)?
        .critical_issuer_script_ins
        .contains(ins))
}

fn state_after_script_phase(phase: ScriptPhase) -> KernelState {
    match phase {
        ScriptPhase::BeforeFinalGenerateAc => KernelState::SecondGenerateAc,
        ScriptPhase::AfterFinalGenerateAc => KernelState::FinalOutcome,
    }
}

fn run_final_generate_ac(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
) -> Result<(), KernelError> {
    if ctx.fsm_state != FsmState::S14 {
        return Err(KernelError::InvalidArgument);
    }
    let Some(cdol2) = ctx.card_data.get(&[0x8d]).map(|value| value.to_vec()) else {
        apply_transition(ctx, FsmEvent::FinalGenerateAcSkipped)?;
        ctx.final_outcome = Some(KrnOutcome::ApprovedOnline);
        ctx.state = KernelState::PostFinalIssuerScripts;
        return Ok(());
    };
    let host_arc = ctx
        .host_response
        .as_ref()
        .and_then(|response| response.authorization_response_code)
        .ok_or(KernelError::MissingMandatoryTag)?;
    let request = if host_arc == [b'0', b'0'] {
        CryptogramRequest::Tc
    } else {
        CryptogramRequest::Aac
    };
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    let cdol = parse_dol(&cdol2)?;
    let cdol_values = build_dol(&cdol, &ctx.card_data)?;
    let command =
        apdu::generate_ac(request, &cdol_values, CdaRequestControl::NotRequested)?.encode()?;
    let response = transmit_apdu_with_followups(
        runtime,
        &command,
        APDU_TRANSMIT_TIMEOUT_MS,
        ApduContext::GenerateAc,
    )?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let body = &response[..response.len() - 2];
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
    match classify(ApduContext::GenerateAc, sw) {
        StatusAction::Success => {}
        StatusAction::Fail { error } => {
            let _ = apply_transition(ctx, FsmEvent::Gac2Failed);
            return Err(error);
        }
        _ => return Err(KernelError::InvalidArgument),
    }
    let parsed = parse_generate_ac_response(body)?;
    ctx.card_data.put(&[0x9f, 0x27], &[parsed.cid.raw()])?;
    ctx.card_data
        .put(&[0x9f, 0x26], &parsed.application_cryptogram)?;
    ctx.card_data.put(&[0x9f, 0x36], &parsed.atc)?;
    if !parsed.issuer_application_data.is_empty() {
        ctx.card_data
            .put(&[0x9f, 0x10], &parsed.issuer_application_data)?;
    }
    if let Some(dynamic_number) = parsed.icc_dynamic_number.as_ref() {
        ctx.card_data.put(&[0x9f, 0x4c], dynamic_number)?;
    }

    match parsed.cid.cryptogram_type() {
        CryptogramType::Tc => {
            ctx.final_outcome = Some(KrnOutcome::ApprovedOnline);
            apply_transition(ctx, FsmEvent::Gac2Tc)?;
        }
        CryptogramType::Aac => {
            ctx.final_outcome = Some(KrnOutcome::DeclinedOnline);
            apply_transition(ctx, FsmEvent::Gac2Aac)?;
        }
        CryptogramType::Arqc | CryptogramType::ApplicationAuthenticationReferral => {
            let _ = apply_transition(ctx, FsmEvent::Gac2Failed);
            return Err(KernelError::InvalidArgument);
        }
    }
    ctx.final_gac_response = Some(parsed);
    ctx.state = KernelState::PostFinalIssuerScripts;
    Ok(())
}

fn issuer_action_codes(data: &DataStore) -> Result<ActionCodes, KernelError> {
    Ok(ActionCodes {
        denial: optional_fixed::<5>(data, &[0x9f, 0x0e])?.unwrap_or([0; 5]),
        online: optional_fixed::<5>(data, &[0x9f, 0x0f])?.unwrap_or([0; 5]),
        default: optional_fixed::<5>(data, &[0x9f, 0x0d])?.unwrap_or([0; 5]),
    })
}

fn run_transaction(ctx: &mut KrnContext) -> KrnOutcome {
    let Some(params) = ctx.txn_params.as_ref() else {
        ctx.last_error = KernelError::InvalidArgument;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    };
    let Some(runtime) = ctx.runtime else {
        ctx.last_error = KernelError::InvalidArgument;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    };
    let Some(profiles) = ctx.profiles.clone() else {
        ctx.last_error = KernelError::InvalidProfile;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    };
    let interface = match params.interface_preference {
        0 | 1 => Interface::Contact,
        2 => Interface::Contactless,
        _ => {
            ctx.last_error = KernelError::InvalidArgument;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    if let Err(err) = fsm::transition(ctx.fsm_state, FsmEvent::CardDetected) {
        ctx.last_error = err;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    }
    ctx.fsm_state = FsmState::S2;
    ctx.state = KernelState::SelectEnvironment;

    let select = match apdu::select_environment(interface).encode() {
        Ok(bytes) => bytes,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    let response = match transmit_apdu(runtime, &select, APDU_TRANSMIT_TIMEOUT_MS) {
        Ok(response) => response,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    if response.len() < 2 {
        ctx.last_error = KernelError::ParseError;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    }
    let sw = [response[response.len() - 2], response[response.len() - 1]];
    let fci = &response[..response.len() - 2];
    let event = match sw {
        [0x90, 0x00] => FsmEvent::PseSelected,
        [0x6a, 0x82] => FsmEvent::PseNotFound,
        _ => {
            ctx.last_error = KernelError::MissingMandatoryTag;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    match fsm::transition(ctx.fsm_state, event) {
        Ok(transition) => {
            ctx.fsm_state = transition.to;
            ctx.state = KernelState::BuildCandidateList;
            ctx.last_error = KernelError::Ok;
        }
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }

    let candidates = match if sw == [0x90, 0x00] {
        parse_fci_candidate_aids(fci).and_then(|aids| {
            if aids.is_empty() {
                direct_profile_candidates(&profiles, interface)
            } else {
                match_profile_candidates(&profiles, interface, &aids)
            }
        })
    } else {
        direct_profile_candidates(&profiles, interface)
    } {
        Ok(candidates) => candidates,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };

    let mut selected: Option<(SelectionCandidate, Vec<u8>)> = None;
    for candidate in candidates {
        let transition = match fsm::transition(ctx.fsm_state, FsmEvent::CandidateAidAvailable) {
            Ok(transition) => transition,
            Err(err) => {
                ctx.last_error = err;
                ctx.state = KernelState::Error;
                ctx.fsm_state = FsmState::Se;
                return KrnOutcome::Error;
            }
        };
        ctx.fsm_state = transition.to;
        let select_aid = match apdu::select_aid(&candidate.aid, 0x00).and_then(|cmd| cmd.encode()) {
            Ok(bytes) => bytes,
            Err(err) => {
                ctx.last_error = err;
                ctx.state = KernelState::Error;
                ctx.fsm_state = FsmState::Se;
                return KrnOutcome::Error;
            }
        };
        let select_response = match transmit_apdu(runtime, &select_aid, APDU_TRANSMIT_TIMEOUT_MS) {
            Ok(response) => response,
            Err(err) => {
                ctx.last_error = err;
                ctx.state = KernelState::Error;
                ctx.fsm_state = FsmState::Se;
                return KrnOutcome::Error;
            }
        };
        if select_response.len() < 2 {
            ctx.last_error = KernelError::ParseError;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
        let select_sw = [
            select_response[select_response.len() - 2],
            select_response[select_response.len() - 1],
        ];
        match select_sw {
            [0x90, 0x00] => {
                let select_fci = select_response[..select_response.len() - 2].to_vec();
                let transition = match fsm::transition(ctx.fsm_state, FsmEvent::AidSelected) {
                    Ok(transition) => transition,
                    Err(err) => {
                        ctx.last_error = err;
                        ctx.state = KernelState::Error;
                        ctx.fsm_state = FsmState::Se;
                        return KrnOutcome::Error;
                    }
                };
                ctx.fsm_state = transition.to;
                ctx.state = KernelState::Gpo;
                selected = Some((candidate, select_fci));
                break;
            }
            [0x6a, 0x82] => {
                let transition = match fsm::transition(ctx.fsm_state, FsmEvent::AidNotSupported) {
                    Ok(transition) => transition,
                    Err(err) => {
                        ctx.last_error = err;
                        ctx.state = KernelState::Error;
                        ctx.fsm_state = FsmState::Se;
                        return KrnOutcome::Error;
                    }
                };
                ctx.fsm_state = transition.to;
            }
            _ => {
                ctx.last_error = KernelError::NoCommonAid;
                ctx.state = KernelState::Error;
                ctx.fsm_state = FsmState::Se;
                return KrnOutcome::Error;
            }
        }
    }

    let Some((selected_candidate, selected_fci)) = selected else {
        let _ = fsm::transition(ctx.fsm_state, FsmEvent::NoCandidateLeft);
        ctx.last_error = KernelError::NoCommonAid;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    };

    let pdol = match parse_pdol_from_fci(&selected_fci) {
        Ok(pdol) => pdol,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    let transaction_date = match ctx.profile_evaluation_date {
        Some(date) => date,
        None => {
            ctx.last_error = KernelError::InvalidProfile;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    let unpredictable_number =
        match request_unpredictable_number(runtime, ctx.last_unpredictable_number) {
            Ok(value) => value,
            Err(err) => {
                ctx.last_error = err;
                ctx.state = KernelState::Error;
                ctx.fsm_state = FsmState::Se;
                return KrnOutcome::Error;
            }
        };
    ctx.last_unpredictable_number = Some(unpredictable_number);
    let data = match transaction_data_store(
        params,
        unpredictable_number,
        transaction_date,
        ctx.tvr,
        ctx.tsi,
    ) {
        Ok(data) => data,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    ctx.card_data = data;
    let gpo = match apdu::get_processing_options(&pdol, &ctx.card_data).and_then(|cmd| cmd.encode())
    {
        Ok(bytes) => bytes,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    let gpo_response = match transmit_apdu(runtime, &gpo, APDU_TRANSMIT_TIMEOUT_MS) {
        Ok(response) => response,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    if gpo_response.len() < 2 {
        ctx.last_error = KernelError::ParseError;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    }
    let gpo_sw = [
        gpo_response[gpo_response.len() - 2],
        gpo_response[gpo_response.len() - 1],
    ];
    if gpo_sw != [0x90, 0x00] {
        let _ = fsm::transition(ctx.fsm_state, FsmEvent::GpoFailed);
        ctx.last_error = KernelError::MissingMandatoryTag;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    }
    let parsed_gpo = match parse_gpo_response(&gpo_response[..gpo_response.len() - 2]) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = fsm::transition(ctx.fsm_state, FsmEvent::GpoFailed);
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    let event = match parsed_gpo.format {
        GpoResponseFormat::Template77 => FsmEvent::GpoTemplate77,
        GpoResponseFormat::Template80 => FsmEvent::GpoTemplate80,
    };
    if let Err(err) = ctx.card_data.put(&[0x82], &parsed_gpo.aip) {
        ctx.last_error = err;
        ctx.state = KernelState::Error;
        ctx.fsm_state = FsmState::Se;
        return KrnOutcome::Error;
    }
    let transition = match fsm::transition(ctx.fsm_state, event) {
        Ok(transition) => transition,
        Err(err) => {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    ctx.fsm_state = transition.to;
    ctx.state = match transition.to {
        FsmState::S4 => KernelState::ReadRecords,
        FsmState::S5 => KernelState::OfflineDataAuthentication,
        _ => KernelState::Error,
    };
    let selected_afl = parsed_gpo.afl.clone();
    ctx.selected_application = Some(SelectedApplication {
        aid: selected_candidate.aid,
        scheme_index: selected_candidate.scheme_index,
        aid_index: selected_candidate.aid_index,
        aip: Some(parsed_gpo.aip),
        afl: parsed_gpo.afl,
    });
    if ctx.fsm_state == FsmState::S4 {
        if let Err(err) = read_application_records(ctx, runtime, &selected_afl) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }
    if ctx.fsm_state == FsmState::S5 {
        if let Err(err) = run_offline_data_authentication(ctx, &profiles) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }
    let params = match ctx.txn_params.clone() {
        Some(params) => params,
        None => {
            ctx.last_error = KernelError::InvalidArgument;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    };
    if ctx.fsm_state == FsmState::S6 {
        if let Err(err) = run_processing_restrictions(ctx, &params) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }
    if ctx.fsm_state == FsmState::S7 {
        if let Err(err) = run_cvm_processing(ctx, &params) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }
    if ctx.fsm_state == FsmState::S8 {
        if let Err(err) = run_terminal_risk_management(ctx, &profiles, &params) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }
    if ctx.fsm_state == FsmState::S9 {
        if let Err(err) = run_terminal_action_analysis(ctx, &profiles) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }
    if ctx.fsm_state == FsmState::S10 {
        if let Err(err) = run_first_generate_ac(ctx, runtime) {
            ctx.last_error = err;
            ctx.state = KernelState::Error;
            ctx.fsm_state = FsmState::Se;
            return KrnOutcome::Error;
        }
    }

    ctx.last_error = KernelError::InvalidArgument;
    KrnOutcome::Error
}

fn transmit_apdu(
    runtime: RuntimeCallbacks,
    command: &[u8],
    timeout_ms: i32,
) -> Result<Vec<u8>, KernelError> {
    let mut response = [0u8; MAX_APDU_RESPONSE_LEN];
    let mut response_len = response.len();
    let status = unsafe {
        (runtime.transmit_apdu)(
            command.as_ptr(),
            command.len(),
            response.as_mut_ptr(),
            &mut response_len,
            timeout_ms,
            runtime.user_data,
        )
    };
    if status != KernelError::Ok.code() {
        return Err(KernelError::CardRemoved);
    }
    if response_len > response.len() {
        return Err(KernelError::LengthOverflow);
    }
    Ok(response[..response_len].to_vec())
}

fn transmit_apdu_with_followups(
    runtime: RuntimeCallbacks,
    command: &[u8],
    timeout_ms: i32,
    context: ApduContext,
) -> Result<Vec<u8>, KernelError> {
    let mut current_command = command.to_vec();
    for _ in 0..=MAX_APDU_FOLLOWUPS {
        let response = transmit_apdu(runtime, &current_command, timeout_ms)?;
        if response.len() < 2 {
            return Err(KernelError::ParseError);
        }
        let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
        match classify(context, sw) {
            StatusAction::GetResponse { length } => {
                current_command = apdu::get_response(length).encode()?;
            }
            StatusAction::RetryWithLe { length } => {
                current_command = retry_apdu_with_le(&current_command, length)?;
            }
            _ => return Ok(response),
        }
    }
    Err(KernelError::LengthOverflow)
}

fn retry_apdu_with_le(command: &[u8], le: u8) -> Result<Vec<u8>, KernelError> {
    if command.len() < 4 {
        return Err(KernelError::InvalidArgument);
    }
    let mut out = command.to_vec();
    match command.len() {
        4 => out.push(le),
        5 => out[4] = le,
        len => {
            let lc = usize::from(command[4]);
            if len == 5 + lc {
                out.push(le);
            } else if len == 6 + lc {
                let last = out.last_mut().ok_or(KernelError::InvalidArgument)?;
                *last = le;
            } else {
                return Err(KernelError::InvalidArgument);
            }
        }
    }
    Ok(out)
}

struct RawContactlessOutcomeArgs {
    outcome_code: u8,
    start_signal: u8,
    ui_message_id: u16,
    ui_status: u8,
    hold_time_ms: u16,
    restart_required: u8,
    data_record: *const u8,
    data_record_len: usize,
    discretionary_data: *const u8,
    discretionary_data_len: usize,
    alternate_interface: u8,
}

unsafe fn emit_contactless_outcome(
    ctx: &mut KrnContext,
    args: RawContactlessOutcomeArgs,
) -> Result<(), KernelError> {
    let callback = ctx
        .contactless_outcome_callback
        .ok_or(KernelError::InvalidArgument)?;
    let data_record = readable_slice(args.data_record, args.data_record_len)?;
    let discretionary_data = readable_slice(args.discretionary_data, args.discretionary_data_len)?;
    let outcome = ContactlessOutcome::new(
        outcome_code_from_u8(args.outcome_code)?,
        start_signal_from_u8(args.start_signal)?,
        UiRequest {
            message_id: args.ui_message_id,
            status: ui_status_from_u8(args.ui_status)?,
            hold_time_ms: args.hold_time_ms,
        },
        args.restart_required != 0,
        data_record,
        discretionary_data,
        alternate_interface_from_u8(args.alternate_interface)?,
    )?;
    let view = outcome.as_ffi();
    callback(&view, ctx.contactless_outcome_user_data);
    Ok(())
}

unsafe fn readable_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], KernelError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

fn outcome_code_from_u8(value: u8) -> Result<ContactlessOutcomeCode, KernelError> {
    match value {
        1 => Ok(ContactlessOutcomeCode::Approved),
        2 => Ok(ContactlessOutcomeCode::Declined),
        3 => Ok(ContactlessOutcomeCode::OnlineRequired),
        4 => Ok(ContactlessOutcomeCode::TryAgain),
        5 => Ok(ContactlessOutcomeCode::SelectNext),
        6 => Ok(ContactlessOutcomeCode::AlternateInterface),
        7 => Ok(ContactlessOutcomeCode::Terminate),
        8 => Ok(ContactlessOutcomeCode::CvmRequired),
        255 => Ok(ContactlessOutcomeCode::ProfileDefined),
        _ => Err(KernelError::InvalidArgument),
    }
}

fn start_signal_from_u8(value: u8) -> Result<StartSignal, KernelError> {
    match value {
        0 => Ok(StartSignal::None),
        1 => Ok(StartSignal::Start),
        2 => Ok(StartSignal::Restart),
        3 => Ok(StartSignal::Prompt),
        _ => Err(KernelError::InvalidArgument),
    }
}

fn ui_status_from_u8(value: u8) -> Result<UiStatus, KernelError> {
    match value {
        0 => Ok(UiStatus::None),
        1 => Ok(UiStatus::ReadyToRead),
        2 => Ok(UiStatus::Processing),
        3 => Ok(UiStatus::Approved),
        4 => Ok(UiStatus::Declined),
        5 => Ok(UiStatus::Error),
        6 => Ok(UiStatus::TryAgain),
        _ => Err(KernelError::InvalidArgument),
    }
}

fn alternate_interface_from_u8(value: u8) -> Result<AlternateInterface, KernelError> {
    match value {
        0 => Ok(AlternateInterface::None),
        1 => Ok(AlternateInterface::Contact),
        2 => Ok(AlternateInterface::Magstripe),
        3 => Ok(AlternateInterface::OtherCard),
        _ => Err(KernelError::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering},
        Mutex,
    };

    static FFI_TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLBACK_OUTCOME_CODE: AtomicU8 = AtomicU8::new(0);
    static CALLBACK_DATA_RECORD_LEN: AtomicUsize = AtomicUsize::new(0);
    static TRANSMIT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TRANSMITTED_INS: AtomicU8 = AtomicU8::new(0);
    static TRANSMITTED_LEN: AtomicUsize = AtomicUsize::new(0);
    static TRANSMIT_TIMEOUT_MS: AtomicI32 = AtomicI32::new(0);
    static ISSUER_AUTH_SW1: AtomicU8 = AtomicU8::new(0x90);
    static ISSUER_AUTH_SW2: AtomicU8 = AtomicU8::new(0x00);
    static SCRIPT_SW1: AtomicU8 = AtomicU8::new(0x90);
    static SCRIPT_SW2: AtomicU8 = AtomicU8::new(0x00);
    static SCRIPT_FOLLOWUP_MODE: AtomicU8 = AtomicU8::new(0);
    static FOLLOWUP_TRANSMIT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FOLLOWUP_TRANSMITTED_INS: AtomicU8 = AtomicU8::new(0);
    static FOLLOWUP_TRANSMITTED_LEN: AtomicUsize = AtomicUsize::new(0);

    fn install_profile_selection(ctx: &mut KrnContext) {
        let evaluation_date = EmvDate {
            year: 26,
            month: 5,
            day: 21,
        };
        let profiles = load_profile_set(
            include_bytes!("../docs/scheme_profiles.cert.json"),
            &ConfigLoadPolicy {
                mode: BuildMode::Certification,
                signature_status: SignatureStatus::Verified,
                installed_version: 1,
                candidate_version: 2,
                evaluation_date,
            },
        )
        .unwrap();
        ctx.profiles = Some(profiles);
        ctx.profile_evaluation_date = Some(evaluation_date);
        ctx.selected_application = Some(SelectedApplication {
            aid: vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
            scheme_index: 0,
            aid_index: 0,
            aip: None,
            afl: Vec::new(),
        });
    }

    unsafe extern "C" fn capture_contactless_outcome(
        outcome: *const KrnContactlessOutcome,
        _user_data: *mut c_void,
    ) {
        let outcome = outcome.as_ref().expect("outcome pointer");
        CALLBACK_OUTCOME_CODE.store(outcome.outcome_code, Ordering::SeqCst);
        CALLBACK_DATA_RECORD_LEN.store(outcome.data_record_len, Ordering::SeqCst);
    }

    unsafe extern "C" fn capture_select_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        let count = TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = match count {
            0 => vec![
                0x6f, 0x13, 0xa5, 0x11, 0xbf, 0x0c, 0x0e, 0x61, 0x0c, 0x4f, 0x07, 0xa0, 0x00, 0x00,
                0x00, 0x03, 0x10, 0x10, 0x87, 0x01, 0x01, 0x90, 0x00,
            ],
            1 => vec![
                0x6f, 0x11, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x06, 0x9f,
                0x38, 0x03, 0x9f, 0x37, 0x04, 0x90, 0x00,
            ],
            2 => vec![
                0x77, 0x0a, 0x82, 0x02, 0x80, 0x00, 0x94, 0x04, 0x10, 0x01, 0x01, 0x00, 0x90, 0x00,
            ],
            3 => vec![
                0x70, 0x67, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f, 0x5f, 0x24,
                0x03, 0x30, 0x12, 0x31, 0x5f, 0x25, 0x03, 0x25, 0x01, 0x01, 0x5f, 0x28, 0x02, 0x08,
                0x40, 0x9f, 0x07, 0x02, 0xff, 0x80, 0x9f, 0x09, 0x02, 0x00, 0x01, 0x8e, 0x0a, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x9f, 0x0d, 0x05, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x9f, 0x0e, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f, 0x0f, 0x05,
                0x00, 0x00, 0x00, 0x80, 0x00, 0x8c, 0x12, 0x9f, 0x02, 0x06, 0x9f, 0x37, 0x04, 0x95,
                0x05, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x1a, 0x02, 0x9f, 0x34, 0x03, 0x8d, 0x08, 0x8a,
                0x02, 0x91, 0x08, 0x95, 0x05, 0x9b, 0x02, 0x90, 0x00,
            ],
            4 => vec![
                0x77, 0x1a, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x9f, 0x10, 0x03, 0xaa, 0xbb, 0xcc,
                0x90, 0x00,
            ],
            _ if command[1] == 0x82 => vec![
                ISSUER_AUTH_SW1.load(Ordering::SeqCst),
                ISSUER_AUTH_SW2.load(Ordering::SeqCst),
            ],
            _ if command[1] == 0xae => vec![
                0x77, 0x14, 0x9f, 0x27, 0x01, 0x40, 0x9f, 0x36, 0x02, 0x00, 0x0a, 0x9f, 0x26, 0x08,
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x90, 0x00,
            ],
            _ => vec![
                SCRIPT_SW1.load(Ordering::SeqCst),
                SCRIPT_SW2.load(Ordering::SeqCst),
            ],
        };
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_script_followup_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        let count = FOLLOWUP_TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        FOLLOWUP_TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        FOLLOWUP_TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = match SCRIPT_FOLLOWUP_MODE.load(Ordering::SeqCst) {
            1 if command[1] == 0xda => vec![0x61, 0x02],
            1 if command[1] == 0xc0 => vec![0x90, 0x00],
            2 if count == 0 => vec![0x6c, 0x02],
            2 if command[1] == 0xda && command.last() == Some(&0x02) => vec![0x90, 0x00],
            _ => vec![0x6a, 0x80],
        };
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn fill_unpredictable_number(
        out: *mut u8,
        out_len: usize,
        _user_data: *mut c_void,
    ) -> i32 {
        for idx in 0..out_len {
            *out.add(idx) = idx as u8;
        }
        KernelError::Ok.code()
    }

    #[test]
    fn ffi_builds_select_into_caller_buffer() {
        unsafe {
            let ctx = krn_context_new();
            let mut out = [0u8; 32];
            let mut len = out.len();
            assert_eq!(
                krn_build_select_environment(ctx, false, out.as_mut_ptr(), &mut len),
                KernelError::Ok.code()
            );
            assert_eq!(len, 20);
            assert_eq!(&out[..5], &[0x00, 0xa4, 0x04, 0x00, 0x0e]);
            assert_eq!(krn_get_last_error(ctx), KernelError::Ok.code());
            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_reports_buffer_size_without_writing() {
        unsafe {
            let ctx = krn_context_new();
            let mut out = [0u8; 4];
            let mut len = out.len();
            assert_eq!(
                krn_build_select_environment(ctx, true, out.as_mut_ptr(), &mut len),
                KernelError::BufferTooSmall.code()
            );
            assert_eq!(len, 20);
            assert_eq!(krn_get_last_error(ctx), KernelError::BufferTooSmall.code());
            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_exposes_stable_error_table() {
        unsafe {
            assert_eq!(krn_error_table_len(), ERROR_TABLE.len());

            let mut script_failed_code = 0i32;
            assert_eq!(
                krn_error_code_at(11, &mut script_failed_code),
                KernelError::Ok.code()
            );
            assert_eq!(script_failed_code, KernelError::ScriptFailed.code());
            assert_eq!(
                krn_error_code_at(ERROR_TABLE.len(), &mut script_failed_code),
                KernelError::InvalidArgument.code()
            );

            let mut len = 0usize;
            assert_eq!(
                krn_error_name(KernelError::RngFailure.code(), ptr::null_mut(), &mut len),
                KernelError::BufferTooSmall.code()
            );
            assert_eq!(len, "KRN_ERR_RNG_FAILURE".len());
            let mut name = vec![0u8; len];
            assert_eq!(
                krn_error_name(KernelError::RngFailure.code(), name.as_mut_ptr(), &mut len),
                KernelError::Ok.code()
            );
            assert_eq!(&name, b"KRN_ERR_RNG_FAILURE");

            let mut description_len = 0usize;
            assert_eq!(
                krn_error_description(
                    KernelError::RngFailure.code(),
                    ptr::null_mut(),
                    &mut description_len,
                ),
                KernelError::BufferTooSmall.code()
            );
            let mut description = vec![0u8; description_len];
            assert_eq!(
                krn_error_description(
                    KernelError::RngFailure.code(),
                    description.as_mut_ptr(),
                    &mut description_len,
                ),
                KernelError::Ok.code()
            );
            let description = core::str::from_utf8(&description).unwrap();
            assert!(description.contains("RNG"));
            assert_eq!(
                krn_error_name(9_999, ptr::null_mut(), &mut len),
                KernelError::InvalidArgument.code()
            );
        }
    }

    #[test]
    fn ffi_emits_structured_contactless_outcome_callback() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
            CALLBACK_DATA_RECORD_LEN.store(0, Ordering::SeqCst);
            let ctx = krn_context_new();
            assert_eq!(
                krn_set_contactless_outcome_callback(
                    ctx,
                    Some(capture_contactless_outcome),
                    ptr::null_mut()
                ),
                KernelError::Ok.code()
            );
            let data_record = [0x9f, 0x27, 0x01, 0x80];
            assert_eq!(
                krn_emit_contactless_outcome(
                    ctx,
                    ContactlessOutcomeCode::OnlineRequired as u8,
                    StartSignal::Start as u8,
                    0x1234,
                    UiStatus::Processing as u8,
                    500,
                    0,
                    data_record.as_ptr(),
                    data_record.len(),
                    ptr::null(),
                    0,
                    AlternateInterface::None as u8,
                ),
                KernelError::Ok.code()
            );
            assert_eq!(
                CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst),
                ContactlessOutcomeCode::OnlineRequired as u8
            );
            assert_eq!(CALLBACK_DATA_RECORD_LEN.load(Ordering::SeqCst), 4);
            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_reports_loaded_profile_version_for_log_identity() {
        unsafe {
            let ctx = krn_context_new();
            let mut version = 0u64;
            assert_eq!(
                krn_get_profile_version(ctx, &mut version),
                KernelError::InvalidProfile.code()
            );
            assert_eq!(
                krn_load_profiles_verified(
                    ctx,
                    include_bytes!("../docs/scheme_profiles.cert.json").as_ptr(),
                    include_bytes!("../docs/scheme_profiles.cert.json").len(),
                    1,
                    7,
                    26,
                    5,
                    21,
                ),
                KernelError::Ok.code()
            );
            assert_eq!(
                krn_get_profile_version(ctx, &mut version),
                KernelError::Ok.code()
            );
            assert_eq!(version, 7);
            assert_eq!(
                krn_get_profile_version(ctx, ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_init_validates_runtime_callbacks_and_reaches_online_after_first_gac() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            let mut ctx = ptr::null_mut();
            let bad_runtime = KrnRuntime {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnRuntime>() as u32,
                transmit_apdu: None,
                get_unpredictable_number: Some(fill_unpredictable_number),
                contactless_outcome: None,
                user_data: ptr::null_mut(),
            };
            assert_eq!(
                krn_init(ptr::null(), &bad_runtime, &mut ctx),
                KernelError::InvalidArgument.code()
            );
            assert!(ctx.is_null());

            let runtime = KrnRuntime {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnRuntime>() as u32,
                transmit_apdu: Some(capture_select_apdu),
                get_unpredictable_number: Some(fill_unpredictable_number),
                contactless_outcome: None,
                user_data: ptr::null_mut(),
            };
            assert_eq!(
                krn_init(ptr::null(), &runtime, &mut ctx),
                KernelError::Ok.code()
            );
            assert!(!ctx.is_null());
            let profiles = include_bytes!("../docs/scheme_profiles.cert.json");
            assert_eq!(
                krn_load_profiles_verified(ctx, profiles.as_ptr(), profiles.len(), 1, 2, 26, 5, 21),
                KernelError::Ok.code()
            );

            let params = KrnTxnParams {
                struct_size: mem::size_of::<KrnTxnParams>() as u32,
                amount_authorised_minor: 2_000,
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
                KernelError::Ok.code()
            );
            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error.code());
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 5);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 30);
            assert_eq!(
                TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst),
                APDU_TRANSMIT_TIMEOUT_MS
            );
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S11.code());
            assert_eq!(krn_get_last_error(ctx), KernelError::InvalidArgument.code());
            let ctx_ref = ctx.as_ref().unwrap();
            assert_eq!(
                ctx_ref.card_data.get(&[0x5a]),
                Some(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f][..])
            );
            assert_eq!(ctx_ref.selected_application.as_ref().unwrap().afl.len(), 1);
            assert!(ctx_ref.tvr.is_set(Tvr::B1_SDA_FAILED));
            assert!(!ctx_ref.tvr.is_set(Tvr::B2_EXPIRED_APPLICATION));
            assert!(!ctx_ref.tvr.is_set(Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED));
            assert!(!ctx_ref
                .tvr
                .is_set(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL));
            assert!(ctx_ref.tvr.is_set(Tvr::B4_FLOOR_LIMIT_EXCEEDED));
            assert!(!ctx_ref
                .tvr
                .is_set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED));
            assert!(ctx_ref
                .tsi
                .is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
            assert!(ctx_ref.tsi.is_set(Tsi::CARDHOLDER_VERIFICATION_PERFORMED));
            assert!(ctx_ref.tsi.is_set(Tsi::TERMINAL_RISK_MANAGEMENT_PERFORMED));
            assert_eq!(
                ctx_ref.card_data.get(&[0x9f, 0x34]),
                Some(&[0x1f, 0x00, 0x02][..])
            );
            assert_eq!(ctx_ref.requested_cryptogram, Some(CryptogramRequest::Arqc));
            assert_eq!(
                ctx_ref.card_data.get(&[0x9f, 0x0f]),
                Some(&[0x00, 0x00, 0x00, 0x80, 0x00][..])
            );
            assert_eq!(ctx_ref.card_data.get(&[0x9f, 0x27]), Some(&[0x80][..]));
            assert_eq!(
                ctx_ref.card_data.get(&[0x9f, 0x26]),
                Some(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18][..])
            );
            assert_eq!(
                ctx_ref.card_data.get(&[0x9f, 0x36]),
                Some(&[0x00, 0x09][..])
            );
            assert!(ctx_ref.first_gac_response.is_some());
            assert!(ctx_ref.online_authorization_data.is_some());
            assert_eq!(
                ctx_ref.card_data.get(&[0x95]),
                Some(&ctx_ref.tvr.bytes()[..])
            );
            assert_eq!(
                ctx_ref.card_data.get(&[0x9b]),
                Some(&ctx_ref.tsi.bytes()[..])
            );
            let _ = ctx_ref;
            let mut auth_len = 0usize;
            assert_eq!(
                krn_get_online_authorization_data(ctx, ptr::null_mut(), &mut auth_len),
                KernelError::BufferTooSmall.code()
            );
            assert!(auth_len > 0);
            assert!(auth_len <= MAX_ONLINE_AUTH_DATA_LEN);
            let mut auth = vec![0u8; auth_len];
            assert_eq!(
                krn_get_online_authorization_data(ctx, auth.as_mut_ptr(), &mut auth_len),
                KernelError::Ok.code()
            );
            let auth_tlvs = crate::tlv::parse_many(&auth).unwrap();
            assert_eq!(
                crate::tlv::find_first(&auth_tlvs, &[0x9f, 0x26]),
                Some(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18][..])
            );
            assert_eq!(
                crate::tlv::find_first(&auth_tlvs, &[0x9f, 0x27]),
                Some(&[0x80][..])
            );
            assert_eq!(
                crate::tlv::find_first(&auth_tlvs, &[0x82]),
                Some(&[0x80, 0x00][..])
            );
            assert!(crate::tlv::find_first(&auth_tlvs, &[0x95]).is_some());
            assert!(crate::tlv::find_first(&auth_tlvs, &[0x9f, 0x37]).is_some());
            let host = [
                0x8a, 0x02, b'0', b'0', 0x91, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x71, 0x08, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x01, 0xaa, 0x72, 0x08, 0x86, 0x06,
                0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb,
            ];
            assert_eq!(
                krn_apply_host_response(ctx, host.as_ptr(), host.len()),
                KernelError::Ok.code()
            );
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S12.code());
            assert_eq!(
                krn_process_issuer_authentication(ctx),
                KernelError::Ok.code()
            );
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0x82);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 6);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 13);
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S13.code());
            let ctx_ref = ctx.as_ref().unwrap();
            assert_eq!(ctx_ref.card_data.get(&[0x8a]), Some(&[b'0', b'0'][..]));
            assert_eq!(
                ctx_ref.card_data.get(&[0x91]),
                Some(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88][..])
            );
            assert_eq!(ctx_ref.host_response.as_ref().unwrap().scripts.len(), 2);
            assert!(ctx_ref.tsi.is_set(Tsi::ISSUER_AUTHENTICATION_PERFORMED));
            assert!(!ctx_ref.tvr.is_set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED));
            assert_eq!(
                ctx_ref.card_data.get(&[0x9b]),
                Some(&ctx_ref.tsi.bytes()[..])
            );
            assert_eq!(
                ctx_ref.card_data.get(&[0x95]),
                Some(&ctx_ref.tvr.bytes()[..])
            );
            let _ = ctx_ref;
            assert_eq!(krn_process_issuer_scripts(ctx), KernelError::Ok.code());
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xda);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 7);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S14.code());
            let ctx_ref = ctx.as_ref().unwrap();
            assert_eq!(ctx_ref.issuer_script_results.len(), 1);
            assert_eq!(
                ctx_ref.issuer_script_results[0],
                ScriptCommandResult {
                    sw1: 0x90,
                    sw2: 0x00
                }
            );
            assert!(ctx_ref.tsi.is_set(Tsi::SCRIPT_PROCESSING_PERFORMED));
            assert!(!ctx_ref
                .tvr
                .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC));
            let _ = ctx_ref;
            assert_eq!(krn_process_final_generate_ac(ctx), KernelError::Ok.code());
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 8);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 23);
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S15.code());
            assert_eq!(
                krn_get_final_outcome(ctx),
                KrnOutcome::ApprovedOnline.code()
            );
            let ctx_ref = ctx.as_ref().unwrap();
            assert!(ctx_ref.final_gac_response.is_some());
            assert_eq!(ctx_ref.final_outcome, Some(KrnOutcome::ApprovedOnline));
            assert_eq!(ctx_ref.card_data.get(&[0x9f, 0x27]), Some(&[0x40][..]));
            assert_eq!(
                ctx_ref.card_data.get(&[0x9f, 0x26]),
                Some(&[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28][..])
            );
            assert_eq!(
                ctx_ref.card_data.get(&[0x9f, 0x36]),
                Some(&[0x00, 0x0a][..])
            );
            let _ = ctx_ref;
            assert_eq!(
                krn_process_post_final_issuer_scripts(ctx),
                KernelError::Ok.code()
            );
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xe2);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 9);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S16.code());
            let ctx_ref = ctx.as_ref().unwrap();
            assert_eq!(ctx_ref.issuer_script_results.len(), 2);
            assert_eq!(
                ctx_ref.issuer_script_results[1],
                ScriptCommandResult {
                    sw1: 0x90,
                    sw2: 0x00
                }
            );
            assert!(!ctx_ref
                .tvr
                .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC));
            krn_context_free(ctx);
        }
    }

    #[test]
    fn issuer_authentication_failure_sets_tvr_and_reaches_scripts() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S12;
        ctx.state = KernelState::IssuerAuthentication;
        ctx.host_response = Some(HostResponse {
            authorization_response_code: Some([b'0', b'0']),
            issuer_authentication_data: Some(vec![0x11, 0x22, 0x33, 0x44]),
            scripts: Vec::new(),
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(5, Ordering::SeqCst);
        ISSUER_AUTH_SW1.store(0x69, Ordering::SeqCst);
        ISSUER_AUTH_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(run_issuer_authentication(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0x82);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 9);
        assert_eq!(ctx.fsm_state, FsmState::S13);
        assert_eq!(ctx.state, KernelState::IssuerScripts);
        assert!(ctx.tsi.is_set(Tsi::ISSUER_AUTHENTICATION_PERFORMED));
        assert!(ctx.tvr.is_set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED));
        assert_eq!(ctx.card_data.get(&[0x9b]), Some(&ctx.tsi.bytes()[..]));
        assert_eq!(ctx.card_data.get(&[0x95]), Some(&ctx.tvr.bytes()[..]));
        ISSUER_AUTH_SW1.store(0x90, Ordering::SeqCst);
        ISSUER_AUTH_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S13;
        ctx.state = KernelState::IssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: Some([b'0', b'0']),
            issuer_authentication_data: None,
            scripts: vec![crate::issuer::IssuerScript {
                phase: crate::issuer::ScriptPhase::BeforeFinalGenerateAc,
                identifier: None,
                commands: vec![vec![0x00, 0xda, 0x00, 0x00, 0x01, 0xaa]],
            }],
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(6, Ordering::SeqCst);
        SCRIPT_SW1.store(0x6a, Ordering::SeqCst);
        SCRIPT_SW2.store(0x80, Ordering::SeqCst);
        assert_eq!(run_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xda);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(ctx.fsm_state, FsmState::S14);
        assert_eq!(ctx.state, KernelState::SecondGenerateAc);
        assert_eq!(
            ctx.issuer_script_results,
            vec![ScriptCommandResult {
                sw1: 0x6a,
                sw2: 0x80
            }]
        );
        assert!(ctx.tsi.is_set(Tsi::SCRIPT_PROCESSING_PERFORMED));
        assert!(ctx
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC));
        assert_eq!(ctx.card_data.get(&[0x9b]), Some(&ctx.tsi.bytes()[..]));
        assert_eq!(ctx.card_data.get(&[0x95]), Some(&ctx.tvr.bytes()[..]));
        SCRIPT_SW1.store(0x90, Ordering::SeqCst);
        SCRIPT_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn post_final_issuer_script_failure_sets_after_final_tvr_and_completes() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S15;
        ctx.state = KernelState::PostFinalIssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: Some([b'0', b'0']),
            issuer_authentication_data: None,
            scripts: vec![crate::issuer::IssuerScript {
                phase: crate::issuer::ScriptPhase::AfterFinalGenerateAc,
                identifier: None,
                commands: vec![vec![0x80, 0xda, 0x00, 0x00, 0x01, 0xbb]],
            }],
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        SCRIPT_SW1.store(0x69, Ordering::SeqCst);
        SCRIPT_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(run_post_final_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xda);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(ctx.fsm_state, FsmState::S16);
        assert_eq!(ctx.state, KernelState::FinalOutcome);
        assert_eq!(
            ctx.issuer_script_results,
            vec![ScriptCommandResult {
                sw1: 0x69,
                sw2: 0x85
            }]
        );
        assert!(ctx.tsi.is_set(Tsi::SCRIPT_PROCESSING_PERFORMED));
        assert!(ctx
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC));
        assert_eq!(ctx.card_data.get(&[0x9b]), Some(&ctx.tsi.bytes()[..]));
        assert_eq!(ctx.card_data.get(&[0x95]), Some(&ctx.tvr.bytes()[..]));
        SCRIPT_SW1.store(0x90, Ordering::SeqCst);
        SCRIPT_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn critical_issuer_script_failure_records_results_and_enters_error() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S15;
        ctx.state = KernelState::PostFinalIssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: Some([b'0', b'0']),
            issuer_authentication_data: None,
            scripts: vec![crate::issuer::IssuerScript {
                phase: crate::issuer::ScriptPhase::AfterFinalGenerateAc,
                identifier: None,
                commands: vec![vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb]],
            }],
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        SCRIPT_SW1.store(0x69, Ordering::SeqCst);
        SCRIPT_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(
            run_post_final_issuer_scripts(&mut ctx, runtime),
            Err(KernelError::ScriptFailed)
        );
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xe2);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(ctx.fsm_state, FsmState::Se);
        assert_eq!(ctx.state, KernelState::Error);
        assert_eq!(
            ctx.issuer_script_results,
            vec![ScriptCommandResult {
                sw1: 0x69,
                sw2: 0x85
            }]
        );
        assert!(ctx.tsi.is_set(Tsi::SCRIPT_PROCESSING_PERFORMED));
        assert!(ctx
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC));
        assert_eq!(ctx.card_data.get(&[0x9b]), Some(&ctx.tsi.bytes()[..]));
        assert_eq!(ctx.card_data.get(&[0x95]), Some(&ctx.tvr.bytes()[..]));
        SCRIPT_SW1.store(0x90, Ordering::SeqCst);
        SCRIPT_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn issuer_script_apdus_resolve_get_response_and_retry_le() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        for (mode, expected_ins, expected_len) in [(1, 0xc0, 5usize), (2, 0xda, 7usize)] {
            let mut ctx = KrnContext::new();
            ctx.fsm_state = FsmState::S13;
            ctx.state = KernelState::IssuerScripts;
            install_profile_selection(&mut ctx);
            ctx.host_response = Some(HostResponse {
                authorization_response_code: Some([b'0', b'0']),
                issuer_authentication_data: None,
                scripts: vec![crate::issuer::IssuerScript {
                    phase: crate::issuer::ScriptPhase::BeforeFinalGenerateAc,
                    identifier: None,
                    commands: vec![vec![0x00, 0xda, 0x00, 0x00, 0x01, 0xaa]],
                }],
            });
            let runtime = RuntimeCallbacks {
                transmit_apdu: capture_script_followup_apdu,
                get_unpredictable_number: fill_unpredictable_number,
                contactless_outcome: None,
                user_data: ptr::null_mut(),
            };

            FOLLOWUP_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            SCRIPT_FOLLOWUP_MODE.store(mode, Ordering::SeqCst);
            assert_eq!(run_issuer_scripts(&mut ctx, runtime), Ok(()));
            assert_eq!(FOLLOWUP_TRANSMIT_COUNT.load(Ordering::SeqCst), 2);
            assert_eq!(
                FOLLOWUP_TRANSMITTED_INS.load(Ordering::SeqCst),
                expected_ins
            );
            assert_eq!(
                FOLLOWUP_TRANSMITTED_LEN.load(Ordering::SeqCst),
                expected_len
            );
            assert_eq!(ctx.issuer_script_results.len(), 1);
            assert_eq!(
                ctx.issuer_script_results[0],
                ScriptCommandResult {
                    sw1: 0x90,
                    sw2: 0x00
                }
            );
            assert_eq!(ctx.fsm_state, FsmState::S14);
            assert!(!ctx
                .tvr
                .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC));
        }
        SCRIPT_FOLLOWUP_MODE.store(0, Ordering::SeqCst);
    }
}
