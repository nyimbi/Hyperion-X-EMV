use crate::apdu::{self, CdaRequestControl, CryptogramRequest, Interface};
use crate::c8::{
    AlternateInterface, ContactlessOutcome, ContactlessOutcomeCode, KrnContactlessOutcome,
    StartSignal, UiRequest, UiStatus,
};
use crate::error::KernelError;
use crate::fsm::{self, FsmEvent, FsmState};
use crate::state::{KernelState, Tsi, Tvr};
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
pub const APDU_TRANSMIT_TIMEOUT_MS: i32 = 500;

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

#[repr(C)]
pub struct KrnContext {
    state: KernelState,
    fsm_state: FsmState,
    tvr: Tvr,
    tsi: Tsi,
    last_error: KernelError,
    busy: bool,
    txn_params: Option<StoredTxnParams>,
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
        ctx.state = KernelState::ParamsSet;
        ctx.fsm_state = transition.to;
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
    let _rng_callback = runtime.get_unpredictable_number;
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
    use std::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

    static CALLBACK_OUTCOME_CODE: AtomicU8 = AtomicU8::new(0);
    static CALLBACK_DATA_RECORD_LEN: AtomicUsize = AtomicUsize::new(0);
    static TRANSMITTED_INS: AtomicU8 = AtomicU8::new(0);
    static TRANSMITTED_LEN: AtomicUsize = AtomicUsize::new(0);
    static TRANSMIT_TIMEOUT_MS: AtomicI32 = AtomicI32::new(0);

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
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = [
            0x6f, 0x09, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x90, 0x00,
        ];
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
    fn ffi_emits_structured_contactless_outcome_callback() {
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
    fn ffi_init_validates_runtime_callbacks_and_runs_first_select_apdu() {
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
            assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error.code());
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xa4);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 20);
            assert_eq!(
                TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst),
                APDU_TRANSMIT_TIMEOUT_MS
            );
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S2AidList.code());
            assert_eq!(krn_get_last_error(ctx), KernelError::InvalidArgument.code());
            krn_context_free(ctx);
        }
    }
}
