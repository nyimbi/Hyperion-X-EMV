use crate::apdu::{self, CdaRequestControl, CryptogramRequest, Interface};
use crate::c8::{
    AlternateInterface, ContactlessOutcome, ContactlessOutcomeCode, KrnContactlessOutcome,
    StartSignal, UiRequest, UiStatus,
};
use crate::error::KernelError;
use crate::state::{KernelState, Tsi, Tvr};
use core::ptr;
use std::ffi::c_void;
use std::slice;

pub type KrnContactlessOutcomeCallback =
    unsafe extern "C" fn(outcome: *const KrnContactlessOutcome, user_data: *mut c_void);

#[repr(C)]
pub struct KrnContext {
    state: KernelState,
    tvr: Tvr,
    tsi: Tsi,
    last_error: KernelError,
    busy: bool,
    contactless_outcome_callback: Option<KrnContactlessOutcomeCallback>,
    contactless_outcome_user_data: *mut c_void,
}

impl KrnContext {
    fn new() -> Self {
        Self {
            state: KernelState::Idle,
            tvr: Tvr::cleared(),
            tsi: Tsi::cleared(),
            last_error: KernelError::Ok,
            busy: false,
            contactless_outcome_callback: None,
            contactless_outcome_user_data: ptr::null_mut(),
        }
    }

    fn reset(&mut self) {
        self.state = KernelState::Idle;
        self.tvr = Tvr::cleared();
        self.tsi = Tsi::cleared();
        self.last_error = KernelError::Ok;
        self.busy = false;
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
    1
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
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    static CALLBACK_OUTCOME_CODE: AtomicU8 = AtomicU8::new(0);
    static CALLBACK_DATA_RECORD_LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn capture_contactless_outcome(
        outcome: *const KrnContactlessOutcome,
        _user_data: *mut c_void,
    ) {
        let outcome = outcome.as_ref().expect("outcome pointer");
        CALLBACK_OUTCOME_CODE.store(outcome.outcome_code, Ordering::SeqCst);
        CALLBACK_DATA_RECORD_LEN.store(outcome.data_record_len, Ordering::SeqCst);
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
}
