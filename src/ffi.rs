use crate::apdu::{self, CdaRequestControl, CryptogramRequest, Interface};
use crate::error::KernelError;
use crate::state::{KernelState, Tsi, Tvr};
use core::ptr;
use std::ffi::c_void;
use std::slice;

#[repr(C)]
pub struct KrnContext {
    state: KernelState,
    tvr: Tvr,
    tsi: Tsi,
    last_error: KernelError,
    busy: bool,
}

impl KrnContext {
    fn new() -> Self {
        Self {
            state: KernelState::Idle,
            tvr: Tvr::cleared(),
            tsi: Tsi::cleared(),
            last_error: KernelError::Ok,
            busy: false,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
