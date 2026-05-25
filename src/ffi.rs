use crate::afl::{record_plan, AflEntry};
use crate::apdu::{self, CdaRequestControl, CryptogramRequest, Interface};
use crate::c8::{
    evaluate_contactless_limits, evaluate_relay_resistance, outcome_from_limit_decision,
    outcome_from_relay_resistance_failure, AlternateInterface, ContactlessLimitDecision,
    ContactlessLimitInput, ContactlessOutcome, ContactlessOutcomeCode, KrnContactlessOutcome,
    RelayResistanceDecision, RelayResistanceFailureOutcome, StartSignal,
    TerminalTransactionQualifiers, UiRequest, UiStatus,
};
use crate::cert_bundle::{
    load_certification_bundle, parse_trust_anchors, BundleLoadPolicy, CallbackTimeoutProfile,
};
use crate::cid::CryptogramType;
use crate::config::{
    load_profile_set, AidProfile, BuildMode, Capk, CdaAuthenticationData, CdaRequestEncoding,
    ConfigLoadPolicy, ProfileSet, SignatureStatus,
};
use crate::conformance::baseline_conformance_statement;
use crate::cvm::{
    evaluate as evaluate_cvm, parse_cvm_list, CvmAction, CvmContext, CvmOutcome, CvmPinHandles,
    CvmTransactionType, Interface as CvmInterface, PedPinHandle,
};
use crate::dol::{build_dol_with_policy, parse_dol, DataStore, DolPaddingPolicy};
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
use crate::numeric::encode_numeric_bcd_fixed;
use crate::oda::{
    apply_oda_outcome, parse_internal_authenticate_response,
    recover_and_verify_public_key_certificate, recover_and_verify_signed_application_data,
    select_capk, select_oda_method, selection_input_from_aip, validate_icc_public_key_inputs,
    validate_issuer_public_key_inputs, verify_static_data_authentication, CapkIntegrity,
    OdaFailure, OdaMethod, OdaOutcome, OdaSelection, RecoveredCertificateKind,
    RecoveredPublicKeyCertificate, RecoveredSignedDataKind, StaticAuthenticationRecord,
};
use crate::provenance::sha256;
use crate::record::parse_read_record_body;
use crate::restrictions::{
    evaluate as evaluate_restrictions, ApplicationUsageControl, EmvDate, RestrictionInput,
    ServiceType, TerminalChannel, TransactionRegion,
};
use crate::selection::{
    direct_profile_candidates, match_profile_candidates, parse_fci_candidate_aids,
    validate_selected_adf_name, SelectionCandidate,
};
use crate::state::{KernelState, Tsi, Tvr};
use crate::sw::{classify, ApduContext, StatusAction, StatusWord};
use crate::taa::{decide as decide_taa, ActionCodes, TaaInput, TerminalAction};
use crate::terminal::{
    terminal_type_online_capable, AdditionalTerminalCapabilities, TerminalCapabilities,
};
use crate::trace::{mask_apdu_command, mask_apdu_response, ApduTraceContext, LogPolicy};
use crate::transaction::{CurrencyExponent, CvmTransactionClass, RuntimeService, TransactionType};
use crate::trm::{evaluate as evaluate_trm, OfflineCounter, TrmInput};
use core::mem;
use core::ptr;
use std::ffi::c_void;
use std::slice;
use std::time::Instant;

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

pub const KRN_ABI_VERSION: u32 = 2;
pub const MAX_MERCHANT_NAME_LOCATION_LEN: usize = 128;
pub const MAX_APDU_RESPONSE_LEN: usize = 258;
pub const MAX_ONLINE_AUTH_DATA_LEN: usize = 1024;
pub const MAX_HOST_RESPONSE_LEN: usize = 1024;
pub const KRN_CALLBACK_TIMEOUT_MIN_MS: i32 = 1;
pub const KRN_CALLBACK_TIMEOUT_MAX_MS: i32 = 60_000;
pub const APDU_TRANSMIT_TIMEOUT_MS: i32 = 500;
pub const HOST_AUTHORIZATION_TIMEOUT_MS: i32 = 30_000;
pub const PIN_ENTRY_TIMEOUT_MS: i32 = 30_000;
pub const CONTACTLESS_UI_TIMEOUT_MS: i32 = 5_000;
pub const KRN_PROFILE_SHA256_LEN: usize = 32;
pub const KRN_PIN_METHOD_OFFLINE_PLAINTEXT: u8 = 1;
pub const KRN_PIN_METHOD_OFFLINE_ENCIPHERED: u8 = 2;
pub const KRN_INTERFACE_CONTACT: u8 = 1;
pub const KRN_INTERFACE_CONTACTLESS: u8 = 2;
pub const KRN_SCRIPT_PHASE_BEFORE_FINAL_GAC: u8 = 1;
pub const KRN_SCRIPT_PHASE_AFTER_FINAL_GAC: u8 = 2;
pub const KRN_ISSUER_SCRIPT_IDENTIFIER_LEN: usize = 4;
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

#[repr(C)]
pub struct KrnCallbackTimeoutPolicy {
    pub abi_version: u32,
    pub struct_size: u32,
    pub min_timeout_ms: i32,
    pub max_timeout_ms: i32,
    pub apdu_transport_timeout_ms: i32,
    pub host_authorization_timeout_ms: i32,
    pub pin_entry_timeout_ms: i32,
    pub contactless_ui_timeout_ms: i32,
}

#[derive(Clone, Copy)]
struct RuntimeCallbacks {
    transmit_apdu: KrnTransmitApduCallback,
    get_unpredictable_number: KrnGetUnpredictableNumberCallback,
    contactless_outcome: Option<KrnContactlessOutcomeCallback>,
    user_data: *mut c_void,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapturedIssuerScriptResult {
    phase: ScriptPhase,
    script_index: u16,
    command_index: u16,
    script_identifier: Option<[u8; KRN_ISSUER_SCRIPT_IDENTIFIER_LEN]>,
    result: ScriptCommandResult,
}

impl PartialEq<ScriptCommandResult> for CapturedIssuerScriptResult {
    fn eq(&self, other: &ScriptCommandResult) -> bool {
        self.result == *other
    }
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
    OnlineRequired = 9,
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
    pub currency_exponent: u8,
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
    pub currency_exponent: u8,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RuntimeCvmCapabilities {
    offline_pin_supported: bool,
    online_pin_supported: bool,
    signature_supported: bool,
    cdcvm_performed: bool,
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
    profile_sha256: Option<[u8; 32]>,
    profile_evaluation_date: Option<EmvDate>,
    certification_bundle_sha256: Option<[u8; 32]>,
    certification_bundle_payload_sha256: Option<[u8; 32]>,
    certification_bundle_rollback_counter: u64,
    callback_timeouts: CallbackTimeoutProfile,
    selected_application: Option<SelectedApplication>,
    selected_oda_method: Option<OdaMethod>,
    requested_cryptogram: Option<CryptogramRequest>,
    first_gac_response: Option<GenerateAcResponse>,
    final_gac_response: Option<GenerateAcResponse>,
    final_outcome: Option<KrnOutcome>,
    online_authorization_data: Option<Vec<u8>>,
    host_response: Option<HostResponse>,
    issuer_script_results: Vec<CapturedIssuerScriptResult>,
    card_data: DataStore,
    offline_auth_records: Vec<StaticAuthenticationRecord>,
    cvm_pin_handles: CvmPinHandles,
    cvm_capabilities: RuntimeCvmCapabilities,
    terminal_capabilities: Option<TerminalCapabilities>,
    additional_terminal_capabilities: Option<AdditionalTerminalCapabilities>,
    terminal_transaction_qualifiers: Option<TerminalTransactionQualifiers>,
    offline_counter: Option<OfflineCounter>,
    trm_random_sample_basis_points: Option<u16>,
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
            profile_sha256: None,
            profile_evaluation_date: None,
            certification_bundle_sha256: None,
            certification_bundle_payload_sha256: None,
            certification_bundle_rollback_counter: 0,
            callback_timeouts: CallbackTimeoutProfile::defaults(),
            selected_application: None,
            selected_oda_method: None,
            requested_cryptogram: None,
            first_gac_response: None,
            final_gac_response: None,
            final_outcome: None,
            online_authorization_data: None,
            host_response: None,
            issuer_script_results: Vec::new(),
            card_data: DataStore::new(),
            offline_auth_records: Vec::new(),
            cvm_pin_handles: CvmPinHandles::none(),
            cvm_capabilities: RuntimeCvmCapabilities::default(),
            terminal_capabilities: None,
            additional_terminal_capabilities: None,
            terminal_transaction_qualifiers: None,
            offline_counter: None,
            trm_random_sample_basis_points: None,
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
        self.selected_oda_method = None;
        self.requested_cryptogram = None;
        self.first_gac_response = None;
        self.final_gac_response = None;
        self.final_outcome = None;
        self.online_authorization_data = None;
        self.host_response = None;
        self.issuer_script_results.clear();
        self.card_data = DataStore::new();
        self.offline_auth_records.clear();
        self.cvm_pin_handles = CvmPinHandles::none();
        self.cvm_capabilities = RuntimeCvmCapabilities::default();
        self.terminal_capabilities = None;
        self.additional_terminal_capabilities = None;
        self.terminal_transaction_qualifiers = None;
        self.offline_counter = None;
        self.trm_random_sample_basis_points = None;
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

fn mark_reentrant_call(ctx: &mut KrnContext) -> bool {
    if ctx.busy {
        ctx.last_error = KernelError::Busy;
        true
    } else {
        false
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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

/// Writes the ABI-defined callback timeout policy into a caller-owned struct.
///
/// # Safety
///
/// `out` must point to a writable [`KrnCallbackTimeoutPolicy`] whose
/// `abi_version` and `struct_size` fields have been initialized by the caller.
/// On success, the function fills every policy field with bounded millisecond
/// values used by the kernel and expected from terminal integration callbacks.
#[no_mangle]
pub unsafe extern "C" fn krn_get_callback_timeout_policy(
    out: *mut KrnCallbackTimeoutPolicy,
) -> i32 {
    if out.is_null() {
        return KernelError::InvalidArgument.code();
    }
    let abi_version = ptr::addr_of!((*out).abi_version).read_unaligned();
    let struct_size = ptr::addr_of!((*out).struct_size).read_unaligned() as usize;
    if abi_version != KRN_ABI_VERSION || struct_size != mem::size_of::<KrnCallbackTimeoutPolicy>() {
        return KernelError::InvalidArgument.code();
    }
    write_callback_timeout_policy(out, CallbackTimeoutProfile::defaults());
    KernelError::Ok.code()
}

/// Writes the active context callback timeout policy.
///
/// If a certification bundle has been loaded, this returns the bundle-defined
/// policy. Otherwise it returns the ABI defaults for backward compatibility.
///
/// # Safety
///
/// `ctx` must be null or a valid context pointer. `out` must point to a
/// writable [`KrnCallbackTimeoutPolicy`] with initialized ABI fields.
#[no_mangle]
pub unsafe extern "C" fn krn_get_context_callback_timeout_policy(
    ctx: *const KrnContext,
    out: *mut KrnCallbackTimeoutPolicy,
) -> i32 {
    if out.is_null() {
        return KernelError::InvalidArgument.code();
    }
    let abi_version = ptr::addr_of!((*out).abi_version).read_unaligned();
    let struct_size = ptr::addr_of!((*out).struct_size).read_unaligned() as usize;
    if abi_version != KRN_ABI_VERSION || struct_size != mem::size_of::<KrnCallbackTimeoutPolicy>() {
        return KernelError::InvalidArgument.code();
    }
    let timeouts = ctx
        .as_ref()
        .map(|ctx| ctx.callback_timeouts)
        .unwrap_or_else(CallbackTimeoutProfile::defaults);
    write_callback_timeout_policy(out, timeouts);
    KernelError::Ok.code()
}

fn write_callback_timeout_policy(
    out: *mut KrnCallbackTimeoutPolicy,
    timeouts: CallbackTimeoutProfile,
) {
    unsafe {
        (*out).min_timeout_ms = KRN_CALLBACK_TIMEOUT_MIN_MS;
        (*out).max_timeout_ms = KRN_CALLBACK_TIMEOUT_MAX_MS;
        (*out).apdu_transport_timeout_ms = timeouts.apdu_transport_timeout_ms;
        (*out).host_authorization_timeout_ms = timeouts.host_authorization_timeout_ms;
        (*out).pin_entry_timeout_ms = timeouts.pin_entry_timeout_ms;
        (*out).contactless_ui_timeout_ms = timeouts.contactless_ui_timeout_ms;
    }
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = read_transaction_params(params).and_then(|stored| {
        let transition = fsm::transition(FsmState::S0, FsmEvent::SetTransactionParams)?;
        ctx.txn_params = Some(stored);
        ctx.tvr = Tvr::cleared();
        ctx.tsi = Tsi::cleared();
        ctx.selected_application = None;
        ctx.selected_oda_method = None;
        ctx.requested_cryptogram = None;
        ctx.first_gac_response = None;
        ctx.final_gac_response = None;
        ctx.final_outcome = None;
        ctx.online_authorization_data = None;
        ctx.host_response = None;
        ctx.issuer_script_results.clear();
        ctx.card_data = DataStore::new();
        ctx.offline_auth_records.clear();
        ctx.cvm_pin_handles = CvmPinHandles::none();
        ctx.cvm_capabilities = RuntimeCvmCapabilities::default();
        ctx.terminal_capabilities = None;
        ctx.additional_terminal_capabilities = None;
        ctx.terminal_transaction_qualifiers = None;
        ctx.offline_counter = None;
        ctx.trm_random_sample_basis_points = None;
        ctx.state = KernelState::ParamsSet;
        ctx.fsm_state = transition.to;
        Ok(0usize)
    });
    ctx.set_result(result)
}

/// Registers EMV tag 9F33 Terminal Capabilities for the current transaction.
///
/// Capabilities are cleared whenever new transaction parameters are set, so
/// callers must set them after [`krn_set_transaction_params`] for each
/// transaction that needs non-zero 9F33 data in PDOL/CDOL construction.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_terminal_capabilities(
    ctx: *mut KrnContext,
    byte1: u8,
    byte2: u8,
    byte3: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let capabilities = TerminalCapabilities::parse(&[byte1, byte2, byte3])
        .expect("fixed-length terminal capabilities must parse");
    ctx.terminal_capabilities = Some(capabilities);
    ctx.set_result(Ok(0usize))
}

/// Registers EMV tag 9F40 Additional Terminal Capabilities for the current transaction.
///
/// Additional Terminal Capabilities are cleared whenever new transaction
/// parameters are set, so callers must set them after
/// [`krn_set_transaction_params`] for each transaction that needs non-zero
/// 9F40 data in PDOL/CDOL construction.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_additional_terminal_capabilities(
    ctx: *mut KrnContext,
    byte1: u8,
    byte2: u8,
    byte3: u8,
    byte4: u8,
    byte5: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let capabilities = AdditionalTerminalCapabilities::parse(&[byte1, byte2, byte3, byte4, byte5])
        .expect("fixed-length additional terminal capabilities must parse");
    ctx.additional_terminal_capabilities = Some(capabilities);
    ctx.set_result(Ok(0usize))
}

/// Registers EMV contactless tag 9F66 Terminal Transaction Qualifiers.
///
/// TTQ is cleared whenever new transaction parameters are set, so callers must
/// set it after [`krn_set_transaction_params`] for contactless transactions
/// whose PDOL/CDOL data requires terminal transaction qualifier bytes.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_terminal_transaction_qualifiers(
    ctx: *mut KrnContext,
    byte1: u8,
    byte2: u8,
    byte3: u8,
    byte4: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let ttq = TerminalTransactionQualifiers::parse(&[byte1, byte2, byte3, byte4])
        .expect("fixed-length terminal transaction qualifiers must parse");
    ctx.terminal_transaction_qualifiers = Some(ttq);
    ctx.set_result(Ok(0usize))
}

/// Registers a transaction offline counter loaded from non-volatile storage.
///
/// The kernel does not maintain terminal velocity counters in volatile memory.
/// When an active signed profile enables consecutive-offline limits, Level 3
/// must supply a counter value whose persistence is owned by the terminal's
/// non-volatile storage boundary. The value is cleared whenever new transaction
/// parameters are set.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_nonvolatile_offline_counter(
    ctx: *mut KrnContext,
    consecutive_offline_count: u16,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    ctx.offline_counter = Some(OfflineCounter::non_volatile(consecutive_offline_count));
    ctx.set_result(Ok(0usize))
}

/// Registers the certified-profile TRM random-selection sample.
///
/// The value is expressed in basis points (`0..=9999`). The kernel consumes it
/// only when the active signed profile enables random transaction selection.
/// The value is cleared whenever new transaction parameters are set.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_trm_random_selection_sample(
    ctx: *mut KrnContext,
    sample_basis_points: u16,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        if sample_basis_points > 9_999 {
            return Err(KernelError::InvalidArgument);
        }
        ctx.trm_random_sample_basis_points = Some(sample_basis_points);
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Registers terminal/PED CVM capabilities for the current transaction.
///
/// The flags are boolean bytes (`0` or `1`). Capabilities are cleared whenever
/// new transaction parameters are set, so callers must set them after
/// [`krn_set_transaction_params`] for each transaction that needs them.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_cvm_capabilities(
    ctx: *mut KrnContext,
    online_pin_supported: u8,
    signature_supported: u8,
    cdcvm_performed: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        let online_pin_supported = bool_flag(online_pin_supported)?;
        let signature_supported = bool_flag(signature_supported)?;
        let cdcvm_performed = bool_flag(cdcvm_performed)?;
        ctx.cvm_capabilities = RuntimeCvmCapabilities {
            offline_pin_supported: ctx.cvm_capabilities.offline_pin_supported,
            online_pin_supported,
            signature_supported,
            cdcvm_performed,
        };
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Registers whether an offline PIN facility is available for the transaction.
///
/// This capability is separate from PED-owned PIN handles: a terminal can have
/// an offline PIN pad but receive no entered PIN for a specific transaction.
/// The flag is cleared whenever new transaction parameters are set.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_offline_pin_capability(
    ctx: *mut KrnContext,
    offline_pin_supported: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        ctx.cvm_capabilities.offline_pin_supported = bool_flag(offline_pin_supported)?;
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Registers a PED-owned opaque handle for offline PIN verification.
///
/// The kernel stores only the opaque handle and method class. It never accepts
/// or copies plaintext PIN bytes or PIN blocks across the C ABI.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer.
#[no_mangle]
pub unsafe extern "C" fn krn_set_offline_pin_handle(
    ctx: *mut KrnContext,
    method: u8,
    secure_pin_data_handle: u64,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        let handle = PedPinHandle::new(secure_pin_data_handle)?;
        match method {
            KRN_PIN_METHOD_OFFLINE_PLAINTEXT => {
                ctx.cvm_pin_handles.offline_plaintext = Some(handle);
            }
            KRN_PIN_METHOD_OFFLINE_ENCIPHERED => {
                ctx.cvm_pin_handles.offline_enciphered = Some(handle);
            }
            _ => return Err(KernelError::InvalidArgument),
        }
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Loads an externally verified scheme profile set into an existing context.
///
/// This function does not perform cryptographic signature verification itself;
/// the caller may only use it after the platform trust layer has verified the
/// profile signature and rollback counter. Certification/production loading is
/// still strict and rejects placeholders, expired CAPKs, rollback/replayed
/// versions, and malformed hex material.
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = readable_slice(json, json_len).and_then(|bytes| {
        let evaluation_date = EmvDate {
            year: eval_year,
            month: eval_month,
            day: eval_day,
        };
        let current_version = ctx
            .profiles
            .as_ref()
            .map(|profiles| profiles.version)
            .unwrap_or(0);
        let profiles = load_profile_set(
            bytes,
            &ConfigLoadPolicy {
                mode: BuildMode::Certification,
                signature_status: SignatureStatus::Verified,
                installed_version: installed_version.max(current_version),
                candidate_version,
                evaluation_date,
            },
        )?;
        ctx.profile_sha256 = Some(sha256(bytes));
        ctx.profiles = Some(profiles);
        ctx.profile_evaluation_date = Some(evaluation_date);
        Ok(0usize)
    });
    ctx.set_result(result)
}

/// Loads a data-driven certification bundle into an existing context.
///
/// The bundle contains the scheme profile JSON, runtime policy, vector bundle,
/// artifact bindings, and signature envelope. `trust_anchor_json` supplies the
/// local trust-anchor data used to verify the bundle without changing kernel
/// code. On success, the embedded profile set and data-driven runtime policy
/// become active for the context.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `bundle_json` and
/// `trust_anchor_json` must point to readable byte buffers for their lengths.
#[no_mangle]
pub unsafe extern "C" fn krn_load_certification_bundle_verified(
    ctx: *mut KrnContext,
    bundle_json: *const u8,
    bundle_json_len: usize,
    trust_anchor_json: *const u8,
    trust_anchor_json_len: usize,
    installed_rollback_counter: u64,
    eval_year: u8,
    eval_month: u8,
    eval_day: u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = readable_slice(bundle_json, bundle_json_len).and_then(|bundle_bytes| {
        let trust_bytes = readable_slice(trust_anchor_json, trust_anchor_json_len)?;
        let trust_anchors = parse_trust_anchors(trust_bytes)?;
        let evaluation_date = EmvDate {
            year: eval_year,
            month: eval_month,
            day: eval_day,
        };
        let installed = installed_rollback_counter.max(ctx.certification_bundle_rollback_counter);
        let loaded = load_certification_bundle(
            bundle_bytes,
            &BundleLoadPolicy {
                mode: BuildMode::Certification,
                installed_rollback_counter: installed,
                evaluation_date,
                trust_anchors,
            },
        )?;
        ctx.profile_sha256 = Some(loaded.scheme_profile_sha256);
        ctx.profiles = Some(loaded.profile_set);
        ctx.profile_evaluation_date = Some(evaluation_date);
        ctx.certification_bundle_sha256 = Some(loaded.bundle_sha256);
        ctx.certification_bundle_payload_sha256 = Some(loaded.payload_sha256);
        ctx.certification_bundle_rollback_counter = loaded.bundle.rollback_counter;
        ctx.callback_timeouts = loaded.bundle.payload.runtime_policy.callback_timeouts;
        Ok(0usize)
    });
    ctx.set_result(result)
}

/// Copies the active certification bundle SHA-256 digest for startup evidence.
///
/// # Safety
///
/// `ctx` must be a valid context pointer. `out` must point to at least 32 bytes
/// and `out_len` must be writable. The digest is only present after
/// [`krn_load_certification_bundle_verified`] succeeds.
#[no_mangle]
pub unsafe extern "C" fn krn_get_certification_bundle_sha256(
    ctx: *const KrnContext,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_ref() else {
        return KernelError::InvalidArgument.code();
    };
    if out.is_null() || out_len.is_null() {
        return KernelError::InvalidArgument.code();
    }
    if *out_len < KRN_PROFILE_SHA256_LEN {
        *out_len = KRN_PROFILE_SHA256_LEN;
        return KernelError::BufferTooSmall.code();
    }
    let digest = match ctx.certification_bundle_sha256 {
        Some(digest) => digest,
        None => return KernelError::InvalidProfile.code(),
    };
    ptr::copy_nonoverlapping(digest.as_ptr(), out, KRN_PROFILE_SHA256_LEN);
    *out_len = KRN_PROFILE_SHA256_LEN;
    KernelError::Ok.code()
}

/// Runs a transaction through the stable ABI entrypoint.
///
/// The runner requires a context created by [`krn_init`] with mandatory runtime
/// callbacks and a verified profile set. Missing callbacks, parameters, or
/// profiles fail explicitly and leave the context in the error state rather
/// than returning a synthetic payment outcome.
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
    if mark_reentrant_call(ctx) {
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }

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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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

/// Builds an INTERNAL AUTHENTICATE APDU from caller-provided DDOL values.
///
/// The DDOL value construction is owned by the kernel DOL builder; this ABI
/// entry point exposes the APDU boundary for Level 1/L3 harnesses that need to
/// inspect or transmit a DDA command. The kernel does not perform issuer-key or
/// ICC private-key operations.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. If
/// `ddol_values_len` is non-zero, `ddol_values` must point to
/// `ddol_values_len` readable bytes. `out_len` and `out` follow the same
/// caller-owned buffer contract as `krn_build_select_environment`.
#[no_mangle]
pub unsafe extern "C" fn krn_build_internal_authenticate(
    ctx: *mut KrnContext,
    ddol_values: *const u8,
    ddol_values_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    if ddol_values.is_null() && ddol_values_len != 0 {
        ctx.last_error = KernelError::InvalidArgument;
        return KernelError::InvalidArgument.code();
    }

    let values = if ddol_values_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ddol_values, ddol_values_len)
    };
    let result = apdu::internal_authenticate(values)
        .and_then(|cmd| cmd.encode())
        .and_then(|bytes| write_output(&bytes, out, out_len));
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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
    if mark_reentrant_call(ctx) {
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
    if mark_reentrant_call(ctx) {
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
    if mark_reentrant_call(ctx) {
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
    if mark_reentrant_call(ctx) {
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        if sw1.is_null() || sw2.is_null() {
            return Err(KernelError::InvalidArgument);
        }
        let result = ctx
            .issuer_script_results
            .get(index)
            .ok_or(KernelError::InvalidArgument)?;
        unsafe {
            *sw1 = result.result.sw1;
            *sw2 = result.result.sw2;
        }
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Copies one captured issuer script command phase to caller storage.
///
/// The returned phase is `KRN_SCRIPT_PHASE_BEFORE_FINAL_GAC` for Template 71
/// commands and `KRN_SCRIPT_PHASE_AFTER_FINAL_GAC` for Template 72 commands.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `phase` must point
/// to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn krn_get_issuer_script_result_phase(
    ctx: *mut KrnContext,
    index: usize,
    phase: *mut u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        if phase.is_null() {
            return Err(KernelError::InvalidArgument);
        }
        let result = ctx
            .issuer_script_results
            .get(index)
            .ok_or(KernelError::InvalidArgument)?;
        unsafe {
            *phase = script_phase_code(result.phase);
        }
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Copies phase-local issuer script and command indexes for a captured result.
///
/// `script_index` is the zero-based index among scripts in the returned phase.
/// `command_index` is the zero-based index of the command inside that script.
/// Together with the phase and optional script identifier, these values let
/// Level 3 correlate SW1/SW2 results to the host response without exposing
/// issuer script command bytes.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `script_index`
/// and `command_index` must point to writable `u16` values.
#[no_mangle]
pub unsafe extern "C" fn krn_get_issuer_script_result_position(
    ctx: *mut KrnContext,
    index: usize,
    script_index: *mut u16,
    command_index: *mut u16,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        if script_index.is_null() || command_index.is_null() {
            return Err(KernelError::InvalidArgument);
        }
        let result = ctx
            .issuer_script_results
            .get(index)
            .ok_or(KernelError::InvalidArgument)?;
        unsafe {
            *script_index = result.script_index;
            *command_index = result.command_index;
        }
        Ok(0usize)
    })();
    ctx.set_result(result)
}

/// Copies the optional issuer script identifier for a captured script result.
///
/// The identifier is present only when the source Template 71/72 carried tag
/// `9F18`. A missing identifier returns `Ok` with `*out_len = 0`. When present,
/// the identifier is exactly `KRN_ISSUER_SCRIPT_IDENTIFIER_LEN` bytes. The
/// caller may pass a null `out` pointer to probe the required length.
///
/// # Safety
///
/// `ctx` must be a valid, uniquely borrowed context pointer. `out_len` must
/// point to writable storage. If `out` is non-null it must reference at least
/// `*out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn krn_get_issuer_script_result_identifier(
    ctx: *mut KrnContext,
    index: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        if out_len.is_null() {
            return Err(KernelError::InvalidArgument);
        }
        let result = ctx
            .issuer_script_results
            .get(index)
            .ok_or(KernelError::InvalidArgument)?;
        let Some(identifier) = result.script_identifier else {
            unsafe {
                *out_len = 0;
            }
            return Ok(0usize);
        };
        let required = identifier.len();
        let available = unsafe { *out_len };
        unsafe {
            *out_len = required;
        }
        if out.is_null() || available < required {
            return Err(KernelError::BufferTooSmall);
        }
        unsafe {
            ptr::copy_nonoverlapping(identifier.as_ptr(), out, required);
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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

/// Copies the SHA-256 digest of the loaded signed profile bytes.
///
/// This is an identity hook for certification freeze and trace correlation. It
/// does not prove profile authority by itself; callers must still verify the
/// signature, rollback counter, and lab/scheme provenance before loading.
///
/// # Safety
///
/// `ctx` must be a valid context pointer. `out_len` must point to a writable
/// `usize`; on input it contains `out` capacity and on output it receives 32.
/// `out` may be null only for a size query.
#[no_mangle]
pub unsafe extern "C" fn krn_get_profile_sha256(
    ctx: *mut KrnContext,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        return KernelError::InvalidArgument.code();
    };
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
    let result = (|| {
        let digest = ctx.profile_sha256.ok_or(KernelError::InvalidProfile)?;
        write_output(&digest, out, out_len)
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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
    if mark_reentrant_call(ctx) {
        return KernelError::Busy.code();
    }
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

/// Masks a command APDU into canonical JSON for lab/support trace emission.
///
/// The returned JSON is always produced by the kernel log policy. Production
/// mode suppresses APDU data, while certification support mode may include
/// non-sensitive command data only after explicit support authorization. VERIFY
/// command data is always suppressed.
///
/// # Safety
///
/// `command` must point to `command_len` readable bytes. `out_len` must point
/// to writable `usize` storage. `out` may be null only for length probing.
#[no_mangle]
pub unsafe extern "C" fn krn_mask_apdu_command_json(
    command: *const u8,
    command_len: usize,
    certification_support: bool,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = readable_slice(command, command_len).and_then(|bytes| {
        let policy = trace_policy(certification_support);
        let json = mask_apdu_command(0, bytes, policy)?.to_json();
        write_output(json.as_bytes(), out, out_len)
    });
    result
        .map(|_| KernelError::Ok.code())
        .unwrap_or_else(|err| err.code())
}

/// Masks a response APDU into canonical JSON for lab/support trace emission.
///
/// `context` is `0` for generic BER-TLV responses and `1` for GENERATE AC
/// responses. GENERATE AC cryptograms and issuer authentication data remain
/// suppressed under production policy.
///
/// # Safety
///
/// `response_data` must point to `response_data_len` readable bytes. `out_len`
/// must point to writable `usize` storage. `out` may be null only for length
/// probing.
#[no_mangle]
pub unsafe extern "C" fn krn_mask_apdu_response_json(
    context: u8,
    response_data: *const u8,
    response_data_len: usize,
    sw1: u8,
    sw2: u8,
    certification_support: bool,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = trace_context(context).and_then(|trace_context| {
        readable_slice(response_data, response_data_len).and_then(|bytes| {
            let policy = trace_policy(certification_support);
            let json = mask_apdu_response(0, trace_context, bytes, [sw1, sw2], policy)?.to_json();
            write_output(json.as_bytes(), out, out_len)
        })
    });
    result
        .map(|_| KernelError::Ok.code())
        .unwrap_or_else(|err| err.code())
}

/// Copies the deterministic KRN-REF-001 conformance statement JSON.
///
/// This artifact declares the controlling engineering baseline, normative
/// reference hierarchy, and certification caveats for the current ABI build.
///
/// # Safety
///
/// `out_len` must point to writable `usize` storage. `out` may be null only for
/// length probing; otherwise it must point to `*out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn krn_get_conformance_statement_json(
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let json = baseline_conformance_statement(KRN_ABI_VERSION).canonical_json();
    match write_output(json.as_bytes(), out, out_len) {
        Ok(_) => KernelError::Ok.code(),
        Err(err) => err.code(),
    }
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

fn trace_policy(certification_support: bool) -> LogPolicy {
    if certification_support {
        LogPolicy::certification_support()
    } else {
        LogPolicy::production()
    }
}

fn trace_context(context: u8) -> Result<ApduTraceContext, KernelError> {
    match context {
        0 => Ok(ApduTraceContext::Generic),
        1 => Ok(ApduTraceContext::GenerateAcResponse),
        _ => Err(KernelError::InvalidArgument),
    }
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
    if bytes.is_empty() {
        return Ok(0);
    }
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
    if !matches!(
        params.interface_preference,
        KRN_INTERFACE_CONTACT | KRN_INTERFACE_CONTACTLESS
    ) {
        return Err(KernelError::InvalidArgument);
    }
    CurrencyExponent::from_value(params.currency_exponent)?;
    validate_three_digit_numeric_code(params.currency_code)?;
    validate_three_digit_numeric_code(params.terminal_country_code)?;
    terminal_type_online_capable(params.terminal_type)?;
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
        currency_exponent: params.currency_exponent,
        terminal_country_code: params.terminal_country_code,
        transaction_type: params.transaction_type,
        terminal_type: params.terminal_type,
        merchant_category_code: params.merchant_category_code,
        interface_preference: params.interface_preference,
        merchant_name_location,
    })
}

fn validate_three_digit_numeric_code(value: u16) -> Result<(), KernelError> {
    if value > 999 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

fn bool_flag(value: u8) -> Result<bool, KernelError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(KernelError::InvalidArgument),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TerminalDolInputs {
    terminal_capabilities: Option<TerminalCapabilities>,
    additional_terminal_capabilities: Option<AdditionalTerminalCapabilities>,
    terminal_transaction_qualifiers: Option<TerminalTransactionQualifiers>,
}

fn transaction_data_store(
    params: &StoredTxnParams,
    unpredictable_number: [u8; 4],
    transaction_date: EmvDate,
    tvr: Tvr,
    tsi: Tsi,
    terminal_inputs: TerminalDolInputs,
) -> Result<DataStore, KernelError> {
    let mut data = DataStore::new();
    let amount_authorised = encode_numeric_bcd_fixed(params.amount_authorised_minor, 6)?;
    let amount_other = encode_numeric_bcd_fixed(params.amount_other_minor, 6)?;
    let transaction_currency = encode_numeric_bcd_fixed(params.currency_code as u64, 2)?;
    let terminal_country = encode_numeric_bcd_fixed(params.terminal_country_code as u64, 2)?;
    data.put(&[0x9f, 0x02], &amount_authorised)?;
    data.put(&[0x9f, 0x03], &amount_other)?;
    data.put(&[0x5f, 0x2a], &transaction_currency)?;
    data.put(&[0x5f, 0x36], &[params.currency_exponent])?;
    data.put(&[0x9f, 0x1a], &terminal_country)?;
    data.put(&[0x9c], &[params.transaction_type])?;
    data.put(&[0x9a], &emv_date_bcd(transaction_date))?;
    if let Some(terminal_capabilities) = terminal_inputs.terminal_capabilities {
        data.put(&[0x9f, 0x33], &terminal_capabilities.raw())?;
    }
    if let Some(additional_terminal_capabilities) = terminal_inputs.additional_terminal_capabilities
    {
        data.put(&[0x9f, 0x40], &additional_terminal_capabilities.raw())?;
    }
    if let Some(terminal_transaction_qualifiers) = terminal_inputs.terminal_transaction_qualifiers {
        data.put(&[0x9f, 0x66], &terminal_transaction_qualifiers.raw())?;
    }
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
    if unpredictable_number.iter().all(|byte| *byte == 0)
        || unpredictable_number.iter().all(|byte| *byte == 0xff)
        || previous == Some(unpredictable_number)
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

fn apply_transition(ctx: &mut KrnContext, event: FsmEvent) -> Result<(), KernelError> {
    let transition = fsm::transition(ctx.fsm_state, event)?;
    ctx.fsm_state = transition.to;
    Ok(())
}

fn require_apdu_success(context: ApduContext, sw: StatusWord) -> Result<(), KernelError> {
    match classify(context, sw) {
        StatusAction::Success => Ok(()),
        StatusAction::Fail { error } => Err(error),
        StatusAction::GetResponse { .. } | StatusAction::RetryWithLe { .. } => {
            Err(KernelError::InternalError)
        }
        StatusAction::FallbackToDirectAid
        | StatusAction::TryNextAid
        | StatusAction::EndOfRecords
        | StatusAction::ContinueWithTvr { .. }
        | StatusAction::PinFailed { .. }
        | StatusAction::ContinueAfterScriptWarning
        | StatusAction::ContinueAfterNonCriticalScriptFailure => Err(KernelError::InternalError),
    }
}

fn require_generate_ac_success(
    ctx: &mut KrnContext,
    sw: StatusWord,
    failure_event: FsmEvent,
) -> Result<(), KernelError> {
    match require_apdu_success(ApduContext::GenerateAc, sw) {
        Ok(()) => Ok(()),
        Err(error @ KernelError::CardRemoved) => {
            let _ = apply_transition(ctx, failure_event);
            Err(error)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadRecordStatus {
    Success,
    EndOfRecords,
    ContinueWithTvr { bit: (usize, u8) },
}

fn read_record_status(action: StatusAction) -> Result<ReadRecordStatus, KernelError> {
    match action {
        StatusAction::Success => Ok(ReadRecordStatus::Success),
        StatusAction::EndOfRecords => Ok(ReadRecordStatus::EndOfRecords),
        StatusAction::ContinueWithTvr { bit } => Ok(ReadRecordStatus::ContinueWithTvr { bit }),
        StatusAction::Fail { error } => Err(error),
        StatusAction::GetResponse { .. }
        | StatusAction::RetryWithLe { .. }
        | StatusAction::FallbackToDirectAid
        | StatusAction::TryNextAid
        | StatusAction::PinFailed { .. }
        | StatusAction::ContinueAfterScriptWarning
        | StatusAction::ContinueAfterNonCriticalScriptFailure => Err(KernelError::InternalError),
    }
}

fn issuer_authentication_event_from_status(
    action: StatusAction,
    tvr: &mut Tvr,
) -> Result<FsmEvent, KernelError> {
    match action {
        StatusAction::Success => Ok(FsmEvent::IssuerAuthenticationSuccess),
        StatusAction::ContinueWithTvr { bit } => {
            tvr.set(bit);
            Ok(FsmEvent::IssuerAuthenticationFailure)
        }
        StatusAction::Fail { error } => Err(error),
        StatusAction::GetResponse { .. }
        | StatusAction::RetryWithLe { .. }
        | StatusAction::FallbackToDirectAid
        | StatusAction::TryNextAid
        | StatusAction::EndOfRecords
        | StatusAction::PinFailed { .. }
        | StatusAction::ContinueAfterScriptWarning
        | StatusAction::ContinueAfterNonCriticalScriptFailure => Err(KernelError::InternalError),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssuerScriptStatus {
    Continue,
    CriticalFailure,
}

fn issuer_script_status(action: StatusAction) -> Result<IssuerScriptStatus, KernelError> {
    match action {
        StatusAction::Success
        | StatusAction::ContinueAfterScriptWarning
        | StatusAction::ContinueAfterNonCriticalScriptFailure => Ok(IssuerScriptStatus::Continue),
        StatusAction::Fail {
            error: KernelError::ScriptFailed,
        } => Ok(IssuerScriptStatus::CriticalFailure),
        StatusAction::Fail { error } => Err(error),
        StatusAction::GetResponse { .. }
        | StatusAction::RetryWithLe { .. }
        | StatusAction::FallbackToDirectAid
        | StatusAction::TryNextAid
        | StatusAction::EndOfRecords
        | StatusAction::ContinueWithTvr { .. }
        | StatusAction::PinFailed { .. } => Err(KernelError::InvalidArgument),
    }
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
        let response = transmit_apdu_with_followups(
            runtime,
            &command,
            apdu_timeout(ctx),
            ApduContext::ReadRecord,
        )?;
        if response.len() < 2 {
            return Err(KernelError::ParseError);
        }
        let body = &response[..response.len() - 2];
        let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
        match read_record_status(classify(ApduContext::ReadRecord, sw))? {
            ReadRecordStatus::Success => {
                parse_read_record_body(body, &mut ctx.card_data)?;
                if locator.contributes_to_offline_auth {
                    ctx.offline_auth_records.push(StaticAuthenticationRecord {
                        sfi: locator.sfi,
                        record: locator.record,
                        body: body.to_vec(),
                    });
                }
                apply_transition(ctx, FsmEvent::RecordRead)?;
                if index + 1 == plan.len() {
                    apply_transition(ctx, FsmEvent::AflComplete)?;
                    break;
                }
                apply_transition(ctx, FsmEvent::MoreAflEntries)?;
            }
            ReadRecordStatus::EndOfRecords => {
                if locator.contributes_to_offline_auth {
                    ctx.tvr.set(Tvr::B1_ICC_DATA_MISSING);
                }
                apply_transition(ctx, FsmEvent::EndOfRecords)?;
                ctx.state = KernelState::OfflineDataAuthentication;
                return Ok(());
            }
            ReadRecordStatus::ContinueWithTvr { bit } => {
                ctx.tvr.set(bit);
                apply_transition(ctx, FsmEvent::RecordReadFailed)?;
                ctx.state = KernelState::OfflineDataAuthentication;
                return Ok(());
            }
        }
    }
    ctx.state = KernelState::OfflineDataAuthentication;
    Ok(())
}

fn run_offline_data_authentication(
    ctx: &mut KrnContext,
    profiles: &ProfileSet,
    runtime: Option<RuntimeCallbacks>,
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

    let selection = select_oda_method(selection_input_from_aip(
        aip,
        aid.cda_allowed_by_profile(),
        true,
    ));
    let outcome = match selection {
        OdaSelection::NotRequired => {
            ctx.selected_oda_method = None;
            apply_transition(ctx, FsmEvent::OdaSuccess)?;
            ctx.state = KernelState::ProcessingRestrictions;
            return Ok(());
        }
        OdaSelection::NotPerformedRequired => {
            ctx.selected_oda_method = None;
            OdaOutcome::NotPerformed
        }
        OdaSelection::Perform(method) => {
            ctx.selected_oda_method = Some(method);
            let evaluation = OdaEvaluationContext {
                profiles,
                rid: &scheme.rid,
                evaluation_date,
                card_data: &ctx.card_data,
                offline_auth_records: &ctx.offline_auth_records,
                runtime,
                apdu_timeout_ms: apdu_timeout(ctx),
            };
            oda_outcome_for_method(method, evaluation)
        }
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

struct OdaEvaluationContext<'a> {
    profiles: &'a ProfileSet,
    rid: &'a [u8; 5],
    evaluation_date: EmvDate,
    card_data: &'a DataStore,
    offline_auth_records: &'a [StaticAuthenticationRecord],
    runtime: Option<RuntimeCallbacks>,
    apdu_timeout_ms: i32,
}

fn oda_outcome_for_method(method: OdaMethod, evaluation: OdaEvaluationContext<'_>) -> OdaOutcome {
    let OdaEvaluationContext {
        profiles,
        rid,
        evaluation_date,
        card_data,
        offline_auth_records,
        runtime,
        apdu_timeout_ms,
    } = evaluation;
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
    let capk = match select_capk(
        profiles,
        rid,
        key_index,
        evaluation_date,
        CapkIntegrity::Verified,
    ) {
        Ok(capk) => capk,
        Err(_) => {
            return OdaOutcome::Failed {
                method,
                failure: OdaFailure::MissingCapk,
            }
        }
    };

    match method {
        OdaMethod::Sda => {
            let issuer_public_key = match recover_issuer_public_key(capk, card_data) {
                Ok(certificate) => certificate,
                Err(failure) => return OdaOutcome::Failed { method, failure },
            };
            let Some(signed_static_application_data) = card_data.get(&[0x93]) else {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::StaticSignature,
                };
            };
            if verify_static_data_authentication(
                &issuer_public_key,
                signed_static_application_data,
                offline_auth_records,
                card_data,
            )
            .is_err()
            {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::StaticSignature,
                };
            }
            OdaOutcome::Passed(method)
        }
        OdaMethod::Dda => {
            let issuer_public_key = match recover_issuer_public_key(capk, card_data) {
                Ok(certificate) => certificate,
                Err(failure) => return OdaOutcome::Failed { method, failure },
            };
            let icc_public_key = match recover_icc_public_key(&issuer_public_key, card_data) {
                Ok(certificate) => certificate,
                Err(failure) => return OdaOutcome::Failed { method, failure },
            };
            let Some(runtime) = runtime else {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::DynamicSignature,
                };
            };
            if perform_dynamic_data_authentication(
                runtime,
                &icc_public_key,
                card_data,
                apdu_timeout_ms,
            )
            .is_err()
            {
                return OdaOutcome::Failed {
                    method,
                    failure: OdaFailure::DynamicSignature,
                };
            }
            OdaOutcome::Passed(method)
        }
        OdaMethod::Cda => {
            let issuer_public_key = match recover_issuer_public_key(capk, card_data) {
                Ok(certificate) => certificate,
                Err(failure) => return OdaOutcome::Failed { method, failure },
            };
            match recover_icc_public_key(&issuer_public_key, card_data) {
                Ok(_) => OdaOutcome::Passed(method),
                Err(failure) => OdaOutcome::Failed { method, failure },
            }
        }
    }
}

fn recover_issuer_public_key(
    capk: &Capk,
    card_data: &DataStore,
) -> Result<RecoveredPublicKeyCertificate, OdaFailure> {
    let issuer_inputs = validate_issuer_public_key_inputs(card_data)
        .map_err(|_| OdaFailure::IssuerCertificateRecovery)?;
    recover_and_verify_public_key_certificate(
        RecoveredCertificateKind::Issuer,
        &issuer_inputs.certificate,
        &capk.modulus,
        &capk.exponent,
        &issuer_inputs.remainder,
        &issuer_inputs.exponent,
        &[],
    )
    .map_err(|_| OdaFailure::IssuerCertificateRecovery)
}

fn recover_icc_public_key(
    issuer_public_key: &RecoveredPublicKeyCertificate,
    card_data: &DataStore,
) -> Result<RecoveredPublicKeyCertificate, OdaFailure> {
    let icc_inputs = validate_icc_public_key_inputs(card_data)
        .map_err(|_| OdaFailure::IccCertificateRecovery)?;
    recover_and_verify_public_key_certificate(
        RecoveredCertificateKind::Icc,
        &icc_inputs.certificate,
        &issuer_public_key.public_key,
        &issuer_public_key.exponent,
        &icc_inputs.remainder,
        &icc_inputs.exponent,
        &[],
    )
    .map_err(|_| OdaFailure::IccCertificateRecovery)
}

fn perform_dynamic_data_authentication(
    runtime: RuntimeCallbacks,
    icc_public_key: &RecoveredPublicKeyCertificate,
    card_data: &DataStore,
    apdu_timeout_ms: i32,
) -> Result<(), KernelError> {
    let ddol = match card_data.get(&[0x9f, 0x49]) {
        Some(value) => parse_dol(value)?,
        None => parse_dol(&[0x9f, 0x37, 0x04])?,
    };
    let ddol_values =
        build_dol_with_policy(&ddol, card_data, DolPaddingPolicy::ZeroPadMissingAndShort)?;
    let command = apdu::internal_authenticate(&ddol_values)?.encode()?;
    let response = transmit_apdu_with_followups(
        runtime,
        &command,
        apdu_timeout_ms,
        ApduContext::InternalAuthenticate,
    )?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let body = &response[..response.len() - 2];
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
    require_apdu_success(ApduContext::InternalAuthenticate, sw)?;
    let internal_authenticate = parse_internal_authenticate_response(body)?;
    recover_and_verify_signed_application_data(
        RecoveredSignedDataKind::DynamicApplicationData,
        &internal_authenticate.signed_dynamic_application_data,
        &icc_public_key.public_key,
        &icc_public_key.exponent,
        &ddol_values,
    )?;
    Ok(())
}

fn verify_combined_data_authentication(
    ctx: &KrnContext,
    response: &GenerateAcResponse,
) -> Result<(), KernelError> {
    let profiles = ctx.profiles.as_ref().ok_or(KernelError::InvalidProfile)?;
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
    let authentication_data = cda_authentication_data(aid, response)?;
    let evaluation_date = ctx
        .profile_evaluation_date
        .ok_or(KernelError::InvalidProfile)?;
    let key_index = ctx
        .card_data
        .get(&[0x8f])
        .and_then(|value| value.first())
        .copied()
        .ok_or(KernelError::MissingMandatoryTag)?;
    let capk = select_capk(
        profiles,
        &scheme.rid,
        key_index,
        evaluation_date,
        CapkIntegrity::Verified,
    )?;
    let issuer_public_key =
        recover_issuer_public_key(capk, &ctx.card_data).map_err(oda_failure_to_kernel_error)?;
    let icc_public_key = recover_icc_public_key(&issuer_public_key, &ctx.card_data)
        .map_err(oda_failure_to_kernel_error)?;
    let signed_dynamic_application_data = response
        .signed_dynamic_application_data
        .as_deref()
        .ok_or(KernelError::MissingMandatoryTag)?;
    recover_and_verify_signed_application_data(
        RecoveredSignedDataKind::DynamicApplicationData,
        signed_dynamic_application_data,
        &icc_public_key.public_key,
        &icc_public_key.exponent,
        &authentication_data,
    )?;
    Ok(())
}

fn cda_authentication_data(
    aid: &AidProfile,
    response: &GenerateAcResponse,
) -> Result<Vec<u8>, KernelError> {
    let mut authentication_data = response.application_cryptogram.to_vec();
    match aid.cda_authentication_data {
        CdaAuthenticationData::ApplicationCryptogram => {}
        CdaAuthenticationData::ApplicationCryptogramAndIccDynamicNumber => {
            authentication_data.extend_from_slice(
                response
                    .icc_dynamic_number
                    .as_deref()
                    .ok_or(KernelError::MissingMandatoryTag)?,
            );
        }
    }
    Ok(authentication_data)
}

fn oda_failure_to_kernel_error(failure: OdaFailure) -> KernelError {
    match failure {
        OdaFailure::MissingCapk => KernelError::MissingMandatoryTag,
        OdaFailure::IssuerCertificateRecovery
        | OdaFailure::IccCertificateRecovery
        | OdaFailure::StaticSignature
        | OdaFailure::DynamicSignature
        | OdaFailure::CdaSignature => KernelError::InvalidProfile,
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
        terminal_channel: terminal_channel(params),
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
    let encoded = encode_numeric_bcd_fixed(value, N)?;
    fixed_slice(&encoded)
}

fn service_type(params: &StoredTxnParams) -> ServiceType {
    match TransactionType::from_value(params.transaction_type).runtime_service() {
        RuntimeService::Cash => ServiceType::Cash,
        RuntimeService::Cashback => ServiceType::Cashback,
        RuntimeService::GoodsOrServices => ServiceType::Goods,
    }
}

fn terminal_channel(params: &StoredTxnParams) -> TerminalChannel {
    if matches!(params.terminal_type, 0x14 | 0x24) {
        TerminalChannel::Atm
    } else {
        TerminalChannel::OtherThanAtm
    }
}

fn cvm_transaction_type(params: &StoredTxnParams) -> CvmTransactionType {
    match TransactionType::from_value(params.transaction_type)
        .cvm_transaction_class(matches!(params.terminal_type, 0x14 | 0x24))
    {
        CvmTransactionClass::UnattendedCash => CvmTransactionType::UnattendedCash,
        CvmTransactionClass::ManualCash => CvmTransactionType::ManualCash,
        CvmTransactionClass::PurchaseWithCashback => CvmTransactionType::PurchaseWithCashback,
        CvmTransactionClass::NonCash => CvmTransactionType::NonCash,
    }
}

fn run_cvm_processing(ctx: &mut KrnContext, params: &StoredTxnParams) -> Result<(), KernelError> {
    let cvm_list = parse_cvm_list(
        ctx.card_data
            .get(&[0x8e])
            .ok_or(KernelError::MissingMandatoryTag)?,
    )?;
    let contactless_interface = params.interface_preference == 2;
    let cdcvm_performed = if !contactless_interface {
        false
    } else if ctx.cvm_capabilities.cdcvm_performed {
        true
    } else {
        contactless_ctq_indicates_cdcvm(ctx, selected_aid_profile(ctx)?, true)?
    };
    let outcome = evaluate_cvm(
        &cvm_list,
        CvmContext {
            amount_authorized: params.amount_authorised_minor,
            transaction_currency_matches_application: transaction_currency_matches_application(
                &ctx.card_data,
                params,
            )?,
            transaction_type: cvm_transaction_type(params),
            interface: if contactless_interface {
                CvmInterface::Contactless
            } else {
                CvmInterface::Contact
            },
            offline_pin_supported: ctx.cvm_capabilities.offline_pin_supported
                || ctx.cvm_pin_handles.offline_plaintext.is_some()
                || ctx.cvm_pin_handles.offline_enciphered.is_some(),
            online_pin_supported: ctx.cvm_capabilities.online_pin_supported,
            signature_supported: ctx.cvm_capabilities.signature_supported,
            cdcvm_performed,
        },
        ctx.cvm_pin_handles,
    );

    let (cvm_results, event) = match outcome {
        CvmOutcome::Selected {
            action,
            cvm_results,
            tvr_bit,
        } => {
            if let Some(tvr_bit) = tvr_bit {
                ctx.tvr.set(tvr_bit);
            }
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

fn run_contactless_limit_processing(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
    profiles: &ProfileSet,
    params: &StoredTxnParams,
) -> Result<Option<KrnOutcome>, KernelError> {
    if params.interface_preference != KRN_INTERFACE_CONTACTLESS {
        return Ok(None);
    }
    let selected = ctx
        .selected_application
        .as_ref()
        .ok_or(KernelError::InvalidArgument)?;
    let scheme = profiles
        .schemes
        .get(selected.scheme_index)
        .ok_or(KernelError::InvalidProfile)?;
    if scheme.kernel_type != "c8_contactless" {
        return Err(KernelError::InvalidProfile);
    }
    let aid = scheme
        .aids
        .get(selected.aid_index)
        .ok_or(KernelError::InvalidProfile)?;
    if !aid
        .interfaces
        .iter()
        .any(|interface| interface == "contactless")
    {
        return Err(KernelError::InvalidProfile);
    }

    if let Some(outcome) = run_required_relay_resistance(ctx, runtime, aid)? {
        return Ok(Some(outcome));
    }

    let decision = evaluate_contactless_limits(ContactlessLimitInput {
        amount_authorised_minor: params.amount_authorised_minor,
        contactless_transaction_limit: aid.contactless_transaction_limit,
        contactless_cvm_limit: aid.contactless_cvm_limit,
        floor_limit: aid.floor_limit,
        cvm_satisfied: contactless_cvm_satisfied(ctx, aid, params.interface_preference == 2)?,
    });

    match decision {
        ContactlessLimitDecision::Allowed => Ok(None),
        ContactlessLimitDecision::OnlineRequired => {
            emit_contactless_outcome_value(ctx, &outcome_from_limit_decision(decision)?)?;
            Ok(None)
        }
        ContactlessLimitDecision::CvmRequired => {
            emit_contactless_outcome_value(ctx, &outcome_from_limit_decision(decision)?)?;
            ctx.fsm_state = FsmState::S16;
            ctx.state = KernelState::FinalOutcome;
            ctx.final_outcome = Some(KrnOutcome::TryAgain);
            ctx.last_error = KernelError::Ok;
            Ok(Some(KrnOutcome::TryAgain))
        }
        ContactlessLimitDecision::AlternateInterface => {
            emit_contactless_outcome_value(ctx, &outcome_from_limit_decision(decision)?)?;
            ctx.fsm_state = FsmState::S16;
            ctx.state = KernelState::FinalOutcome;
            ctx.final_outcome = Some(KrnOutcome::AlternateInterface);
            ctx.last_error = KernelError::Ok;
            Ok(Some(KrnOutcome::AlternateInterface))
        }
    }
}

fn validate_selected_kernel_mapping(
    ctx: &KrnContext,
    params: &StoredTxnParams,
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

    match params.interface_preference {
        KRN_INTERFACE_CONTACT => {
            if !aid
                .interfaces
                .iter()
                .any(|interface| interface == "contact")
            {
                return Err(KernelError::InvalidProfile);
            }
            match scheme.contact_kernel_type.as_deref() {
                Some(contact_kernel_type) if contact_kernel_type != "c8_contactless" => Ok(()),
                _ => Err(KernelError::InvalidProfile),
            }
        }
        KRN_INTERFACE_CONTACTLESS => {
            if scheme.kernel_type != "c8_contactless"
                || !aid
                    .interfaces
                    .iter()
                    .any(|interface| interface == "contactless")
            {
                return Err(KernelError::InvalidProfile);
            }
            Ok(())
        }
        _ => Err(KernelError::InvalidArgument),
    }
}

fn run_required_relay_resistance(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
    aid: &AidProfile,
) -> Result<Option<KrnOutcome>, KernelError> {
    let Some(profile) = aid.relay_resistance.as_ref() else {
        return Ok(None);
    };

    let started = Instant::now();
    let response = transmit_apdu(
        runtime,
        &profile.command_apdu,
        i32::from(profile.max_round_trip_ms),
    )?;
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u16::MAX)) as u16;
    match evaluate_relay_resistance(profile, &response, elapsed_ms) {
        RelayResistanceDecision::Passed => Ok(None),
        RelayResistanceDecision::Failed(failure_outcome) => {
            emit_contactless_outcome_value(
                ctx,
                &outcome_from_relay_resistance_failure(failure_outcome)?,
            )?;
            let outcome = match failure_outcome {
                RelayResistanceFailureOutcome::TryAgain => KrnOutcome::TryAgain,
                RelayResistanceFailureOutcome::AlternateInterface => KrnOutcome::AlternateInterface,
                RelayResistanceFailureOutcome::Terminate => KrnOutcome::Terminated,
            };
            ctx.fsm_state = FsmState::S16;
            ctx.state = KernelState::FinalOutcome;
            ctx.final_outcome = Some(outcome);
            ctx.last_error = KernelError::Ok;
            Ok(Some(outcome))
        }
    }
}

fn is_final_outcome_state(ctx: &KrnContext) -> bool {
    ctx.state == KernelState::FinalOutcome && matches!(ctx.fsm_state, FsmState::S14 | FsmState::S16)
}

fn contactless_cvm_satisfied(
    ctx: &KrnContext,
    aid: &AidProfile,
    contactless_interface: bool,
) -> Result<bool, KernelError> {
    let cvm_result_succeeded = ctx
        .card_data
        .get(&[0x9f, 0x34])
        .is_some_and(|result| result.len() == 3 && result[2] == 0x02);
    Ok(cvm_result_succeeded || contactless_ctq_indicates_cdcvm(ctx, aid, contactless_interface)?)
}

fn contactless_ctq_indicates_cdcvm(
    ctx: &KrnContext,
    aid: &AidProfile,
    contactless_interface: bool,
) -> Result<bool, KernelError> {
    if !contactless_interface || !aid.cdcvm_supported {
        return Ok(false);
    }
    let Some(ctq) = ctx.card_data.get(&[0x9f, 0x6c]) else {
        return Ok(false);
    };
    if ctq.len() != 2 {
        return Err(KernelError::ParseError);
    }
    Ok(ctq[0] & 0x10 != 0)
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
            transaction_type: params.transaction_type,
            exception_file_match: false,
            merchant_forced_online: false,
            offline_counter: ctx.offline_counter,
            random_sample_basis_points: ctx.trm_random_sample_basis_points,
            profile,
        },
        ctx.tvr,
        ctx.tsi,
    )?;
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
        iac: issuer_action_codes(&ctx.card_data, aid.issuer_action_codes)?,
        terminal_online_capable: ctx
            .txn_params
            .as_ref()
            .map(|params| terminal_type_online_capable(params.terminal_type))
            .transpose()?
            .unwrap_or(true),
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
    let cdol = cdol1_definition_for_first_gac(ctx)?;
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    let cdol_values =
        build_dol_with_policy(&cdol, &ctx.card_data, DolPaddingPolicy::RequireExactValues)?;
    let cda_control = cda_request_control_for_first_gac(ctx)?;
    let command = apdu::generate_ac(request, &cdol_values, cda_control)?.encode()?;
    let response = transmit_apdu_with_followups(
        runtime,
        &command,
        apdu_timeout(ctx),
        ApduContext::GenerateAc,
    )?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let body = &response[..response.len() - 2];
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
    require_generate_ac_success(ctx, sw, FsmEvent::GacFailed)?;

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
    if let Some(sdad) = parsed.signed_dynamic_application_data.as_ref() {
        ctx.card_data.put(&[0x9f, 0x4b], sdad)?;
    }
    let cda_verification_failed = ctx.selected_oda_method == Some(OdaMethod::Cda)
        && verify_combined_data_authentication(ctx, &parsed).is_err();
    if cda_verification_failed {
        ctx.tvr.set(Tvr::B1_CDA_FAILED);
        ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    }

    let cryptogram_type = parsed.cid.cryptogram_type();
    if cda_verification_failed
        && matches!(cryptogram_type, CryptogramType::Tc | CryptogramType::Aac)
    {
        ctx.first_gac_response = Some(parsed);
        return reroute_cda_failed_offline_cryptogram_through_taa(ctx);
    }

    let (event, state) = match cryptogram_type {
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

fn reroute_cda_failed_offline_cryptogram_through_taa(
    ctx: &mut KrnContext,
) -> Result<(), KernelError> {
    let profiles = ctx.profiles.clone().ok_or(KernelError::InvalidProfile)?;
    apply_transition(ctx, FsmEvent::CdaFailure)?;
    ctx.state = KernelState::TerminalActionAnalysis;
    run_terminal_action_analysis(ctx, &profiles)?;
    if ctx.requested_cryptogram == Some(CryptogramRequest::Arqc) {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

fn finish_offline_outcome_from_taa(ctx: &mut KrnContext) -> Result<KrnOutcome, KernelError> {
    let outcome = match ctx
        .requested_cryptogram
        .ok_or(KernelError::InvalidArgument)?
    {
        CryptogramRequest::Tc => KrnOutcome::ApprovedOffline,
        CryptogramRequest::Aac => KrnOutcome::DeclinedOffline,
        CryptogramRequest::Arqc => return Err(KernelError::InvalidArgument),
    };
    ctx.final_outcome = Some(outcome);
    ctx.last_error = KernelError::Ok;
    Ok(outcome)
}

fn finish_offline_outcome_from_first_gac(ctx: &mut KrnContext) -> Result<KrnOutcome, KernelError> {
    let response = ctx
        .first_gac_response
        .as_ref()
        .ok_or(KernelError::InvalidArgument)?;
    let outcome = match response.cid.cryptogram_type() {
        CryptogramType::Tc => KrnOutcome::ApprovedOffline,
        CryptogramType::Aac => KrnOutcome::DeclinedOffline,
        CryptogramType::Arqc | CryptogramType::ApplicationAuthenticationReferral => {
            return Err(KernelError::InvalidArgument);
        }
    };
    ctx.final_outcome = Some(outcome);
    ctx.last_error = KernelError::Ok;
    Ok(outcome)
}

fn apply_host_response(ctx: &mut KrnContext, bytes: &[u8]) -> Result<(), KernelError> {
    if ctx.fsm_state != FsmState::S11 {
        return Err(KernelError::InvalidArgument);
    }
    let response = parse_host_response(bytes)?;
    ctx.card_data
        .put(&[0x8a], &response.authorization_response_code)?;
    if let Some(authorization_code) = response.authorization_code.as_ref() {
        ctx.card_data.put(&[0x89], authorization_code)?;
    }
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
    let response = transmit_apdu_with_followups(
        runtime,
        &command,
        apdu_timeout(ctx),
        ApduContext::ExternalAuthenticate,
    )?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);

    ctx.tsi.set(Tsi::ISSUER_AUTHENTICATION_PERFORMED);
    let event = issuer_authentication_event_from_status(
        classify(ApduContext::ExternalAuthenticate, sw),
        &mut ctx.tvr,
    )?;
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

    for (script_index, script) in scripts.into_iter().enumerate() {
        let script_index = u16::try_from(script_index).map_err(|_| KernelError::LengthOverflow)?;
        let script_identifier = issuer_script_identifier_array(script.identifier.as_deref())?;
        apply_transition(ctx, FsmEvent::ScriptAvailable)?;
        let mut script_results = Vec::with_capacity(script.commands.len());
        let mut critical_failure = false;
        for (command_index, command) in script.commands.iter().enumerate() {
            let command_index =
                u16::try_from(command_index).map_err(|_| KernelError::LengthOverflow)?;
            let critical = issuer_script_command_is_critical(ctx, command)?;
            let script_context = ApduContext::IssuerScript { critical };
            let response =
                transmit_apdu_with_followups(runtime, command, apdu_timeout(ctx), script_context)?;
            if response.len() < 2 {
                return Err(KernelError::ParseError);
            }
            let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
            let result = ScriptCommandResult {
                sw1: sw.sw1,
                sw2: sw.sw2,
            };
            script_results.push(result);
            ctx.issuer_script_results.push(CapturedIssuerScriptResult {
                phase: script.phase,
                script_index,
                command_index,
                script_identifier,
                result,
            });
            match issuer_script_status(classify(script_context, sw))? {
                IssuerScriptStatus::Continue => {}
                IssuerScriptStatus::CriticalFailure => {
                    critical_failure = true;
                    break;
                }
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

fn cdol1_definition_for_first_gac(
    ctx: &KrnContext,
) -> Result<Vec<crate::dol::DolEntry>, KernelError> {
    if let Some(card_cdol1) = ctx.card_data.get(&[0x8c]) {
        return parse_dol(card_cdol1);
    }
    let default_cdol1 = selected_aid_profile(ctx)?
        .default_cdol1
        .as_deref()
        .ok_or(KernelError::MissingMandatoryTag)?;
    parse_dol(default_cdol1)
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

fn cda_request_control_for_first_gac(ctx: &KrnContext) -> Result<CdaRequestControl, KernelError> {
    if ctx.selected_oda_method != Some(OdaMethod::Cda) {
        return Ok(CdaRequestControl::NotRequested);
    }
    let encoding = selected_aid_profile(ctx)?
        .cda_request_encoding
        .ok_or(KernelError::UnsupportedCdaRequest)?;
    match encoding {
        CdaRequestEncoding::InCdolData => Ok(CdaRequestControl::InCdolData),
        CdaRequestEncoding::P1LowBits(bits) => Ok(CdaRequestControl::P1LowBits(bits)),
    }
}

fn state_after_script_phase(phase: ScriptPhase) -> KernelState {
    match phase {
        ScriptPhase::BeforeFinalGenerateAc => KernelState::SecondGenerateAc,
        ScriptPhase::AfterFinalGenerateAc => KernelState::FinalOutcome,
    }
}

fn script_phase_code(phase: ScriptPhase) -> u8 {
    match phase {
        ScriptPhase::BeforeFinalGenerateAc => KRN_SCRIPT_PHASE_BEFORE_FINAL_GAC,
        ScriptPhase::AfterFinalGenerateAc => KRN_SCRIPT_PHASE_AFTER_FINAL_GAC,
    }
}

fn issuer_script_identifier_array(
    identifier: Option<&[u8]>,
) -> Result<Option<[u8; KRN_ISSUER_SCRIPT_IDENTIFIER_LEN]>, KernelError> {
    match identifier {
        Some(identifier) => {
            let mut out = [0u8; KRN_ISSUER_SCRIPT_IDENTIFIER_LEN];
            if identifier.len() != out.len() {
                return Err(KernelError::ParseError);
            }
            out.copy_from_slice(identifier);
            Ok(Some(out))
        }
        None => Ok(None),
    }
}

fn run_final_generate_ac(
    ctx: &mut KrnContext,
    runtime: RuntimeCallbacks,
) -> Result<(), KernelError> {
    if ctx.fsm_state != FsmState::S14 {
        return Err(KernelError::InvalidArgument);
    }
    let host_arc = ctx
        .host_response
        .as_ref()
        .map(|response| response.authorization_response_code)
        .ok_or(KernelError::MissingMandatoryTag)?;
    let Some(cdol2) = ctx.card_data.get(&[0x8d]).map(|value| value.to_vec()) else {
        apply_transition(ctx, FsmEvent::FinalGenerateAcSkipped)?;
        ctx.final_outcome = Some(final_outcome_for_host_arc(host_arc));
        ctx.state = KernelState::PostFinalIssuerScripts;
        return Ok(());
    };
    let request = if host_arc == [b'0', b'0'] {
        CryptogramRequest::Tc
    } else {
        CryptogramRequest::Aac
    };
    ctx.card_data.put(&[0x95], &ctx.tvr.bytes())?;
    ctx.card_data.put(&[0x9b], &ctx.tsi.bytes())?;
    let cdol = parse_dol(&cdol2)?;
    let cdol_values =
        build_dol_with_policy(&cdol, &ctx.card_data, DolPaddingPolicy::RequireExactValues)?;
    let command =
        apdu::generate_ac(request, &cdol_values, CdaRequestControl::NotRequested)?.encode()?;
    let response = transmit_apdu_with_followups(
        runtime,
        &command,
        apdu_timeout(ctx),
        ApduContext::GenerateAc,
    )?;
    if response.len() < 2 {
        return Err(KernelError::ParseError);
    }
    let body = &response[..response.len() - 2];
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
    require_generate_ac_success(ctx, sw, FsmEvent::Gac2Failed)?;
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

fn final_outcome_for_host_arc(host_arc: [u8; 2]) -> KrnOutcome {
    if host_arc == [b'0', b'0'] {
        KrnOutcome::ApprovedOnline
    } else {
        KrnOutcome::DeclinedOnline
    }
}

fn issuer_action_codes(
    data: &DataStore,
    profile_fallback: ActionCodes,
) -> Result<ActionCodes, KernelError> {
    Ok(ActionCodes {
        denial: optional_fixed::<5>(data, &[0x9f, 0x0e])?.unwrap_or(profile_fallback.denial),
        online: optional_fixed::<5>(data, &[0x9f, 0x0f])?.unwrap_or(profile_fallback.online),
        default: optional_fixed::<5>(data, &[0x9f, 0x0d])?.unwrap_or(profile_fallback.default),
    })
}

fn fail_transaction(ctx: &mut KrnContext, error: KernelError) -> KrnOutcome {
    ctx.last_error = error;
    ctx.state = KernelState::Error;
    ctx.fsm_state = FsmState::Se;
    KrnOutcome::Error
}

fn run_transaction(ctx: &mut KrnContext) -> KrnOutcome {
    let Some(params) = ctx.txn_params.clone() else {
        return fail_transaction(ctx, KernelError::InvalidArgument);
    };
    let Some(runtime) = ctx.runtime else {
        return fail_transaction(ctx, KernelError::InvalidArgument);
    };
    let Some(profiles) = ctx.profiles.clone() else {
        return fail_transaction(ctx, KernelError::InvalidProfile);
    };
    let interface = match params.interface_preference {
        KRN_INTERFACE_CONTACT => Interface::Contact,
        KRN_INTERFACE_CONTACTLESS => Interface::Contactless,
        _ => {
            return fail_transaction(ctx, KernelError::InvalidArgument);
        }
    };
    if let Err(err) = fsm::transition(ctx.fsm_state, FsmEvent::CardDetected) {
        return fail_transaction(ctx, err);
    }
    ctx.fsm_state = FsmState::S2;
    ctx.state = KernelState::SelectEnvironment;

    let select = match apdu::select_environment(interface).encode() {
        Ok(bytes) => bytes,
        Err(err) => {
            return fail_transaction(ctx, err);
        }
    };
    let response = match transmit_apdu_with_followups(
        runtime,
        &select,
        apdu_timeout(ctx),
        ApduContext::SelectPse,
    ) {
        Ok(response) => response,
        Err(err) => {
            return fail_transaction(ctx, err);
        }
    };
    if response.len() < 2 {
        return fail_transaction(ctx, KernelError::ParseError);
    }
    let sw = StatusWord::new(response[response.len() - 2], response[response.len() - 1]);
    let fci = &response[..response.len() - 2];
    let pse_status = classify(ApduContext::SelectPse, sw);
    let event = match pse_status {
        StatusAction::Success => FsmEvent::PseSelected,
        StatusAction::FallbackToDirectAid => FsmEvent::PseNotFound,
        StatusAction::Fail { error } => {
            return fail_transaction(ctx, error);
        }
        _ => {
            return fail_transaction(ctx, KernelError::NoCommonAid);
        }
    };
    match fsm::transition(ctx.fsm_state, event) {
        Ok(transition) => {
            ctx.fsm_state = transition.to;
            ctx.state = KernelState::BuildCandidateList;
            ctx.last_error = KernelError::Ok;
        }
        Err(err) => {
            return fail_transaction(ctx, err);
        }
    }

    let candidates = match if matches!(pse_status, StatusAction::Success) {
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
            return fail_transaction(ctx, err);
        }
    };

    let mut selected: Option<(SelectionCandidate, Vec<u8>)> = None;
    for candidate in candidates {
        let transition = match fsm::transition(ctx.fsm_state, FsmEvent::CandidateAidAvailable) {
            Ok(transition) => transition,
            Err(err) => {
                return fail_transaction(ctx, err);
            }
        };
        ctx.fsm_state = transition.to;
        let select_aid =
            match apdu::select_aid(&candidate.select_aid, 0x00).and_then(|cmd| cmd.encode()) {
                Ok(bytes) => bytes,
                Err(err) => {
                    return fail_transaction(ctx, err);
                }
            };
        let select_response = match transmit_apdu_with_followups(
            runtime,
            &select_aid,
            apdu_timeout(ctx),
            ApduContext::SelectAid,
        ) {
            Ok(response) => response,
            Err(err) => {
                return fail_transaction(ctx, err);
            }
        };
        if select_response.len() < 2 {
            return fail_transaction(ctx, KernelError::ParseError);
        }
        let select_sw = StatusWord::new(
            select_response[select_response.len() - 2],
            select_response[select_response.len() - 1],
        );
        match classify(ApduContext::SelectAid, select_sw) {
            StatusAction::Success => {
                let select_fci = select_response[..select_response.len() - 2].to_vec();
                if let Err(err) = validate_selected_adf_name(&select_fci, &candidate) {
                    return fail_transaction(ctx, err);
                }
                let transition = match fsm::transition(ctx.fsm_state, FsmEvent::AidSelected) {
                    Ok(transition) => transition,
                    Err(err) => {
                        return fail_transaction(ctx, err);
                    }
                };
                ctx.fsm_state = transition.to;
                ctx.state = KernelState::Gpo;
                selected = Some((candidate, select_fci));
                break;
            }
            StatusAction::TryNextAid => {
                let transition = match fsm::transition(ctx.fsm_state, FsmEvent::AidNotSupported) {
                    Ok(transition) => transition,
                    Err(err) => {
                        return fail_transaction(ctx, err);
                    }
                };
                ctx.fsm_state = transition.to;
            }
            StatusAction::Fail { error } => {
                return fail_transaction(ctx, error);
            }
            _ => {
                return fail_transaction(ctx, KernelError::InvalidArgument);
            }
        }
    }

    let Some((selected_candidate, selected_fci)) = selected else {
        let _ = fsm::transition(ctx.fsm_state, FsmEvent::NoCandidateLeft);
        return fail_transaction(ctx, KernelError::NoCommonAid);
    };

    let pdol = match parse_pdol_from_fci(&selected_fci) {
        Ok(pdol) => pdol,
        Err(err) => {
            return fail_transaction(ctx, err);
        }
    };
    let transaction_date = match ctx.profile_evaluation_date {
        Some(date) => date,
        None => {
            return fail_transaction(ctx, KernelError::InvalidProfile);
        }
    };
    let unpredictable_number =
        match request_unpredictable_number(runtime, ctx.last_unpredictable_number) {
            Ok(value) => value,
            Err(err) => {
                return fail_transaction(ctx, err);
            }
        };
    ctx.last_unpredictable_number = Some(unpredictable_number);
    let data = match transaction_data_store(
        &params,
        unpredictable_number,
        transaction_date,
        ctx.tvr,
        ctx.tsi,
        TerminalDolInputs {
            terminal_capabilities: ctx.terminal_capabilities,
            additional_terminal_capabilities: ctx.additional_terminal_capabilities,
            terminal_transaction_qualifiers: ctx.terminal_transaction_qualifiers,
        },
    ) {
        Ok(data) => data,
        Err(err) => {
            return fail_transaction(ctx, err);
        }
    };
    ctx.card_data = data;
    ctx.offline_auth_records.clear();
    let gpo = match apdu::get_processing_options(&pdol, &ctx.card_data).and_then(|cmd| cmd.encode())
    {
        Ok(bytes) => bytes,
        Err(err) => {
            return fail_transaction(ctx, err);
        }
    };
    let gpo_response =
        match transmit_apdu_with_followups(runtime, &gpo, apdu_timeout(ctx), ApduContext::Gpo) {
            Ok(response) => response,
            Err(err) => {
                return fail_transaction(ctx, err);
            }
        };
    if gpo_response.len() < 2 {
        return fail_transaction(ctx, KernelError::ParseError);
    }
    let gpo_sw = [
        gpo_response[gpo_response.len() - 2],
        gpo_response[gpo_response.len() - 1],
    ];
    if gpo_sw != [0x90, 0x00] {
        let _ = fsm::transition(ctx.fsm_state, FsmEvent::GpoFailed);
        return fail_transaction(ctx, KernelError::MissingMandatoryTag);
    }
    let parsed_gpo = match parse_gpo_response(&gpo_response[..gpo_response.len() - 2]) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = fsm::transition(ctx.fsm_state, FsmEvent::GpoFailed);
            return fail_transaction(ctx, err);
        }
    };
    let event = match parsed_gpo.format {
        GpoResponseFormat::Template77 => FsmEvent::GpoTemplate77,
        GpoResponseFormat::Template80 => FsmEvent::GpoTemplate80,
    };
    if let Err(err) = ctx.card_data.put(&[0x82], &parsed_gpo.aip) {
        return fail_transaction(ctx, err);
    }
    let transition = match fsm::transition(ctx.fsm_state, event) {
        Ok(transition) => transition,
        Err(err) => {
            return fail_transaction(ctx, err);
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
        aid: selected_candidate.select_aid,
        scheme_index: selected_candidate.scheme_index,
        aid_index: selected_candidate.aid_index,
        aip: Some(parsed_gpo.aip),
        afl: parsed_gpo.afl,
    });
    if let Err(err) = validate_selected_kernel_mapping(ctx, &params, &profiles) {
        return fail_transaction(ctx, err);
    }
    if ctx.fsm_state == FsmState::S4 {
        if let Err(err) = read_application_records(ctx, runtime, &selected_afl) {
            return fail_transaction(ctx, err);
        }
    }
    if ctx.fsm_state == FsmState::S5 {
        if let Err(err) = run_offline_data_authentication(ctx, &profiles, Some(runtime)) {
            return fail_transaction(ctx, err);
        }
    }
    if ctx.fsm_state == FsmState::S6 {
        if let Err(err) = run_processing_restrictions(ctx, &params) {
            return fail_transaction(ctx, err);
        }
    }
    if ctx.fsm_state == FsmState::S7 {
        if let Err(err) = run_cvm_processing(ctx, &params) {
            return fail_transaction(ctx, err);
        }
        match run_contactless_limit_processing(ctx, runtime, &profiles, &params) {
            Ok(Some(outcome)) => return outcome,
            Ok(None) => {}
            Err(err) => {
                return fail_transaction(ctx, err);
            }
        }
    }
    if ctx.fsm_state == FsmState::S8 {
        if let Err(err) = run_terminal_risk_management(ctx, &profiles, &params) {
            return fail_transaction(ctx, err);
        }
    }
    if ctx.fsm_state == FsmState::S9 {
        if let Err(err) = run_terminal_action_analysis(ctx, &profiles) {
            return fail_transaction(ctx, err);
        }
        if is_final_outcome_state(ctx) {
            return match finish_offline_outcome_from_taa(ctx) {
                Ok(outcome) => outcome,
                Err(err) => fail_transaction(ctx, err),
            };
        }
    }
    if ctx.fsm_state == FsmState::S10 {
        if let Err(err) = run_first_generate_ac(ctx, runtime) {
            return fail_transaction(ctx, err);
        }
        match ctx.fsm_state {
            FsmState::S11 => {
                ctx.last_error = KernelError::Ok;
                return KrnOutcome::OnlineRequired;
            }
            _ if is_final_outcome_state(ctx) => {
                let result = if ctx.tvr.is_set(Tvr::B1_CDA_FAILED) {
                    finish_offline_outcome_from_taa(ctx)
                } else {
                    finish_offline_outcome_from_first_gac(ctx)
                };
                return match result {
                    Ok(outcome) => outcome,
                    Err(err) => fail_transaction(ctx, err),
                };
            }
            _ => {}
        }
    }

    fail_transaction(ctx, KernelError::InvalidArgument)
}

fn transmit_apdu(
    runtime: RuntimeCallbacks,
    command: &[u8],
    timeout_ms: i32,
) -> Result<Vec<u8>, KernelError> {
    validate_callback_timeout(timeout_ms)?;
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
        return Err(KernelError::from_code(status).unwrap_or(KernelError::InternalError));
    }
    if response_len > response.len() {
        return Err(KernelError::LengthOverflow);
    }
    Ok(response[..response_len].to_vec())
}

fn validate_callback_timeout(timeout_ms: i32) -> Result<(), KernelError> {
    if (KRN_CALLBACK_TIMEOUT_MIN_MS..=KRN_CALLBACK_TIMEOUT_MAX_MS).contains(&timeout_ms) {
        Ok(())
    } else {
        Err(KernelError::InvalidArgument)
    }
}

fn apdu_timeout(ctx: &KrnContext) -> i32 {
    ctx.callback_timeouts.apdu_transport_timeout_ms
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

fn emit_contactless_outcome_value(
    ctx: &mut KrnContext,
    outcome: &ContactlessOutcome,
) -> Result<(), KernelError> {
    let callback = ctx
        .contactless_outcome_callback
        .ok_or(KernelError::InvalidArgument)?;
    let view = outcome.as_ffi();
    unsafe {
        callback(&view, ctx.contactless_outcome_user_data);
    }
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
    use crate::c8::RelayResistanceProfile;
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
    static LAST_TRANSMITTED_COMMAND: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static TRANSMIT_TIMEOUT_MS: AtomicI32 = AtomicI32::new(0);
    static ISSUER_AUTH_SW1: AtomicU8 = AtomicU8::new(0x90);
    static ISSUER_AUTH_SW2: AtomicU8 = AtomicU8::new(0x00);
    static SCRIPT_SW1: AtomicU8 = AtomicU8::new(0x90);
    static SCRIPT_SW2: AtomicU8 = AtomicU8::new(0x00);
    static RELAY_SW1: AtomicU8 = AtomicU8::new(0x90);
    static RELAY_SW2: AtomicU8 = AtomicU8::new(0x00);
    static SCRIPT_FOLLOWUP_MODE: AtomicU8 = AtomicU8::new(0);
    static FOLLOWUP_TRANSMIT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FOLLOWUP_TRANSMITTED_INS: AtomicU8 = AtomicU8::new(0);
    static FOLLOWUP_TRANSMITTED_LEN: AtomicUsize = AtomicUsize::new(0);
    static DDA_RESPONSE_MODE: AtomicU8 = AtomicU8::new(0);
    static READ_RECORD_RESPONSE_MODE: AtomicU8 = AtomicU8::new(0);

    struct SelectionStatusPolicyScript {
        counter: AtomicUsize,
        mode: u8,
        commands: Mutex<Vec<Vec<u8>>>,
    }

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

    unsafe fn set_test_trm_random_selection_sample(ctx: *mut KrnContext) {
        assert_eq!(
            krn_set_trm_random_selection_sample(ctx, 9_999),
            KernelError::Ok.code()
        );
    }

    fn stored_txn_params(interface_preference: u8) -> StoredTxnParams {
        StoredTxnParams {
            amount_authorised_minor: 2_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference,
            merchant_name_location: Vec::new(),
        }
    }

    fn runtime_with_transmit(transmit_apdu: KrnTransmitApduCallback) -> RuntimeCallbacks {
        RuntimeCallbacks {
            transmit_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        }
    }

    unsafe extern "C" fn fail_transmit_apdu(
        _cmd: *const u8,
        _cmd_len: usize,
        _resp: *mut u8,
        _resp_len: *mut usize,
        _timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        KernelError::HostTimeout.code()
    }

    unsafe extern "C" fn short_pse_transmit_apdu(
        _cmd: *const u8,
        _cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        _timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        if !resp.is_null() {
            *resp = 0x6f;
        }
        *resp_len = 1;
        KernelError::Ok.code()
    }

    unsafe extern "C" fn failed_pse_transmit_apdu(
        _cmd: *const u8,
        _cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        _timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let response = [0x69, 0x85];
        *resp_len = response.len();
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    #[test]
    fn run_transaction_early_error_paths_fail_closed() {
        let mut ctx = KrnContext::new();
        ctx.txn_params = Some(stored_txn_params(KRN_INTERFACE_CONTACT));
        ctx.runtime = Some(runtime_with_transmit(capture_select_apdu));
        assert_eq!(run_transaction(&mut ctx), KrnOutcome::Error);
        assert_eq!(ctx.last_error, KernelError::InvalidProfile);
        assert_eq!(ctx.state, KernelState::Error);
        assert_eq!(ctx.fsm_state, FsmState::Se);

        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.txn_params = Some(stored_txn_params(0xff));
        ctx.runtime = Some(runtime_with_transmit(capture_select_apdu));
        assert_eq!(run_transaction(&mut ctx), KrnOutcome::Error);
        assert_eq!(ctx.last_error, KernelError::InvalidArgument);
        assert_eq!(ctx.state, KernelState::Error);
        assert_eq!(ctx.fsm_state, FsmState::Se);

        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.txn_params = Some(stored_txn_params(KRN_INTERFACE_CONTACT));
        ctx.runtime = Some(runtime_with_transmit(capture_select_apdu));
        ctx.fsm_state = FsmState::S16;
        assert_eq!(run_transaction(&mut ctx), KrnOutcome::Error);
        assert_eq!(ctx.state, KernelState::Error);
        assert_eq!(ctx.fsm_state, FsmState::Se);

        for (transmit, expected_error) in [
            (
                fail_transmit_apdu as KrnTransmitApduCallback,
                KernelError::HostTimeout,
            ),
            (
                short_pse_transmit_apdu as KrnTransmitApduCallback,
                KernelError::ParseError,
            ),
            (
                failed_pse_transmit_apdu as KrnTransmitApduCallback,
                KernelError::NoCommonAid,
            ),
        ] {
            let mut ctx = KrnContext::new();
            install_profile_selection(&mut ctx);
            ctx.txn_params = Some(stored_txn_params(KRN_INTERFACE_CONTACT));
            ctx.state = KernelState::ParamsSet;
            ctx.fsm_state = FsmState::S1;
            ctx.runtime = Some(runtime_with_transmit(transmit));
            assert_eq!(run_transaction(&mut ctx), KrnOutcome::Error);
            assert_eq!(ctx.last_error, expected_error);
            assert_eq!(ctx.state, KernelState::Error);
            assert_eq!(ctx.fsm_state, FsmState::Se);
        }
    }

    #[test]
    fn callback_timeout_policy_is_versioned_and_bounded() {
        unsafe {
            assert_eq!(
                krn_get_callback_timeout_policy(ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );

            let mut policy = KrnCallbackTimeoutPolicy {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnCallbackTimeoutPolicy>() as u32,
                min_timeout_ms: 0,
                max_timeout_ms: 0,
                apdu_transport_timeout_ms: 0,
                host_authorization_timeout_ms: 0,
                pin_entry_timeout_ms: 0,
                contactless_ui_timeout_ms: 0,
            };
            assert_eq!(
                krn_get_callback_timeout_policy(&mut policy),
                KernelError::Ok.code()
            );
            assert_eq!(policy.min_timeout_ms, KRN_CALLBACK_TIMEOUT_MIN_MS);
            assert_eq!(policy.max_timeout_ms, KRN_CALLBACK_TIMEOUT_MAX_MS);
            for timeout in [
                policy.apdu_transport_timeout_ms,
                policy.host_authorization_timeout_ms,
                policy.pin_entry_timeout_ms,
                policy.contactless_ui_timeout_ms,
            ] {
                assert!((policy.min_timeout_ms..=policy.max_timeout_ms).contains(&timeout));
            }
            assert_eq!(policy.apdu_transport_timeout_ms, APDU_TRANSMIT_TIMEOUT_MS);

            policy.abi_version = KRN_ABI_VERSION + 1;
            assert_eq!(
                krn_get_callback_timeout_policy(&mut policy),
                KernelError::InvalidArgument.code()
            );
            policy.abi_version = KRN_ABI_VERSION;
            policy.struct_size = 0;
            assert_eq!(
                krn_get_callback_timeout_policy(&mut policy),
                KernelError::InvalidArgument.code()
            );
        }

        assert_eq!(
            validate_callback_timeout(KRN_CALLBACK_TIMEOUT_MIN_MS),
            Ok(())
        );
        assert_eq!(
            validate_callback_timeout(KRN_CALLBACK_TIMEOUT_MAX_MS),
            Ok(())
        );
        assert_eq!(
            validate_callback_timeout(KRN_CALLBACK_TIMEOUT_MIN_MS - 1),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(
            validate_callback_timeout(KRN_CALLBACK_TIMEOUT_MAX_MS + 1),
            Err(KernelError::InvalidArgument)
        );
    }

    #[test]
    fn ffi_boundary_rejects_null_bad_abi_busy_and_bad_setter_inputs() {
        unsafe {
            assert_eq!(
                krn_init(ptr::null(), ptr::null(), ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );

            let mut out_ctx = ptr::null_mut();
            let bad_cfg = KrnConfigBlob {
                abi_version: KRN_ABI_VERSION + 1,
                struct_size: mem::size_of::<KrnConfigBlob>() as u32,
                bytes: ptr::null(),
                len: 0,
            };
            assert_eq!(
                krn_init(&bad_cfg, ptr::null(), &mut out_ctx),
                KernelError::InvalidArgument.code()
            );
            assert!(out_ctx.is_null());

            assert_eq!(
                krn_reset(ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_last_error(ptr::null()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(krn_get_fsm_state(ptr::null()), FsmState::Se.code());

            let mut ctx = KrnContext::new();
            ctx.last_error = KernelError::HostTimeout;
            assert_eq!(krn_get_last_error(&ctx), KernelError::HostTimeout.code());
            ctx.busy = true;
            assert_eq!(krn_reset(&mut ctx), KernelError::Busy.code());
            ctx.busy = false;
            ctx.last_error = KernelError::HostTimeout;
            ctx.state = KernelState::FinalOutcome;
            assert_eq!(krn_reset(&mut ctx), KernelError::Ok.code());
            assert_eq!(ctx.last_error, KernelError::Ok);
            assert_eq!(ctx.state, KernelState::Idle);

            let mut policy = KrnCallbackTimeoutPolicy {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnCallbackTimeoutPolicy>() as u32,
                min_timeout_ms: 0,
                max_timeout_ms: 0,
                apdu_transport_timeout_ms: 0,
                host_authorization_timeout_ms: 0,
                pin_entry_timeout_ms: 0,
                contactless_ui_timeout_ms: 0,
            };
            assert_eq!(
                krn_get_context_callback_timeout_policy(ptr::null(), ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            policy.abi_version = KRN_ABI_VERSION + 1;
            assert_eq!(
                krn_get_context_callback_timeout_policy(&ctx, &mut policy),
                KernelError::InvalidArgument.code()
            );
            policy.abi_version = KRN_ABI_VERSION;
            policy.struct_size = 0;
            assert_eq!(
                krn_get_context_callback_timeout_policy(&ctx, &mut policy),
                KernelError::InvalidArgument.code()
            );
            policy.struct_size = mem::size_of::<KrnCallbackTimeoutPolicy>() as u32;
            ctx.callback_timeouts.apdu_transport_timeout_ms = 4_321;
            assert_eq!(
                krn_get_context_callback_timeout_policy(&ctx, &mut policy),
                KernelError::Ok.code()
            );
            assert_eq!(policy.apdu_transport_timeout_ms, 4_321);

            assert_eq!(
                krn_set_transaction_params(ptr::null_mut(), ptr::null()),
                KernelError::InvalidArgument.code()
            );
            for call in [
                krn_set_terminal_capabilities(ptr::null_mut(), 0, 0, 0),
                krn_set_additional_terminal_capabilities(ptr::null_mut(), 0, 0, 0, 0, 0),
                krn_set_terminal_transaction_qualifiers(ptr::null_mut(), 0, 0, 0, 0),
                krn_set_nonvolatile_offline_counter(ptr::null_mut(), 0),
                krn_set_trm_random_selection_sample(ptr::null_mut(), 0),
                krn_set_cvm_capabilities(ptr::null_mut(), 0, 0, 0),
                krn_set_offline_pin_capability(ptr::null_mut(), 0),
                krn_set_offline_pin_handle(ptr::null_mut(), KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 1),
            ] {
                assert_eq!(call, KernelError::InvalidArgument.code());
            }

            ctx.busy = true;
            assert_eq!(
                krn_set_terminal_capabilities(&mut ctx, 0xe0, 0xb0, 0xc8),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_additional_terminal_capabilities(&mut ctx, 0, 0, 0, 0, 0),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_terminal_transaction_qualifiers(&mut ctx, 0, 0, 0, 0),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_nonvolatile_offline_counter(&mut ctx, 1),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_trm_random_selection_sample(&mut ctx, 1),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_cvm_capabilities(&mut ctx, 1, 0, 0),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_offline_pin_capability(&mut ctx, 1),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_offline_pin_handle(&mut ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 1),
                KernelError::Busy.code()
            );
            ctx.busy = false;

            assert_eq!(
                krn_set_terminal_capabilities(&mut ctx, 0xe0, 0xb0, 0xc8),
                KernelError::Ok.code()
            );
            assert_eq!(
                krn_set_additional_terminal_capabilities(&mut ctx, 0x70, 0x80, 0xf0, 0xf0, 0xff),
                KernelError::Ok.code()
            );
            assert_eq!(
                krn_set_terminal_transaction_qualifiers(&mut ctx, 0x36, 0, 0x40, 0),
                KernelError::Ok.code()
            );
            assert_eq!(
                krn_set_nonvolatile_offline_counter(&mut ctx, 7),
                KernelError::Ok.code()
            );
            assert_eq!(ctx.offline_counter.unwrap().count, 7);
            assert_eq!(
                krn_set_trm_random_selection_sample(&mut ctx, 10_000),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_trm_random_selection_sample(&mut ctx, 9_999),
                KernelError::Ok.code()
            );
            assert_eq!(ctx.trm_random_sample_basis_points, Some(9_999));
            assert_eq!(
                krn_set_cvm_capabilities(&mut ctx, 2, 0, 0),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_cvm_capabilities(&mut ctx, 1, 1, 1),
                KernelError::Ok.code()
            );
            assert!(ctx.cvm_capabilities.online_pin_supported);
            assert!(ctx.cvm_capabilities.signature_supported);
            assert!(ctx.cvm_capabilities.cdcvm_performed);
            assert_eq!(
                krn_set_offline_pin_capability(&mut ctx, 2),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_offline_pin_capability(&mut ctx, 1),
                KernelError::Ok.code()
            );
            assert!(ctx.cvm_capabilities.offline_pin_supported);
            assert_eq!(
                krn_set_offline_pin_handle(&mut ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 0),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_offline_pin_handle(&mut ctx, 0xff, 1),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_offline_pin_handle(&mut ctx, KRN_PIN_METHOD_OFFLINE_PLAINTEXT, 1),
                KernelError::Ok.code()
            );
            assert_eq!(
                krn_set_offline_pin_handle(&mut ctx, KRN_PIN_METHOD_OFFLINE_ENCIPHERED, 2),
                KernelError::Ok.code()
            );
        }
    }

    #[test]
    fn apdu_transport_timeout_comes_from_active_context_policy() {
        let mut ctx = KrnContext::new();
        ctx.callback_timeouts.apdu_transport_timeout_ms = 1_237;
        assert_eq!(apdu_timeout(&ctx), 1_237);
    }

    #[test]
    fn first_gac_cda_request_control_is_profile_defined() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        assert_eq!(
            cda_request_control_for_first_gac(&ctx).unwrap(),
            CdaRequestControl::NotRequested
        );

        ctx.selected_oda_method = Some(OdaMethod::Cda);
        assert_eq!(
            cda_request_control_for_first_gac(&ctx).unwrap(),
            CdaRequestControl::InCdolData
        );

        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].cda_request_encoding = None;
        assert_eq!(
            cda_request_control_for_first_gac(&ctx).unwrap_err(),
            KernelError::UnsupportedCdaRequest
        );
    }

    #[test]
    fn cda_authentication_data_follows_profile_policy() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        let response = GenerateAcResponse {
            cid: crate::cid::Cid::new(0x80),
            application_cryptogram: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            atc: [0x00, 0x09],
            issuer_application_data: Vec::new(),
            icc_dynamic_number: None,
            signed_dynamic_application_data: Some(vec![0xaa; 48]),
        };
        assert_eq!(
            cda_authentication_data(selected_aid_profile(&ctx).unwrap(), &response).unwrap(),
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );

        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].cda_authentication_data =
            CdaAuthenticationData::ApplicationCryptogramAndIccDynamicNumber;
        assert_eq!(
            cda_authentication_data(selected_aid_profile(&ctx).unwrap(), &response).unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        let response = GenerateAcResponse {
            icc_dynamic_number: Some(vec![0x01, 0x02, 0x03, 0x04]),
            ..response
        };
        assert_eq!(
            cda_authentication_data(selected_aid_profile(&ctx).unwrap(), &response).unwrap(),
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn transaction_params_bind_minor_units_to_currency_exponent() {
        let merchant = b"HYPERION TEST MERCHANT";
        let params = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_234,
            amount_other_minor: 56,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: merchant.as_ptr(),
            merchant_name_location_len: merchant.len(),
        };
        let stored = unsafe { read_transaction_params(&params).unwrap() };
        assert_eq!(stored.amount_authorised_minor, 1_234);
        assert_eq!(stored.amount_other_minor, 56);
        assert_eq!(stored.currency_code, 840);
        assert_eq!(stored.currency_exponent, 2);

        let data = transaction_data_store(
            &stored,
            [0x11, 0x22, 0x33, 0x44],
            EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
            Tvr::cleared(),
            Tsi::cleared(),
            TerminalDolInputs::default(),
        )
        .unwrap();
        assert_eq!(
            data.get(&[0x9f, 0x02]),
            Some(&[0, 0, 0, 0x00, 0x12, 0x34][..])
        );
        assert_eq!(data.get(&[0x9f, 0x03]), Some(&[0, 0, 0, 0, 0, 0x56][..]));
        assert_eq!(data.get(&[0x5f, 0x2a]), Some(&[0x08, 0x40][..]));
        assert_eq!(data.get(&[0x5f, 0x36]), Some(&[0x02][..]));

        let invalid_exponent = KrnTxnParams {
            currency_exponent: 10,
            ..params
        };
        assert_eq!(
            unsafe { read_transaction_params(&invalid_exponent).unwrap_err() },
            KernelError::InvalidArgument
        );
        let invalid_terminal_type = KrnTxnParams {
            terminal_type: 0x00,
            ..params
        };
        assert_eq!(
            unsafe { read_transaction_params(&invalid_terminal_type).unwrap_err() },
            KernelError::InvalidArgument
        );
        assert_eq!(terminal_type_online_capable(0x22), Ok(true));
        assert_eq!(terminal_type_online_capable(0x23), Ok(false));

        let oversized_merchant = KrnTxnParams {
            merchant_name_location: ptr::null(),
            merchant_name_location_len: MAX_MERCHANT_NAME_LOCATION_LEN + 1,
            ..params
        };
        assert_eq!(
            unsafe { read_transaction_params(&oversized_merchant).unwrap_err() },
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn processing_restriction_mapping_separates_service_from_terminal_channel() {
        let mut params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x01,
            terminal_type: 0x14,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACT,
            merchant_name_location: Vec::new(),
        };

        assert_eq!(service_type(&params), ServiceType::Cash);
        assert_eq!(terminal_channel(&params), TerminalChannel::Atm);

        params.terminal_type = 0x22;
        assert_eq!(service_type(&params), ServiceType::Cash);
        assert_eq!(terminal_channel(&params), TerminalChannel::OtherThanAtm);

        params.transaction_type = 0x00;
        params.terminal_type = 0x14;
        assert_eq!(service_type(&params), ServiceType::Goods);
        assert_eq!(terminal_channel(&params), TerminalChannel::Atm);
    }

    #[test]
    fn transaction_params_require_explicit_supported_interface() {
        let params = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_234,
            amount_other_minor: 56,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACT,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 0,
        };

        assert_eq!(
            unsafe { read_transaction_params(&params).unwrap() }.interface_preference,
            KRN_INTERFACE_CONTACT
        );
        let contactless = KrnTxnParams {
            interface_preference: KRN_INTERFACE_CONTACTLESS,
            ..params
        };
        assert_eq!(
            unsafe { read_transaction_params(&contactless).unwrap() }.interface_preference,
            KRN_INTERFACE_CONTACTLESS
        );

        for interface_preference in [0, 3] {
            let invalid = KrnTxnParams {
                interface_preference,
                ..params
            };
            assert_eq!(
                unsafe { read_transaction_params(&invalid).unwrap_err() },
                KernelError::InvalidArgument
            );
        }
    }

    #[test]
    fn transaction_params_clear_previous_transaction_artifacts() {
        let mut ctx = KrnContext::new();
        ctx.selected_oda_method = Some(OdaMethod::Sda);
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        ctx.first_gac_response = Some(GenerateAcResponse {
            cid: crate::cid::Cid::new(0x80),
            application_cryptogram: [0x11; 8],
            atc: [0x00, 0x01],
            issuer_application_data: vec![0x9f, 0x10, 0x01],
            icc_dynamic_number: Some(vec![0x01, 0x02, 0x03, 0x04]),
            signed_dynamic_application_data: None,
        });
        ctx.final_gac_response = Some(GenerateAcResponse {
            cid: crate::cid::Cid::new(0x40),
            application_cryptogram: [0x22; 8],
            atc: [0x00, 0x02],
            issuer_application_data: Vec::new(),
            icc_dynamic_number: None,
            signed_dynamic_application_data: Some(vec![0xaa; 48]),
        });
        ctx.final_outcome = Some(KrnOutcome::ApprovedOnline);
        ctx.online_authorization_data = Some(vec![0x70, 0x00]);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: None,
            scripts: Vec::new(),
        });
        ctx.issuer_script_results.push(CapturedIssuerScriptResult {
            phase: ScriptPhase::BeforeFinalGenerateAc,
            script_index: 0,
            command_index: 0,
            script_identifier: None,
            result: ScriptCommandResult {
                sw1: 0x90,
                sw2: 0x00,
            },
        });
        ctx.card_data.put(&[0x9f, 0x10], &[0x01]).unwrap();
        ctx.offline_auth_records.push(StaticAuthenticationRecord {
            sfi: 1,
            record: 1,
            body: vec![0x70, 0x00],
        });
        ctx.last_unpredictable_number = Some([0x01, 0x02, 0x03, 0x04]);

        let params = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_234,
            amount_other_minor: 56,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACT,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 0,
        };

        assert_eq!(
            unsafe { krn_set_transaction_params(&mut ctx, &params) },
            KernelError::Ok.code()
        );
        assert_eq!(ctx.state, KernelState::ParamsSet);
        assert_eq!(ctx.fsm_state, FsmState::S1);
        assert!(ctx.selected_oda_method.is_none());
        assert!(ctx.requested_cryptogram.is_none());
        assert!(ctx.first_gac_response.is_none());
        assert!(ctx.final_gac_response.is_none());
        assert!(ctx.final_outcome.is_none());
        assert!(ctx.online_authorization_data.is_none());
        assert!(ctx.host_response.is_none());
        assert!(ctx.issuer_script_results.is_empty());
        assert!(ctx.card_data.get(&[0x9f, 0x10]).is_none());
        assert!(ctx.offline_auth_records.is_empty());
        assert_eq!(
            ctx.last_unpredictable_number,
            Some([0x01, 0x02, 0x03, 0x04])
        );
    }

    #[test]
    fn transaction_params_reject_non_three_digit_numeric_codes() {
        let merchant = b"HYPERION TEST MERCHANT";
        let base = || KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_234,
            amount_other_minor: 56,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: merchant.as_ptr(),
            merchant_name_location_len: merchant.len(),
        };

        let stored = unsafe { read_transaction_params(&base()).unwrap() };
        let data = transaction_data_store(
            &stored,
            [0x11, 0x22, 0x33, 0x44],
            EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
            Tvr::cleared(),
            Tsi::cleared(),
            TerminalDolInputs::default(),
        )
        .unwrap();
        assert_eq!(data.get(&[0x5f, 0x2a]), Some(&[0x08, 0x40][..]));
        assert_eq!(data.get(&[0x9f, 0x1a]), Some(&[0x08, 0x40][..]));

        let invalid_currency = KrnTxnParams {
            currency_code: 1000,
            ..base()
        };
        assert_eq!(
            unsafe { read_transaction_params(&invalid_currency).unwrap_err() },
            KernelError::InvalidArgument
        );

        let invalid_terminal_country = KrnTxnParams {
            terminal_country_code: 1000,
            ..base()
        };
        assert_eq!(
            unsafe { read_transaction_params(&invalid_terminal_country).unwrap_err() },
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn ffi_internal_helpers_cover_remaining_security_edges() {
        unsafe {
            assert_eq!(
                krn_build_select_environment(
                    ptr::null_mut(),
                    false,
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                KernelError::InvalidArgument.code()
            );
        }
        assert_eq!(trace_context(0), Ok(ApduTraceContext::Generic));
        assert_eq!(trace_context(2).unwrap_err(), KernelError::InvalidArgument);

        let merchant = b"HYPERION TEST MERCHANT";
        let params = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_234,
            amount_other_minor: 56,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x09,
            terminal_type: 0x24,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACTLESS,
            merchant_name_location: merchant.as_ptr(),
            merchant_name_location_len: merchant.len(),
        };
        let stored = unsafe { read_transaction_params(&params).unwrap() };
        assert_eq!(stored.merchant_name_location, merchant);
        assert_eq!(service_type(&stored), ServiceType::Cashback);
        assert_eq!(terminal_channel(&stored), TerminalChannel::Atm);

        let terminal_inputs = TerminalDolInputs {
            terminal_capabilities: Some(TerminalCapabilities::parse(&[0xe0, 0xf8, 0xe8]).unwrap()),
            additional_terminal_capabilities: Some(
                AdditionalTerminalCapabilities::parse(&[0x11, 0x22, 0x33, 0x44, 0x55]).unwrap(),
            ),
            terminal_transaction_qualifiers: Some(
                TerminalTransactionQualifiers::parse(&[0x36, 0x00, 0x80, 0x00]).unwrap(),
            ),
        };
        let data = transaction_data_store(
            &stored,
            [0xaa, 0xbb, 0xcc, 0xdd],
            EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
            Tvr::cleared(),
            Tsi::cleared(),
            terminal_inputs,
        )
        .unwrap();
        assert_eq!(data.get(&[0x9f, 0x4e]), Some(&merchant[..]));
        assert_eq!(data.get(&[0x9f, 0x33]), Some(&[0xe0, 0xf8, 0xe8][..]));
        assert_eq!(
            data.get(&[0x9f, 0x40]),
            Some(&[0x11, 0x22, 0x33, 0x44, 0x55][..])
        );
        assert_eq!(data.get(&[0x9f, 0x66]), Some(&[0x36, 0x00, 0x80, 0x00][..]));

        let rng_failure_runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fail_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            request_unpredictable_number(rng_failure_runtime, None).unwrap_err(),
            KernelError::RngFailure
        );

        assert_eq!(
            encode_online_authorization_package(&OnlineAuthorizationPackage {
                objects: vec![crate::gac::TagValue {
                    tag: vec![0x9f, 0x26],
                    value: vec![0x11; 8],
                }],
            })
            .unwrap(),
            vec![0x9f, 0x26, 0x08, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]
        );

        let mut currency_data = DataStore::new();
        assert_eq!(
            transaction_currency_matches_application(&currency_data, &stored),
            Ok(true)
        );
        currency_data.put(&[0x9f, 0x42], &[0x08, 0x26]).unwrap();
        assert_eq!(
            transaction_currency_matches_application(&currency_data, &stored),
            Ok(false)
        );
        currency_data.put(&[0x9f, 0x42], &[0x08]).unwrap();
        assert_eq!(
            transaction_currency_matches_application(&currency_data, &stored).unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            fixed_slice::<2>(&[0x01]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            fixed_numeric_bcd::<2>(10_000).unwrap_err(),
            KernelError::InvalidArgument
        );

        let mut version_data = DataStore::new();
        assert_eq!(card_application_version(&version_data), Ok(None));
        version_data.put(&[0x9f, 0x08], &[0x00, 0x96]).unwrap();
        assert_eq!(
            card_application_version(&version_data),
            Ok(Some([0x00, 0x96]))
        );
        version_data.put(&[0x9f, 0x09], &[0x01]).unwrap();
        assert_eq!(
            card_application_version(&version_data).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            required_fixed::<2>(&version_data, &[0x5f, 0x28]).unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        assert_eq!(
            oda_failure_to_kernel_error(OdaFailure::MissingCapk),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            oda_failure_to_kernel_error(OdaFailure::CdaSignature),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn apdu_success_helpers_map_followup_and_failure_statuses() {
        assert_eq!(
            require_apdu_success(
                ApduContext::InternalAuthenticate,
                StatusWord::new(0x90, 0x00)
            ),
            Ok(())
        );
        assert_eq!(
            require_apdu_success(
                ApduContext::InternalAuthenticate,
                StatusWord::new(0x6a, 0x80)
            ),
            Err(KernelError::InvalidProfile)
        );
        assert_eq!(
            require_apdu_success(
                ApduContext::InternalAuthenticate,
                StatusWord::new(0x61, 0x02)
            ),
            Err(KernelError::InternalError)
        );
        assert_eq!(
            require_apdu_success(ApduContext::ReadRecord, StatusWord::new(0x6a, 0x83)),
            Err(KernelError::InternalError)
        );

        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S10;
        assert_eq!(
            require_generate_ac_success(&mut ctx, StatusWord::new(0x69, 0x85), FsmEvent::GacFailed),
            Err(KernelError::CardRemoved)
        );
        assert_eq!(ctx.fsm_state, FsmState::Se);

        let mut followup_ctx = KrnContext::new();
        assert_eq!(
            require_generate_ac_success(
                &mut followup_ctx,
                StatusWord::new(0x61, 0x02),
                FsmEvent::GacFailed,
            ),
            Err(KernelError::InternalError)
        );
    }

    #[test]
    fn context_status_helpers_cover_all_defensive_mappings() {
        assert_eq!(
            read_record_status(StatusAction::Success),
            Ok(ReadRecordStatus::Success)
        );
        assert_eq!(
            read_record_status(StatusAction::EndOfRecords),
            Ok(ReadRecordStatus::EndOfRecords)
        );
        assert_eq!(
            read_record_status(StatusAction::ContinueWithTvr {
                bit: Tvr::B1_ICC_DATA_MISSING,
            }),
            Ok(ReadRecordStatus::ContinueWithTvr {
                bit: Tvr::B1_ICC_DATA_MISSING,
            })
        );
        assert_eq!(
            read_record_status(StatusAction::Fail {
                error: KernelError::CardRemoved,
            }),
            Err(KernelError::CardRemoved)
        );
        for action in [
            StatusAction::GetResponse { length: 1 },
            StatusAction::RetryWithLe { length: 2 },
            StatusAction::FallbackToDirectAid,
            StatusAction::TryNextAid,
            StatusAction::PinFailed { tries_remaining: 1 },
            StatusAction::ContinueAfterScriptWarning,
            StatusAction::ContinueAfterNonCriticalScriptFailure,
        ] {
            assert_eq!(read_record_status(action), Err(KernelError::InternalError));
        }

        let mut tvr = Tvr::cleared();
        assert_eq!(
            issuer_authentication_event_from_status(StatusAction::Success, &mut tvr),
            Ok(FsmEvent::IssuerAuthenticationSuccess)
        );
        assert!(!tvr.is_set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED));
        assert_eq!(
            issuer_authentication_event_from_status(
                StatusAction::ContinueWithTvr {
                    bit: Tvr::B5_ISSUER_AUTHENTICATION_FAILED,
                },
                &mut tvr,
            ),
            Ok(FsmEvent::IssuerAuthenticationFailure)
        );
        assert!(tvr.is_set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED));
        assert_eq!(
            issuer_authentication_event_from_status(
                StatusAction::Fail {
                    error: KernelError::InvalidProfile,
                },
                &mut tvr,
            ),
            Err(KernelError::InvalidProfile)
        );
        for action in [
            StatusAction::GetResponse { length: 1 },
            StatusAction::RetryWithLe { length: 2 },
            StatusAction::FallbackToDirectAid,
            StatusAction::TryNextAid,
            StatusAction::EndOfRecords,
            StatusAction::PinFailed { tries_remaining: 1 },
            StatusAction::ContinueAfterScriptWarning,
            StatusAction::ContinueAfterNonCriticalScriptFailure,
        ] {
            assert_eq!(
                issuer_authentication_event_from_status(action, &mut tvr),
                Err(KernelError::InternalError)
            );
        }

        for action in [
            StatusAction::Success,
            StatusAction::ContinueAfterScriptWarning,
            StatusAction::ContinueAfterNonCriticalScriptFailure,
        ] {
            assert_eq!(
                issuer_script_status(action),
                Ok(IssuerScriptStatus::Continue)
            );
        }
        assert_eq!(
            issuer_script_status(StatusAction::Fail {
                error: KernelError::ScriptFailed,
            }),
            Ok(IssuerScriptStatus::CriticalFailure)
        );
        assert_eq!(
            issuer_script_status(StatusAction::Fail {
                error: KernelError::InvalidProfile,
            }),
            Err(KernelError::InvalidProfile)
        );
        for action in [
            StatusAction::GetResponse { length: 1 },
            StatusAction::RetryWithLe { length: 2 },
            StatusAction::FallbackToDirectAid,
            StatusAction::TryNextAid,
            StatusAction::EndOfRecords,
            StatusAction::ContinueWithTvr {
                bit: Tvr::B1_ICC_DATA_MISSING,
            },
            StatusAction::PinFailed { tries_remaining: 1 },
        ] {
            assert_eq!(
                issuer_script_status(action),
                Err(KernelError::InvalidArgument)
            );
        }
    }

    #[test]
    fn transaction_data_store_rejects_unencodable_direct_values() {
        let base = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACT,
            merchant_name_location: Vec::new(),
        };
        let date = EmvDate {
            year: 26,
            month: 5,
            day: 21,
        };
        let inputs = TerminalDolInputs::default();

        let mut too_large_amount = base.clone();
        too_large_amount.amount_authorised_minor = u64::MAX;
        assert_eq!(
            transaction_data_store(
                &too_large_amount,
                [0x11, 0x22, 0x33, 0x44],
                date,
                Tvr::cleared(),
                Tsi::cleared(),
                inputs,
            )
            .unwrap_err(),
            KernelError::InvalidArgument
        );

        let mut too_large_other_amount = base.clone();
        too_large_other_amount.amount_other_minor = u64::MAX;
        assert_eq!(
            transaction_data_store(
                &too_large_other_amount,
                [0x11, 0x22, 0x33, 0x44],
                date,
                Tvr::cleared(),
                Tsi::cleared(),
                inputs,
            )
            .unwrap_err(),
            KernelError::InvalidArgument
        );

        let mut too_large_currency = base.clone();
        too_large_currency.currency_code = 10_000;
        assert_eq!(
            transaction_data_store(
                &too_large_currency,
                [0x11, 0x22, 0x33, 0x44],
                date,
                Tvr::cleared(),
                Tsi::cleared(),
                inputs,
            )
            .unwrap_err(),
            KernelError::InvalidArgument
        );

        let mut too_large_country = base;
        too_large_country.terminal_country_code = 10_000;
        assert_eq!(
            transaction_data_store(
                &too_large_country,
                [0x11, 0x22, 0x33, 0x44],
                date,
                Tvr::cleared(),
                Tsi::cleared(),
                inputs,
            )
            .unwrap_err(),
            KernelError::InvalidArgument
        );

        let dangling_merchant = KrnTxnParams {
            struct_size: mem::size_of::<KrnTxnParams>() as u32,
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACT,
            merchant_name_location: ptr::null(),
            merchant_name_location_len: 1,
        };
        assert_eq!(
            unsafe { read_transaction_params(&dangling_merchant) }.unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn cvm_transaction_type_uses_terminal_and_transaction_tags() {
        let params = |transaction_type, terminal_type| StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type,
            terminal_type,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };

        assert_eq!(
            cvm_transaction_type(&params(0x00, 0x22)),
            CvmTransactionType::NonCash
        );
        assert_eq!(
            cvm_transaction_type(&params(0x00, 0x14)),
            CvmTransactionType::UnattendedCash
        );
        assert_eq!(
            cvm_transaction_type(&params(0x01, 0x22)),
            CvmTransactionType::ManualCash
        );
        assert_eq!(
            cvm_transaction_type(&params(0x09, 0x22)),
            CvmTransactionType::PurchaseWithCashback
        );
        assert_eq!(
            cvm_transaction_type(&params(0x17, 0x22)),
            CvmTransactionType::PurchaseWithCashback
        );
        assert_eq!(
            cvm_transaction_type(&params(0x01, 0x24)),
            CvmTransactionType::UnattendedCash
        );
    }

    #[test]
    fn cvm_processing_persists_unrecognized_tvr_on_later_success() {
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S7;
        ctx.state = KernelState::Cvm;
        ctx.card_data
            .put(&[0x8e], &[0, 0, 0, 0, 0, 0, 0, 0, 0x47, 0x00, 0x02, 0x00])
            .unwrap();
        ctx.cvm_capabilities = RuntimeCvmCapabilities {
            offline_pin_supported: false,
            online_pin_supported: true,
            signature_supported: false,
            cdcvm_performed: false,
        };
        let params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };

        assert_eq!(run_cvm_processing(&mut ctx, &params), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S8);
        assert!(ctx.tvr.is_set(Tvr::B3_UNRECOGNIZED_CVM));
        assert!(ctx.tvr.is_set(Tvr::B3_ONLINE_PIN_ENTERED));
        assert!(!ctx
            .tvr
            .is_set(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL));
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x34]),
            Some(&[0x02, 0x00, 0x02][..])
        );
        assert_eq!(
            ctx.card_data.get(&[0x95]),
            Some(&[0x00, 0x00, 0x44, 0x00, 0x00][..])
        );
    }

    #[test]
    fn offline_pin_capability_is_separate_from_ped_handle() {
        unsafe {
            let ctx = krn_context_new();
            assert!(!ctx.is_null());

            assert_eq!(
                krn_set_offline_pin_capability(ptr::null_mut(), 0),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_offline_pin_capability(ctx, 2),
                KernelError::InvalidArgument.code()
            );
            assert!(!(*ctx).cvm_capabilities.offline_pin_supported);

            assert_eq!(
                krn_set_offline_pin_capability(ctx, 1),
                KernelError::Ok.code()
            );
            assert!((*ctx).cvm_capabilities.offline_pin_supported);

            assert_eq!(
                krn_set_cvm_capabilities(ctx, 1, 0, 0),
                KernelError::Ok.code()
            );
            assert!((*ctx).cvm_capabilities.offline_pin_supported);
            assert!((*ctx).cvm_capabilities.online_pin_supported);

            krn_context_free(ctx);
        }
    }

    #[test]
    fn cvm_processing_persists_missing_pin_pad_tvr_on_later_success() {
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S7;
        ctx.state = KernelState::Cvm;
        ctx.card_data
            .put(&[0x8e], &[0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0x00, 0x02, 0x00])
            .unwrap();
        ctx.cvm_capabilities = RuntimeCvmCapabilities {
            offline_pin_supported: false,
            online_pin_supported: true,
            signature_supported: false,
            cdcvm_performed: false,
        };
        let params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };

        assert_eq!(run_cvm_processing(&mut ctx, &params), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S8);
        assert!(ctx.tvr.is_set(Tvr::B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING));
        assert!(ctx.tvr.is_set(Tvr::B3_ONLINE_PIN_ENTERED));
        assert!(!ctx
            .tvr
            .is_set(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL));
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x34]),
            Some(&[0x02, 0x00, 0x02][..])
        );
        assert_eq!(
            ctx.card_data.get(&[0x95]),
            Some(&[0x00, 0x00, 0x14, 0x00, 0x00][..])
        );
    }

    #[test]
    fn cvm_processing_persists_pin_not_entered_tvr_when_handle_missing() {
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S7;
        ctx.state = KernelState::Cvm;
        ctx.card_data
            .put(&[0x8e], &[0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0x00, 0x02, 0x00])
            .unwrap();
        ctx.cvm_capabilities = RuntimeCvmCapabilities {
            offline_pin_supported: true,
            online_pin_supported: true,
            signature_supported: false,
            cdcvm_performed: false,
        };
        let params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };

        assert_eq!(run_cvm_processing(&mut ctx, &params), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S8);
        assert!(ctx.tvr.is_set(Tvr::B3_PIN_NOT_ENTERED));
        assert!(ctx.tvr.is_set(Tvr::B3_ONLINE_PIN_ENTERED));
        assert!(!ctx.tvr.is_set(Tvr::B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING));
        assert!(!ctx
            .tvr
            .is_set(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL));
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x34]),
            Some(&[0x02, 0x00, 0x02][..])
        );
        assert_eq!(
            ctx.card_data.get(&[0x95]),
            Some(&[0x00, 0x00, 0x0c, 0x00, 0x00][..])
        );
    }

    #[test]
    fn cvm_processing_sets_pin_pad_tvr_when_online_pin_unavailable() {
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S7;
        ctx.state = KernelState::Cvm;
        ctx.card_data
            .put(&[0x8e], &[0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00])
            .unwrap();
        ctx.cvm_capabilities = RuntimeCvmCapabilities {
            offline_pin_supported: false,
            online_pin_supported: false,
            signature_supported: false,
            cdcvm_performed: false,
        };
        let params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };

        assert_eq!(run_cvm_processing(&mut ctx, &params), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S8);
        assert!(ctx.tvr.is_set(Tvr::B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING));
        assert!(!ctx.tvr.is_set(Tvr::B3_ONLINE_PIN_ENTERED));
        assert!(!ctx
            .tvr
            .is_set(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL));
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x34]),
            Some(&[0x02, 0x00, 0x01][..])
        );
        assert_eq!(
            ctx.card_data.get(&[0x95]),
            Some(&[0x00, 0x00, 0x10, 0x00, 0x00][..])
        );
    }

    #[test]
    fn offline_taa_and_first_gac_results_finish_with_real_outcomes() {
        let mut ctx = KrnContext::new();
        ctx.requested_cryptogram = Some(CryptogramRequest::Tc);
        assert_eq!(
            finish_offline_outcome_from_taa(&mut ctx),
            Ok(KrnOutcome::ApprovedOffline)
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::ApprovedOffline));
        assert_eq!(ctx.last_error, KernelError::Ok);

        ctx.requested_cryptogram = Some(CryptogramRequest::Aac);
        assert_eq!(
            finish_offline_outcome_from_taa(&mut ctx),
            Ok(KrnOutcome::DeclinedOffline)
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::DeclinedOffline));

        ctx.first_gac_response = Some(GenerateAcResponse {
            cid: crate::cid::Cid::new(0x40),
            atc: [0x00, 0x01],
            application_cryptogram: [0x11; 8],
            issuer_application_data: Vec::new(),
            icc_dynamic_number: None,
            signed_dynamic_application_data: None,
        });
        assert_eq!(
            finish_offline_outcome_from_first_gac(&mut ctx),
            Ok(KrnOutcome::ApprovedOffline)
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::ApprovedOffline));

        ctx.first_gac_response.as_mut().unwrap().cid = crate::cid::Cid::new(0x00);
        assert_eq!(
            finish_offline_outcome_from_first_gac(&mut ctx),
            Ok(KrnOutcome::DeclinedOffline)
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::DeclinedOffline));
    }

    #[test]
    fn offline_outcome_helpers_reject_incomplete_or_online_only_state() {
        let mut ctx = KrnContext::new();
        assert_eq!(
            finish_offline_outcome_from_taa(&mut ctx).unwrap_err(),
            KernelError::InvalidArgument
        );
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        assert_eq!(
            finish_offline_outcome_from_taa(&mut ctx).unwrap_err(),
            KernelError::InvalidArgument
        );

        let mut first_gac_ctx = KrnContext::new();
        assert_eq!(
            finish_offline_outcome_from_first_gac(&mut first_gac_ctx).unwrap_err(),
            KernelError::InvalidArgument
        );
        first_gac_ctx.first_gac_response = Some(GenerateAcResponse {
            cid: crate::cid::Cid::new(0x80),
            atc: [0x00, 0x01],
            application_cryptogram: [0x11; 8],
            issuer_application_data: Vec::new(),
            icc_dynamic_number: None,
            signed_dynamic_application_data: None,
        });
        assert_eq!(
            finish_offline_outcome_from_first_gac(&mut first_gac_ctx).unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn taa_offline_final_state_finishes_from_s16() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S9;
        ctx.state = KernelState::TerminalActionAnalysis;
        ctx.tvr.set(Tvr::B1_SDA_FAILED);
        ctx.card_data
            .put(&[0x9f, 0x0e], &[0x40, 0x00, 0x00, 0x00, 0x00])
            .unwrap();

        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(run_terminal_action_analysis(&mut ctx, &profiles), Ok(()));
        assert!(is_final_outcome_state(&ctx));
        assert_eq!(ctx.fsm_state, FsmState::S16);
        assert_eq!(ctx.requested_cryptogram, Some(CryptogramRequest::Aac));
        assert_eq!(
            finish_offline_outcome_from_taa(&mut ctx),
            Ok(KrnOutcome::DeclinedOffline)
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::DeclinedOffline));
    }

    #[test]
    fn taa_uses_profile_iac_fallbacks_when_card_omits_iacs() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S9;
        ctx.state = KernelState::TerminalActionAnalysis;
        ctx.tvr.set(Tvr::B4_FLOOR_LIMIT_EXCEEDED);
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0]
            .issuer_action_codes
            .online = [0, 0, 0, 0x80, 0];

        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(run_terminal_action_analysis(&mut ctx, &profiles), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S10);
        assert_eq!(ctx.requested_cryptogram, Some(CryptogramRequest::Arqc));
    }

    #[test]
    fn trm_random_selection_sample_drives_online_handoff() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S8;
        ctx.state = KernelState::TerminalRiskManagement;
        ctx.txn_params = Some(StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        });
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].floor_limit = 9_999;
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].random_selection_percent = 5;
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0]
            .issuer_action_codes
            .online = [0, 0, 0, 0x10, 0];

        unsafe {
            assert_eq!(
                krn_set_trm_random_selection_sample(ptr::null_mut(), 499),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_trm_random_selection_sample(&mut ctx, 10_000),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_set_trm_random_selection_sample(&mut ctx, 499),
                KernelError::Ok.code()
            );
        }

        let profiles = ctx.profiles.clone().unwrap();
        let params = ctx.txn_params.clone().unwrap();
        assert_eq!(
            run_terminal_risk_management(&mut ctx, &profiles, &params),
            Ok(())
        );
        assert!(ctx
            .tvr
            .is_set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED));
        assert!(!ctx.tvr.is_set(Tvr::B4_FLOOR_LIMIT_EXCEEDED));
        assert_eq!(ctx.fsm_state, FsmState::S9);
        assert_eq!(ctx.state, KernelState::TerminalActionAnalysis);

        assert_eq!(run_terminal_action_analysis(&mut ctx, &profiles), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S10);
        assert_eq!(ctx.requested_cryptogram, Some(CryptogramRequest::Arqc));
    }

    #[test]
    fn trm_random_selection_requires_sample_when_profile_enables_it() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S8;
        ctx.state = KernelState::TerminalRiskManagement;
        ctx.txn_params = Some(StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        });
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].floor_limit = 9_999;
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].random_selection_percent = 5;

        let profiles = ctx.profiles.clone().unwrap();
        let params = ctx.txn_params.clone().unwrap();
        assert_eq!(
            run_terminal_risk_management(&mut ctx, &profiles, &params).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert!(!ctx
            .tvr
            .is_set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED));
        assert!(!ctx.tsi.is_set(Tsi::TERMINAL_RISK_MANAGEMENT_PERFORMED));
    }

    #[test]
    fn taa_uses_terminal_type_online_capability() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S9;
        ctx.state = KernelState::TerminalActionAnalysis;
        ctx.txn_params = Some(StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x23,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        });
        ctx.tvr.set(Tvr::B4_FLOOR_LIMIT_EXCEEDED);
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0]
            .issuer_action_codes
            .online = [0, 0, 0, 0x80, 0];
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0]
            .issuer_action_codes
            .default = [0, 0, 0, 0x80, 0];

        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(run_terminal_action_analysis(&mut ctx, &profiles), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S16);
        assert_eq!(ctx.requested_cryptogram, Some(CryptogramRequest::Aac));
    }

    #[test]
    fn card_iac_tags_override_profile_fallbacks() {
        let mut data = DataStore::new();
        let profile_fallback = ActionCodes {
            denial: [0x40, 0, 0, 0, 0],
            online: [0, 0, 0, 0x80, 0],
            default: [0x20, 0, 0, 0, 0],
        };

        assert_eq!(
            issuer_action_codes(&data, profile_fallback).unwrap(),
            profile_fallback
        );

        data.put(&[0x9f, 0x0e], &[0, 0, 0, 0, 0]).unwrap();
        let iac = issuer_action_codes(&data, profile_fallback).unwrap();
        assert_eq!(iac.denial, [0, 0, 0, 0, 0]);
        assert_eq!(iac.online, profile_fallback.online);
        assert_eq!(iac.default, profile_fallback.default);
    }

    fn install_sda_success_fixture(ctx: &mut KrnContext) {
        install_profile_selection(ctx);
        let capk_modulus = hex_bytes(
            "95FDEDCBA9876FEDCBA9876FCFEDFEFDFCFEFECFFC4FBD7F983A7659F2245302\
             20AA7B861F2489891E003143C4C4AA9A82A3B1A8154D2AA6D553D0678981F7\
             CD3B8CDFF9DE1A48FBB77C847D775F61CBF435FFDF53EF50F9DB45",
        );
        let capk_exponent = vec![0x03];
        let source = ctx.profiles.as_ref().unwrap().schemes[0].capks[0]
            .source
            .clone();
        let mut capk = crate::config::Capk {
            rid: [0xa0, 0x00, 0x00, 0x00, 0x03],
            key_index: 0x42,
            modulus: capk_modulus,
            exponent: capk_exponent,
            expiry: EmvDate {
                year: 30,
                month: 12,
                day: 31,
            },
            checksum: Vec::new(),
            source,
        };
        capk.checksum = crate::oda::capk_checksum(&capk).to_vec();
        ctx.profiles.as_mut().unwrap().schemes[0].capks = vec![capk];
        ctx.selected_application.as_mut().unwrap().aip = Some([0x80, 0x00]);
        ctx.card_data.put(&[0x8f], &[0x42]).unwrap();
        ctx.card_data
            .put(
                &[0x90],
                &hex_bytes(
                    "000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000001\
                     000000000000000000000000000000000000000000000000000000000001",
                ),
            )
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x32], &[0x01, 0x00, 0x01])
            .unwrap();
        ctx.card_data
            .put(
                &[0x93],
                &hex_bytes(
                    "6D492A5DB481273D1127EF24D1059B5702AED358BB75A3AD004766DD75157DE9\
                     9A517A830517EB821D22CD55E0FF2AE4",
                ),
            )
            .unwrap();
        ctx.card_data.put(&[0x9f, 0x4a], &[0x82]).unwrap();
        ctx.card_data.put(&[0x82], &[0xcc]).unwrap();
        ctx.offline_auth_records = vec![
            StaticAuthenticationRecord {
                sfi: 11,
                record: 1,
                body: vec![0xaa],
            },
            StaticAuthenticationRecord {
                sfi: 12,
                record: 1,
                body: vec![0xbb],
            },
        ];
    }

    fn install_dda_success_fixture(ctx: &mut KrnContext) {
        install_profile_selection(ctx);
        let capk_modulus = hex_bytes(
            "95FDEDCBA9876FEDCBA9876FCFEDFEFDFCFEFEA5FE6A041234567890123456\
             7890301201020301013003B709C0C6940601638B89144AEC5D8C229DA65024\
             129CD31CE56F75F4FEC42EC9921572260452E932BDC7672863C1AA53DD5228\
             58276E86F173FE37F8EDDBD5211A23A396BAD38403E98245C5DCC31603A55\
             FB74AD2289131E845",
        );
        let source = ctx.profiles.as_ref().unwrap().schemes[0].capks[0]
            .source
            .clone();
        let mut capk = crate::config::Capk {
            rid: [0xa0, 0x00, 0x00, 0x00, 0x03],
            key_index: 0x43,
            modulus: capk_modulus,
            exponent: vec![0x03],
            expiry: EmvDate {
                year: 30,
                month: 12,
                day: 31,
            },
            checksum: Vec::new(),
            source,
        };
        capk.checksum = crate::oda::capk_checksum(&capk).to_vec();
        ctx.profiles.as_mut().unwrap().schemes[0].capks = vec![capk];
        ctx.selected_application.as_mut().unwrap().aip = Some([0x40, 0x00]);
        ctx.card_data.put(&[0x8f], &[0x43]).unwrap();
        ctx.card_data
            .put(
                &[0x90],
                &hex_bytes(
                    "000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000010000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000001",
                ),
            )
            .unwrap();
        ctx.card_data.put(&[0x9f, 0x32], &[0x03]).unwrap();
        ctx.card_data
            .put(
                &[0x9f, 0x46],
                &hex_bytes(
                    "000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000001\
                     000000000000000000000000000000000000000000000000000000000001",
                ),
            )
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x47], &[0x01, 0x00, 0x01])
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x49], &[0x9f, 0x37, 0x04])
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x37], &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
    }

    fn install_cda_success_fixture(ctx: &mut KrnContext) {
        install_profile_selection(ctx);
        let capk_modulus = hex_bytes(
            "95FDEDCBA9876FEDCBA9876FCFEDFEFDFCFEFEA5FE6A041234567890123456\
             789030120102030101300195FDFEFBFEFDFCFB414444444444444744444444\
             444444444444443417CD6B0415F87CE74BFC886E3D1ABEB65E16CB455FF98\
             79C8FB364A8E30DD765A5614D8848519095BA4A882A0960A480FB002521E4\
             3B0DC5EAE0A5ED3745",
        );
        let source = ctx.profiles.as_ref().unwrap().schemes[0].capks[0]
            .source
            .clone();
        let mut capk = crate::config::Capk {
            rid: [0xa0, 0x00, 0x00, 0x00, 0x03],
            key_index: 0x44,
            modulus: capk_modulus,
            exponent: vec![0x03],
            expiry: EmvDate {
                year: 30,
                month: 12,
                day: 31,
            },
            checksum: Vec::new(),
            source,
        };
        capk.checksum = crate::oda::capk_checksum(&capk).to_vec();
        ctx.profiles.as_mut().unwrap().schemes[0].capks = vec![capk];
        ctx.selected_application.as_mut().unwrap().aip = Some([0x00, 0x80]);
        ctx.card_data.put(&[0x8f], &[0x44]).unwrap();
        ctx.card_data
            .put(
                &[0x90],
                &hex_bytes(
                    "000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000010000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000001",
                ),
            )
            .unwrap();
        ctx.card_data.put(&[0x9f, 0x32], &[0x03]).unwrap();
        ctx.card_data
            .put(
                &[0x9f, 0x46],
                &hex_bytes(
                    "000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000001\
                     000000000000000000000000000000000000000000000000000000000001",
                ),
            )
            .unwrap();
        ctx.card_data.put(&[0x9f, 0x47], &[0x03]).unwrap();
        ctx.card_data.put(&[0x8c], &[0x9f, 0x37, 0x04]).unwrap();
        ctx.card_data
            .put(&[0x9f, 0x37], &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
    }

    fn hex_bytes(input: &str) -> Vec<u8> {
        let filtered: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
        assert_eq!(filtered.len() % 2, 0);
        filtered
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn runtime_oda_covers_selection_and_certificate_failure_edges() {
        let mut not_required = KrnContext::new();
        install_profile_selection(&mut not_required);
        not_required.selected_application.as_mut().unwrap().aip = Some([0x00, 0x00]);
        not_required.fsm_state = FsmState::S5;
        not_required.state = KernelState::OfflineDataAuthentication;
        let profiles = not_required.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut not_required, &profiles, None),
            Ok(())
        );
        assert_eq!(not_required.selected_oda_method, None);
        assert_eq!(not_required.fsm_state, FsmState::S6);
        assert_eq!(not_required.state, KernelState::ProcessingRestrictions);

        let mut not_performed_required = KrnContext::new();
        install_profile_selection(&mut not_performed_required);
        not_performed_required
            .selected_application
            .as_mut()
            .unwrap()
            .aip = Some([0x00, 0x80]);
        not_performed_required.profiles.as_mut().unwrap().schemes[0].aids[0].cda_supported = false;
        not_performed_required.fsm_state = FsmState::S5;
        not_performed_required.state = KernelState::OfflineDataAuthentication;
        let profiles = not_performed_required.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut not_performed_required, &profiles, None),
            Ok(())
        );
        assert_eq!(not_performed_required.selected_oda_method, None);
        assert!(not_performed_required
            .tvr
            .is_set(Tvr::B1_OFFLINE_DATA_AUTH_NOT_PERFORMED));
        assert_eq!(not_performed_required.fsm_state, FsmState::S6);

        let mut missing_capk = KrnContext::new();
        install_sda_success_fixture(&mut missing_capk);
        missing_capk.card_data.put(&[0x8f], &[0xfe]).unwrap();
        let profiles = missing_capk.profiles.clone().unwrap();
        let scheme = &profiles.schemes[0];
        assert_eq!(
            oda_outcome_for_method(
                OdaMethod::Sda,
                OdaEvaluationContext {
                    profiles: &profiles,
                    rid: &scheme.rid,
                    evaluation_date: missing_capk.profile_evaluation_date.unwrap(),
                    card_data: &missing_capk.card_data,
                    offline_auth_records: &missing_capk.offline_auth_records,
                    runtime: None,
                    apdu_timeout_ms: apdu_timeout(&missing_capk),
                },
            ),
            OdaOutcome::Failed {
                method: OdaMethod::Sda,
                failure: OdaFailure::MissingCapk,
            }
        );

        let mut bad_sda_issuer_certificate = KrnContext::new();
        install_sda_success_fixture(&mut bad_sda_issuer_certificate);
        bad_sda_issuer_certificate
            .card_data
            .put(&[0x90], &[0x00])
            .unwrap();
        let profiles = bad_sda_issuer_certificate.profiles.clone().unwrap();
        let scheme = &profiles.schemes[0];
        assert_eq!(
            oda_outcome_for_method(
                OdaMethod::Sda,
                OdaEvaluationContext {
                    profiles: &profiles,
                    rid: &scheme.rid,
                    evaluation_date: bad_sda_issuer_certificate.profile_evaluation_date.unwrap(),
                    card_data: &bad_sda_issuer_certificate.card_data,
                    offline_auth_records: &bad_sda_issuer_certificate.offline_auth_records,
                    runtime: None,
                    apdu_timeout_ms: apdu_timeout(&bad_sda_issuer_certificate),
                },
            ),
            OdaOutcome::Failed {
                method: OdaMethod::Sda,
                failure: OdaFailure::IssuerCertificateRecovery,
            }
        );

        let mut dda_without_runtime = KrnContext::new();
        install_dda_success_fixture(&mut dda_without_runtime);
        let profiles = dda_without_runtime.profiles.clone().unwrap();
        let scheme = &profiles.schemes[0];
        assert_eq!(
            oda_outcome_for_method(
                OdaMethod::Dda,
                OdaEvaluationContext {
                    profiles: &profiles,
                    rid: &scheme.rid,
                    evaluation_date: dda_without_runtime.profile_evaluation_date.unwrap(),
                    card_data: &dda_without_runtime.card_data,
                    offline_auth_records: &dda_without_runtime.offline_auth_records,
                    runtime: None,
                    apdu_timeout_ms: apdu_timeout(&dda_without_runtime),
                },
            ),
            OdaOutcome::Failed {
                method: OdaMethod::Dda,
                failure: OdaFailure::DynamicSignature,
            }
        );

        let mut bad_cda_icc_certificate = KrnContext::new();
        install_cda_success_fixture(&mut bad_cda_icc_certificate);
        bad_cda_icc_certificate
            .card_data
            .put(&[0x9f, 0x46], &[0x00])
            .unwrap();
        let profiles = bad_cda_icc_certificate.profiles.clone().unwrap();
        let scheme = &profiles.schemes[0];
        assert_eq!(
            oda_outcome_for_method(
                OdaMethod::Cda,
                OdaEvaluationContext {
                    profiles: &profiles,
                    rid: &scheme.rid,
                    evaluation_date: bad_cda_icc_certificate.profile_evaluation_date.unwrap(),
                    card_data: &bad_cda_icc_certificate.card_data,
                    offline_auth_records: &bad_cda_icc_certificate.offline_auth_records,
                    runtime: None,
                    apdu_timeout_ms: apdu_timeout(&bad_cda_icc_certificate),
                },
            ),
            OdaOutcome::Failed {
                method: OdaMethod::Cda,
                failure: OdaFailure::IccCertificateRecovery,
            }
        );
    }

    #[test]
    fn runtime_oda_executes_sda_signature_success() {
        let mut ctx = KrnContext::new();
        install_sda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;

        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Sda));
        assert_eq!(ctx.fsm_state, FsmState::S6);
        assert_eq!(ctx.state, KernelState::ProcessingRestrictions);
        assert!(ctx.tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
        assert!(!ctx.tvr.is_set(Tvr::B1_SDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    }

    #[test]
    fn runtime_oda_maps_bad_sda_signature_to_tvr_failure() {
        let mut ctx = KrnContext::new();
        install_sda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        ctx.card_data.put(&[0x82], &[0xdd]).unwrap();

        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Sda));
        assert_eq!(ctx.fsm_state, FsmState::S6);
        assert!(ctx.tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
        assert!(ctx.tvr.is_set(Tvr::B1_SDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    }

    unsafe extern "C" fn capture_internal_authenticate_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let mut signed_dynamic_data = hex_bytes(
            "A826FBA6E8D7C0548D2E05551AFEEE0512C8AB02F33055BC389BECD93026B69F\
             B5ED72B750BE23C27E932C963F820550",
        );
        if DDA_RESPONSE_MODE.load(Ordering::SeqCst) == 1 {
            let last = signed_dynamic_data.last_mut().unwrap();
            *last ^= 0x01;
        }
        let mut response = Vec::with_capacity(64);
        response.extend_from_slice(&[0x77, 0x3a, 0x9f, 0x4b, 0x30]);
        response.extend_from_slice(&signed_dynamic_data);
        response.extend_from_slice(&[0x9f, 0x4c, 0x04, 0x01, 0x02, 0x03, 0x04, 0x90, 0x00]);
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    #[test]
    fn runtime_oda_executes_dda_internal_authenticate_success() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_dda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_internal_authenticate_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, Some(runtime)),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Dda));
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0x88);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 10);
        assert_eq!(
            TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst),
            APDU_TRANSMIT_TIMEOUT_MS
        );
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x00, 0x88, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00]
        );
        assert_eq!(ctx.fsm_state, FsmState::S6);
        assert!(ctx.tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
        assert!(!ctx.tvr.is_set(Tvr::B1_DDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    }

    #[test]
    fn runtime_oda_maps_bad_dda_signature_to_tvr_failure() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_dda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_internal_authenticate_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        DDA_RESPONSE_MODE.store(1, Ordering::SeqCst);
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, Some(runtime)),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Dda));
        assert_eq!(ctx.fsm_state, FsmState::S6);
        assert!(ctx.tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
        assert!(ctx.tvr.is_set(Tvr::B1_DDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
        DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
    }

    fn cda_generate_ac_response_with_icc_dynamic_number(
        cid: u8,
        icc_dynamic_number: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut sdad = hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000001\
             00000000000000000000000000000001",
        );
        if DDA_RESPONSE_MODE.load(Ordering::SeqCst) == 1 {
            let last = sdad.last_mut().unwrap();
            *last ^= 0x01;
        }
        let mut children = Vec::with_capacity(78);
        children.extend_from_slice(&[
            0x9f, 0x27, 0x01, cid, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x9f, 0x4b, 0x30,
        ]);
        children.extend_from_slice(&sdad);
        if let Some(dynamic_number) = icc_dynamic_number {
            children.extend_from_slice(&[0x9f, 0x4c]);
            children.push(u8::try_from(dynamic_number.len()).unwrap());
            children.extend_from_slice(dynamic_number);
        }
        let mut response = Vec::with_capacity(children.len() + 4);
        response.extend_from_slice(&[0x77, u8::try_from(children.len()).unwrap()]);
        response.extend_from_slice(&children);
        response.extend_from_slice(&[0x90, 0x00]);
        response
    }

    fn cda_generate_ac_response(cid: u8) -> Vec<u8> {
        cda_generate_ac_response_with_icc_dynamic_number(cid, Some(&[0x01, 0x02, 0x03, 0x04]))
    }

    unsafe extern "C" fn capture_cda_generate_ac_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = cda_generate_ac_response(0x80);
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_cda_generate_ac_apdu_without_9f4c(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = cda_generate_ac_response_with_icc_dynamic_number(0x80, None);
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_cda_tc_generate_ac_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = cda_generate_ac_response(0x40);
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_cda_aac_generate_ac_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = cda_generate_ac_response(0x00);
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_cda_referral_generate_ac_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = cda_generate_ac_response(0xc0);
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_short_apdu_response(
        _cmd: *const u8,
        _cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        _timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let response = [0x70];
        *resp_len = response.len();
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn capture_cda_format_1_generate_ac_without_sdad(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = [
            0x80, 0x0b, 0x80, 0x00, 0x09, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x90,
            0x00,
        ];
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    #[test]
    fn runtime_cda_verifies_first_gac_signed_dynamic_data() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_cda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Cda));
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(ctx.fsm_state, FsmState::S11);
        assert!(!ctx.tvr.is_set(Tvr::B1_CDA_FAILED));
        assert!(ctx.first_gac_response.is_some());
        assert!(ctx.card_data.get(&[0x9f, 0x4b]).is_some());
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x26]),
            Some(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88][..])
        );
    }

    #[test]
    fn runtime_cda_profile_required_9f4c_sets_tvr_when_absent() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_cda_success_fixture(&mut ctx);
        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].cda_authentication_data =
            CdaAuthenticationData::ApplicationCryptogramAndIccDynamicNumber;
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Cda));
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu_without_9f4c,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert!(ctx.tvr.is_set(Tvr::B1_CDA_FAILED));
        assert_eq!(ctx.card_data.get(&[0x9f, 0x4c]), None);
        assert_eq!(ctx.fsm_state, FsmState::S11);
        assert_eq!(ctx.state, KernelState::OnlineAuthorization);
    }

    #[test]
    fn first_gac_uses_profile_default_cdol1_when_card_omits_8c() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        assert!(ctx.card_data.get(&[0x8c]).is_none());
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        ctx.card_data
            .put(&[0x9f, 0x37], &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x02], &[0x00, 0x00, 0x00, 0x00, 0x10, 0x00])
            .unwrap();
        ctx.card_data.put(&[0x9a], &[0x26, 0x05, 0x21]).unwrap();
        ctx.card_data.put(&[0x9c], &[0x00]).unwrap();
        ctx.card_data.put(&[0x9f, 0x1a], &[0x08, 0x40]).unwrap();
        ctx.card_data
            .put(&[0x9f, 0x34], &[0x01, 0x00, 0x02])
            .unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));

        let command = LAST_TRANSMITTED_COMMAND.lock().unwrap().clone();
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(&command[..5], &[0x80, 0xae, 0x80, 0x00, 0x18]);
        assert_eq!(
            &command[5..29],
            &hex_bytes("112233440000000000000000001000260521000840010002")
        );
        assert_eq!(command[29], 0x00);

        let mut missing_default = KrnContext::new();
        install_profile_selection(&mut missing_default);
        missing_default.profiles.as_mut().unwrap().schemes[0].aids[0].default_cdol1 = None;
        missing_default.requested_cryptogram = Some(CryptogramRequest::Arqc);
        assert_eq!(
            cdol1_definition_for_first_gac(&missing_default),
            Err(KernelError::MissingMandatoryTag)
        );
    }

    #[test]
    fn first_gac_rejects_missing_cdol1_source_without_zero_padding() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        ctx.card_data
            .put(&[0x8c], &[0x9f, 0x37, 0x04, 0x9f, 0x34, 0x03])
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x37], &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(
            run_first_generate_ac(&mut ctx, runtime),
            Err(KernelError::MissingMandatoryTag)
        );
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn first_gac_preserves_terminal_dol_sources_after_rejected_record_tags() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let params = StoredTxnParams {
            amount_authorised_minor: 2_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };
        ctx.card_data = transaction_data_store(
            &params,
            [0x11, 0x22, 0x33, 0x44],
            EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
            Tvr::cleared(),
            Tsi::cleared(),
            TerminalDolInputs {
                terminal_capabilities: Some(
                    TerminalCapabilities::parse(&[0xe0, 0xb0, 0xc8]).unwrap(),
                ),
                additional_terminal_capabilities: Some(
                    AdditionalTerminalCapabilities::parse(&[0x70, 0x80, 0xf0, 0xf0, 0xff]).unwrap(),
                ),
                terminal_transaction_qualifiers: Some(
                    TerminalTransactionQualifiers::parse(&[0x36, 0x00, 0x40, 0x00]).unwrap(),
                ),
            },
        )
        .unwrap();
        let record_with_card_and_terminal_data = [
            0x70, 0x0c, 0x5a, 0x01, 0x12, 0x9f, 0x02, 0x06, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        ];
        assert_eq!(
            parse_read_record_body(&record_with_card_and_terminal_data, &mut ctx.card_data)
                .unwrap_err(),
            KernelError::ParseError
        );
        assert!(ctx.card_data.get(&[0x5a]).is_none());
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x02]),
            Some(&[0x00, 0x00, 0x00, 0x00, 0x20, 0x00][..])
        );
        ctx.card_data
            .put(
                &[0x8c],
                &[
                    0x9f, 0x02, 0x06, 0x9f, 0x37, 0x04, 0x95, 0x05, 0x9a, 0x03, 0x9c, 0x01, 0x9f,
                    0x1a, 0x02, 0x9f, 0x34, 0x03,
                ],
            )
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x34], &[0x01, 0x00, 0x02])
            .unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));

        let command = LAST_TRANSMITTED_COMMAND.lock().unwrap().clone();
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(&command[..5], &[0x80, 0xae, 0x80, 0x00, 0x18]);
        assert_eq!(
            &command[5..29],
            &hex_bytes("000000002000112233440000000000260521000840010002")
        );
        assert_eq!(command[29], 0x00);
    }

    #[test]
    fn first_gac_preserves_generated_unpredictable_number_after_rejected_record_tags() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let params = StoredTxnParams {
            amount_authorised_minor: 2_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0x00,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 1,
            merchant_name_location: Vec::new(),
        };
        ctx.card_data = transaction_data_store(
            &params,
            [0xaa, 0xbb, 0xcc, 0xdd],
            EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
            Tvr::cleared(),
            Tsi::cleared(),
            TerminalDolInputs::default(),
        )
        .unwrap();
        let record_with_card_and_un = [
            0x70, 0x0a, 0x5a, 0x01, 0x12, 0x9f, 0x37, 0x04, 0x99, 0x99, 0x99, 0x99,
        ];
        assert_eq!(
            parse_read_record_body(&record_with_card_and_un, &mut ctx.card_data).unwrap_err(),
            KernelError::ParseError
        );
        assert!(ctx.card_data.get(&[0x5a]).is_none());
        assert_eq!(
            ctx.card_data.get(&[0x9f, 0x37]),
            Some(&[0xaa, 0xbb, 0xcc, 0xdd][..])
        );
        ctx.card_data
            .put(&[0x8c], &[0x9f, 0x37, 0x04, 0x9f, 0x02, 0x06])
            .unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));

        let command = LAST_TRANSMITTED_COMMAND.lock().unwrap().clone();
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(&command[..5], &[0x80, 0xae, 0x80, 0x00, 0x0a]);
        assert_eq!(&command[5..15], &hex_bytes("aabbccdd000000002000"));
        assert_eq!(command[15], 0x00);
    }

    #[test]
    fn runtime_cda_failure_sets_tvr_without_falling_back_to_dda() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_cda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Cda));
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        DDA_RESPONSE_MODE.store(1, Ordering::SeqCst);
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Cda));
        assert_eq!(ctx.fsm_state, FsmState::S11);
        assert!(ctx.tvr.is_set(Tvr::B1_CDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_DDA_FAILED));
        DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn runtime_cda_failed_offline_cryptogram_reroutes_through_taa() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_cda_success_fixture(&mut ctx);
        ctx.card_data
            .put(&[0x9f, 0x0e], &[0x04, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Cda));
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_tc_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        DDA_RESPONSE_MODE.store(1, Ordering::SeqCst);
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));
        assert!(ctx.tvr.is_set(Tvr::B1_CDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_DDA_FAILED));
        assert_eq!(ctx.fsm_state, FsmState::S16);
        assert_eq!(ctx.state, KernelState::FinalOutcome);
        assert_eq!(ctx.requested_cryptogram, Some(CryptogramRequest::Aac));
        assert_eq!(
            finish_offline_outcome_from_taa(&mut ctx),
            Ok(KrnOutcome::DeclinedOffline)
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::DeclinedOffline));
        assert!(ctx
            .first_gac_response
            .as_ref()
            .is_some_and(|response| response.cid.cryptogram_type() == CryptogramType::Tc));
        DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn runtime_cda_missing_signed_dynamic_data_sets_tvr_for_online_handoff() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_cda_success_fixture(&mut ctx);
        ctx.fsm_state = FsmState::S5;
        ctx.state = KernelState::OfflineDataAuthentication;
        let profiles = ctx.profiles.clone().unwrap();
        assert_eq!(
            run_offline_data_authentication(&mut ctx, &profiles, None),
            Ok(())
        );
        assert_eq!(ctx.selected_oda_method, Some(OdaMethod::Cda));
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(CryptogramRequest::Arqc);
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_format_1_generate_ac_without_sdad,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));

        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(ctx.fsm_state, FsmState::S11);
        assert!(ctx.tvr.is_set(Tvr::B1_CDA_FAILED));
        assert!(!ctx.tvr.is_set(Tvr::B1_DDA_FAILED));
        assert!(ctx.card_data.get(&[0x9f, 0x4b]).is_none());
        assert!(ctx
            .first_gac_response
            .as_ref()
            .is_some_and(|response| response.signed_dynamic_application_data.is_none()));
        let online = ctx.online_authorization_data.as_ref().unwrap();
        assert!(online
            .windows(7)
            .any(|window| window == [0x95, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00]));
    }

    fn prepare_basic_first_gac_context(ctx: &mut KrnContext, request: CryptogramRequest) {
        install_profile_selection(ctx);
        ctx.fsm_state = FsmState::S10;
        ctx.state = KernelState::FirstGenerateAc;
        ctx.requested_cryptogram = Some(request);
        ctx.card_data
            .put(&[0x9f, 0x37], &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        ctx.card_data
            .put(&[0x9f, 0x02], &[0x00, 0x00, 0x00, 0x00, 0x10, 0x00])
            .unwrap();
        ctx.card_data.put(&[0x9a], &[0x26, 0x05, 0x21]).unwrap();
        ctx.card_data.put(&[0x9c], &[0x00]).unwrap();
        ctx.card_data.put(&[0x9f, 0x1a], &[0x08, 0x40]).unwrap();
        ctx.card_data
            .put(&[0x9f, 0x34], &[0x01, 0x00, 0x02])
            .unwrap();
    }

    #[test]
    fn first_gac_handles_offline_cryptograms_referrals_and_short_responses() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        for (request, callback, expected_event) in [
            (
                CryptogramRequest::Tc,
                capture_cda_tc_generate_ac_apdu as KrnTransmitApduCallback,
                FsmState::S16,
            ),
            (
                CryptogramRequest::Aac,
                capture_cda_aac_generate_ac_apdu as KrnTransmitApduCallback,
                FsmState::S16,
            ),
        ] {
            let mut ctx = KrnContext::new();
            prepare_basic_first_gac_context(&mut ctx, request);
            let runtime = RuntimeCallbacks {
                transmit_apdu: callback,
                get_unpredictable_number: fill_unpredictable_number,
                contactless_outcome: None,
                user_data: ptr::null_mut(),
            };

            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_eq!(run_first_generate_ac(&mut ctx, runtime), Ok(()));
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
            assert_eq!(ctx.fsm_state, expected_event);
            assert_eq!(ctx.state, KernelState::FinalOutcome);
            assert_eq!(ctx.online_authorization_data, None);
            assert!(ctx.first_gac_response.is_some());
        }

        let mut referral_ctx = KrnContext::new();
        prepare_basic_first_gac_context(&mut referral_ctx, CryptogramRequest::Arqc);
        let referral_runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_referral_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            run_first_generate_ac(&mut referral_ctx, referral_runtime),
            Err(KernelError::InvalidArgument)
        );

        let mut short_ctx = KrnContext::new();
        prepare_basic_first_gac_context(&mut short_ctx, CryptogramRequest::Arqc);
        let short_runtime = RuntimeCallbacks {
            transmit_apdu: capture_short_apdu_response,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            run_first_generate_ac(&mut short_ctx, short_runtime),
            Err(KernelError::ParseError)
        );
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
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = match count {
            0 => vec![
                0x6f, 0x13, 0xa5, 0x11, 0xbf, 0x0c, 0x0e, 0x61, 0x0c, 0x4f, 0x07, 0xa0, 0x00, 0x00,
                0x00, 0x03, 0x10, 0x10, 0x87, 0x01, 0x01, 0x90, 0x00,
            ],
            1 => selected_fci_response(&[0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]),
            2 => gpo_aip_afl_response(),
            3 => application_record_response(),
            4 => first_gac_arqc_response(),
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

    unsafe extern "C" fn capture_selection_status_policy_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        let script = &*(user_data as *const SelectionStatusPolicyScript);
        let count = script.counter.fetch_add(1, Ordering::SeqCst);
        script.commands.lock().unwrap().push(command.to_vec());
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);

        let response = match script.mode {
            1 => match count {
                0 => vec![0x61, 0x17],
                1 => pse_directory_response(),
                2 => selected_fci_response(&[0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]),
                3 => gpo_aip_afl_response(),
                4 => application_record_response(),
                5 => first_gac_arqc_response(),
                _ => vec![0x6a, 0x80],
            },
            2 => match count {
                0 => vec![0x62, 0x83],
                1 => vec![0x62, 0x83],
                2 => selected_fci_response(&[0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]),
                3 => gpo_aip_afl_response(),
                4 => application_record_response(),
                5 => first_gac_arqc_response(),
                _ => vec![0x6a, 0x80],
            },
            3 => match count {
                0 => pse_directory_response(),
                1 => selected_fci_response(&[0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]),
                2 => vec![0x61, (gpo_aip_afl_response().len() - 2) as u8],
                3 => gpo_aip_afl_response(),
                4 => vec![0x61, (application_record_response().len() - 2) as u8],
                5 => application_record_response(),
                6 => vec![0x6c, (first_gac_arqc_response().len() - 2) as u8],
                7 => first_gac_arqc_response(),
                _ => vec![0x6a, 0x80],
            },
            4 => match count {
                0 => pse_directory_response(),
                1 => selected_fci_response(&[0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]),
                _ => vec![0x6a, 0x80],
            },
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

    unsafe extern "C" fn capture_relay_resistance_apdu(
        cmd: *const u8,
        cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let command = slice::from_raw_parts(cmd, cmd_len);
        TRANSMIT_COUNT.fetch_add(1, Ordering::SeqCst);
        TRANSMITTED_INS.store(command[1], Ordering::SeqCst);
        TRANSMITTED_LEN.store(cmd_len, Ordering::SeqCst);
        *LAST_TRANSMITTED_COMMAND.lock().unwrap() = command.to_vec();
        TRANSMIT_TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
        let response = [
            RELAY_SW1.load(Ordering::SeqCst),
            RELAY_SW2.load(Ordering::SeqCst),
        ];
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    fn pse_directory_response() -> Vec<u8> {
        vec![
            0x6f, 0x1b, 0xa5, 0x19, 0xbf, 0x0c, 0x16, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00,
            0x00, 0x03, 0x10, 0x10, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x04, 0x10,
            0x10, 0x90, 0x00,
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
            0x70, 0x67, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f, 0x5f, 0x24,
            0x03, 0x30, 0x12, 0x31, 0x5f, 0x25, 0x03, 0x25, 0x01, 0x01, 0x5f, 0x28, 0x02, 0x08,
            0x40, 0x9f, 0x07, 0x02, 0xff, 0x80, 0x9f, 0x09, 0x02, 0x00, 0x01, 0x8e, 0x0a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x9f, 0x0d, 0x05, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x9f, 0x0e, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f, 0x0f, 0x05,
            0x00, 0x00, 0x00, 0x80, 0x00, 0x8c, 0x12, 0x9f, 0x02, 0x06, 0x9f, 0x37, 0x04, 0x95,
            0x05, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x1a, 0x02, 0x9f, 0x34, 0x03, 0x8d, 0x08, 0x8a,
            0x02, 0x91, 0x08, 0x95, 0x05, 0x9b, 0x02, 0x90, 0x00,
        ]
    }

    fn first_gac_arqc_response() -> Vec<u8> {
        vec![
            0x77, 0x1a, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x9f, 0x10, 0x03, 0xaa, 0xbb, 0xcc,
            0x90, 0x00,
        ]
    }

    unsafe extern "C" fn capture_offline_auth_record_apdu(
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
            0 => vec![0x70, 0x03, 0x5a, 0x01, 0x99, 0x90, 0x00],
            _ => vec![0x70, 0x03, 0x5f, 0x20, 0x00, 0x90, 0x00],
        };
        let capacity = *resp_len;
        *resp_len = response.len();
        if capacity < response.len() {
            return KernelError::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(response.as_ptr(), resp, response.len());
        KernelError::Ok.code()
    }

    unsafe extern "C" fn scripted_read_record_status_apdu(
        _cmd: *const u8,
        _cmd_len: usize,
        resp: *mut u8,
        resp_len: *mut usize,
        _timeout_ms: i32,
        _user_data: *mut c_void,
    ) -> i32 {
        let response: &[u8] = match READ_RECORD_RESPONSE_MODE.load(Ordering::SeqCst) {
            0 => &[0x70],
            1 => &[0x6a, 0x83],
            _ => &[0x69, 0x85],
        };
        *resp_len = response.len();
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
            3 => vec![0x61, 0x02],
            4 if command[1] == 0x82 => vec![0x61, 0x02],
            4 if command[1] == 0xc0 => vec![0x90, 0x00],
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

    fn reset_callback_fixture_state() {
        CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
        CALLBACK_DATA_RECORD_LEN.store(0, Ordering::SeqCst);
        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        TRANSMITTED_INS.store(0, Ordering::SeqCst);
        TRANSMITTED_LEN.store(0, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        TRANSMIT_TIMEOUT_MS.store(0, Ordering::SeqCst);
        ISSUER_AUTH_SW1.store(0x90, Ordering::SeqCst);
        ISSUER_AUTH_SW2.store(0x00, Ordering::SeqCst);
        SCRIPT_SW1.store(0x90, Ordering::SeqCst);
        SCRIPT_SW2.store(0x00, Ordering::SeqCst);
        RELAY_SW1.store(0x90, Ordering::SeqCst);
        RELAY_SW2.store(0x00, Ordering::SeqCst);
        SCRIPT_FOLLOWUP_MODE.store(0, Ordering::SeqCst);
        FOLLOWUP_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        FOLLOWUP_TRANSMITTED_INS.store(0, Ordering::SeqCst);
        FOLLOWUP_TRANSMITTED_LEN.store(0, Ordering::SeqCst);
        DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
        READ_RECORD_RESPONSE_MODE.store(0, Ordering::SeqCst);
    }

    unsafe fn assert_callback_rejects_small_response_buffer(
        callback: KrnTransmitApduCallback,
        command: &[u8],
        user_data: *mut c_void,
    ) {
        let mut response = [0u8; 1];
        let mut response_len = response.len();

        assert_eq!(
            callback(
                command.as_ptr(),
                command.len(),
                response.as_mut_ptr(),
                &mut response_len,
                APDU_TRANSMIT_TIMEOUT_MS,
                user_data,
            ),
            KernelError::BufferTooSmall.code()
        );
        assert!(response_len > response.len());
    }

    unsafe fn callback_response(
        callback: KrnTransmitApduCallback,
        command: &[u8],
        user_data: *mut c_void,
    ) -> (i32, Vec<u8>) {
        let mut response = [0u8; 256];
        let mut response_len = response.len();
        let code = callback(
            command.as_ptr(),
            command.len(),
            response.as_mut_ptr(),
            &mut response_len,
            APDU_TRANSMIT_TIMEOUT_MS,
            user_data,
        );
        (code, response[..response_len].to_vec())
    }

    #[test]
    fn ffi_runtime_callback_fixtures_cover_default_status_responses() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        reset_callback_fixture_state();
        let command = [0x00, 0xda, 0x00, 0x00, 0x00];

        unsafe {
            for (mode, count) in [(1, 6usize), (2, 6), (3, 8), (4, 2), (99, 0)] {
                let selection_script = SelectionStatusPolicyScript {
                    counter: AtomicUsize::new(count),
                    mode,
                    commands: Mutex::new(Vec::new()),
                };
                let (code, response) = callback_response(
                    capture_selection_status_policy_apdu,
                    &command,
                    (&selection_script as *const SelectionStatusPolicyScript)
                        .cast_mut()
                        .cast(),
                );
                assert_eq!(code, KernelError::Ok.code());
                assert_eq!(response, vec![0x6a, 0x80]);
            }

            SCRIPT_FOLLOWUP_MODE.store(0, Ordering::SeqCst);
            FOLLOWUP_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            let (code, response) =
                callback_response(capture_script_followup_apdu, &command, ptr::null_mut());
            assert_eq!(code, KernelError::Ok.code());
            assert_eq!(response, vec![0x6a, 0x80]);
        }
        reset_callback_fixture_state();
    }

    #[test]
    fn ffi_runtime_callback_fixtures_reject_small_output_buffers() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        reset_callback_fixture_state();
        let auth_command = [0x00, 0x88, 0x00, 0x00];
        let gac_command = [0x80, 0xae, 0x80, 0x00];
        let script_command = [0x80, 0xda, 0x00, 0x00];

        unsafe {
            DDA_RESPONSE_MODE.store(0, Ordering::SeqCst);
            assert_callback_rejects_small_response_buffer(
                capture_internal_authenticate_apdu,
                &auth_command,
                ptr::null_mut(),
            );
            assert_callback_rejects_small_response_buffer(
                capture_cda_generate_ac_apdu,
                &gac_command,
                ptr::null_mut(),
            );
            assert_callback_rejects_small_response_buffer(
                capture_cda_generate_ac_apdu_without_9f4c,
                &gac_command,
                ptr::null_mut(),
            );
            assert_callback_rejects_small_response_buffer(
                capture_cda_tc_generate_ac_apdu,
                &gac_command,
                ptr::null_mut(),
            );
            assert_callback_rejects_small_response_buffer(
                capture_cda_format_1_generate_ac_without_sdad,
                &gac_command,
                ptr::null_mut(),
            );

            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_callback_rejects_small_response_buffer(
                capture_select_apdu,
                &auth_command,
                ptr::null_mut(),
            );

            let selection_script = SelectionStatusPolicyScript {
                counter: AtomicUsize::new(0),
                mode: 1,
                commands: Mutex::new(Vec::new()),
            };
            assert_callback_rejects_small_response_buffer(
                capture_selection_status_policy_apdu,
                &auth_command,
                (&selection_script as *const SelectionStatusPolicyScript)
                    .cast_mut()
                    .cast(),
            );

            assert_callback_rejects_small_response_buffer(
                capture_relay_resistance_apdu,
                &auth_command,
                ptr::null_mut(),
            );

            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_callback_rejects_small_response_buffer(
                capture_offline_auth_record_apdu,
                &auth_command,
                ptr::null_mut(),
            );

            SCRIPT_FOLLOWUP_MODE.store(1, Ordering::SeqCst);
            FOLLOWUP_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_callback_rejects_small_response_buffer(
                capture_script_followup_apdu,
                &script_command,
                ptr::null_mut(),
            );
            SCRIPT_FOLLOWUP_MODE.store(0, Ordering::SeqCst);
        }
        reset_callback_fixture_state();
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

    unsafe extern "C" fn fail_unpredictable_number(
        _out: *mut u8,
        _out_len: usize,
        _user_data: *mut c_void,
    ) -> i32 {
        KernelError::RngFailure.code()
    }

    #[test]
    fn ffi_remaining_entrypoint_guards_fail_closed() {
        unsafe {
            let mut ctx = KrnContext::new();
            let mut out_len = 0usize;
            let mut byte = 0u8;
            let mut phase = 0u8;
            let mut script_index = 0u16;
            let mut command_index = 0u16;
            let mut profile_version = 0u64;

            assert_eq!(
                krn_load_certification_bundle_verified(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    26,
                    5,
                    21,
                ),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_online_authorization_data(ptr::null_mut(), ptr::null_mut(), &mut out_len),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_apply_host_response(ptr::null_mut(), ptr::null(), 0),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_issuer_scripts(ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_post_final_issuer_scripts(ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_final_generate_ac(ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_issuer_script_result_phase(ptr::null_mut(), 0, &mut phase),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_issuer_script_result_position(
                    ptr::null_mut(),
                    0,
                    &mut script_index,
                    &mut command_index,
                ),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_issuer_script_result_identifier(
                    ptr::null_mut(),
                    0,
                    &mut byte,
                    &mut out_len,
                ),
                KernelError::InvalidArgument.code()
            );

            ctx.busy = true;
            for code in [
                krn_load_certification_bundle_verified(
                    &mut ctx,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    26,
                    5,
                    21,
                ),
                krn_build_internal_authenticate(
                    &mut ctx,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    &mut out_len,
                ),
                krn_get_online_authorization_data(&mut ctx, ptr::null_mut(), &mut out_len),
                krn_apply_host_response(&mut ctx, ptr::null(), 0),
                krn_process_issuer_authentication(&mut ctx),
                krn_process_issuer_scripts(&mut ctx),
                krn_process_post_final_issuer_scripts(&mut ctx),
                krn_process_final_generate_ac(&mut ctx),
                krn_get_issuer_script_result_phase(&mut ctx, 0, &mut phase),
                krn_get_issuer_script_result_position(
                    &mut ctx,
                    0,
                    &mut script_index,
                    &mut command_index,
                ),
                krn_get_issuer_script_result_identifier(&mut ctx, 0, &mut byte, &mut out_len),
                krn_get_profile_version(&mut ctx, &mut profile_version),
                krn_get_profile_sha256(&mut ctx, ptr::null_mut(), &mut out_len),
                krn_set_contactless_outcome_callback(
                    &mut ctx,
                    Some(capture_contactless_outcome),
                    ptr::null_mut(),
                ),
            ] {
                assert_eq!(code, KernelError::Busy.code());
            }
        }
    }

    #[test]
    fn contactless_callback_registration_updates_active_runtime_callbacks() {
        let mut ctx = KrnContext::new();
        ctx.runtime = Some(RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        });
        let user_data = 0x1usize as *mut c_void;

        assert_eq!(
            unsafe {
                krn_set_contactless_outcome_callback(
                    &mut ctx,
                    Some(capture_contactless_outcome),
                    user_data,
                )
            },
            KernelError::Ok.code()
        );

        let runtime = ctx.runtime.expect("runtime should remain installed");
        assert!(runtime.contactless_outcome.is_some());
        assert_eq!(runtime.user_data, user_data);
        assert!(ctx.contactless_outcome_callback.is_some());
        assert_eq!(ctx.contactless_outcome_user_data, user_data);
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
    fn ffi_builds_generate_ac_and_internal_authenticate_boundaries() {
        unsafe {
            let ctx = krn_context_new();
            let mut out = [0u8; 64];
            let mut len = out.len();

            assert_eq!(
                krn_build_generate_ac(
                    ptr::null_mut(),
                    2,
                    ptr::null(),
                    0,
                    0,
                    out.as_mut_ptr(),
                    &mut len,
                ),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_build_generate_ac(ctx, 2, ptr::null(), 1, 0, out.as_mut_ptr(), &mut len),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_build_generate_ac(ctx, 9, ptr::null(), 0, 0, out.as_mut_ptr(), &mut len),
                KernelError::InvalidArgument.code()
            );

            for (request, expected_p1) in [(0, 0x00), (1, 0x40), (2, 0x80)] {
                len = out.len();
                assert_eq!(
                    krn_build_generate_ac(
                        ctx,
                        request,
                        ptr::null(),
                        0,
                        0,
                        out.as_mut_ptr(),
                        &mut len,
                    ),
                    KernelError::Ok.code()
                );
                assert_eq!(&out[..5], &[0x80, 0xae, expected_p1, 0x00, 0x00]);
                assert_eq!(len, 5);
            }

            let cdol_values = [0x9f, 0x37, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
            len = out.len();
            assert_eq!(
                krn_build_generate_ac(
                    ctx,
                    2,
                    cdol_values.as_ptr(),
                    cdol_values.len(),
                    0x10,
                    out.as_mut_ptr(),
                    &mut len,
                ),
                KernelError::Ok.code()
            );
            assert_eq!(&out[..5], &[0x80, 0xae, 0x90, 0x00, 0x07]);
            assert_eq!(&out[5..12], &cdol_values);
            assert_eq!(out[12], 0x00);
            assert_eq!(len, 13);

            assert_eq!(
                krn_build_internal_authenticate(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    &mut len,
                ),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_build_internal_authenticate(ctx, ptr::null(), 1, out.as_mut_ptr(), &mut len),
                KernelError::InvalidArgument.code()
            );
            len = out.len();
            assert_eq!(
                krn_build_internal_authenticate(ctx, ptr::null(), 0, out.as_mut_ptr(), &mut len),
                KernelError::Ok.code()
            );
            assert_eq!(&out[..5], &[0x00, 0x88, 0x00, 0x00, 0x00]);
            assert_eq!(len, 5);

            let ddol_values = [0x01, 0x02, 0x03, 0x04];
            len = out.len();
            assert_eq!(
                krn_build_internal_authenticate(
                    ctx,
                    ddol_values.as_ptr(),
                    ddol_values.len(),
                    out.as_mut_ptr(),
                    &mut len,
                ),
                KernelError::Ok.code()
            );
            assert_eq!(&out[..5], &[0x00, 0x88, 0x00, 0x00, 0x04]);
            assert_eq!(&out[5..9], &ddol_values);
            assert_eq!(out[9], 0x00);
            assert_eq!(len, 10);

            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_trace_and_conformance_exports_cover_error_and_success_paths() {
        unsafe {
            let mut out = [0u8; 512];
            let mut len = out.len();

            assert_eq!(krn_abi_version(), KRN_ABI_VERSION);
            assert_eq!(
                krn_context_as_opaque(ptr::null_mut()),
                ptr::null_mut::<c_void>()
            );
            assert_eq!(
                krn_error_code_at(0, ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );

            assert_eq!(
                krn_mask_apdu_response_json(
                    9,
                    ptr::null(),
                    0,
                    0x90,
                    0x00,
                    false,
                    out.as_mut_ptr(),
                    &mut len,
                ),
                KernelError::InvalidArgument.code()
            );

            let response = first_gac_arqc_response();
            let response_body = &response[..response.len() - 2];
            len = out.len();
            assert_eq!(
                krn_mask_apdu_response_json(
                    1,
                    response_body.as_ptr(),
                    response_body.len(),
                    0x90,
                    0x00,
                    false,
                    out.as_mut_ptr(),
                    &mut len,
                ),
                KernelError::Ok.code()
            );
            let json = core::str::from_utf8(&out[..len]).unwrap();
            assert!(json.contains("generate-ac-response"));
            assert!(json.contains("9000"));

            len = 0;
            assert_eq!(
                krn_get_conformance_statement_json(ptr::null_mut(), &mut len),
                KernelError::BufferTooSmall.code()
            );
            assert!(len > 0);
            let mut json = vec![0u8; len];
            assert_eq!(
                krn_get_conformance_statement_json(json.as_mut_ptr(), &mut len),
                KernelError::Ok.code()
            );
            assert!(core::str::from_utf8(&json)
                .unwrap()
                .contains("Hyperion EMV Level 2 Kernel"));

            assert_eq!(
                krn_error_description(9_999, out.as_mut_ptr(), &mut len),
                KernelError::InvalidArgument.code()
            );
        }
    }

    #[test]
    fn ffi_accessors_reject_null_missing_runtime_and_missing_results() {
        unsafe {
            let ctx = krn_context_new();

            assert_eq!(
                krn_run_transaction(ptr::null_mut()),
                KrnOutcome::Error.code()
            );
            assert_eq!(krn_get_final_outcome(ptr::null()), KrnOutcome::Error.code());
            assert_eq!(krn_get_issuer_script_result_count(ptr::null()), 0);
            assert_eq!(krn_get_issuer_script_result_count(ctx), 0);

            let mut sw1 = 0u8;
            let mut sw2 = 0u8;
            assert_eq!(
                krn_get_issuer_script_result(ptr::null_mut(), 0, &mut sw1, &mut sw2),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_issuer_script_result(ctx, 0, ptr::null_mut(), &mut sw2),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_issuer_script_result(ctx, 0, &mut sw1, &mut sw2),
                KernelError::InvalidArgument.code()
            );

            assert_eq!(
                krn_process_issuer_authentication(ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_issuer_authentication(ctx),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_issuer_scripts(ctx),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_post_final_issuer_scripts(ctx),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_process_final_generate_ac(ctx),
                KernelError::InvalidArgument.code()
            );

            let mut version = 0u64;
            assert_eq!(
                krn_get_profile_version(ptr::null_mut(), &mut version),
                KernelError::InvalidArgument.code()
            );
            let mut digest = [0u8; KRN_PROFILE_SHA256_LEN];
            let mut digest_len = digest.len();
            assert_eq!(
                krn_get_profile_sha256(ptr::null_mut(), digest.as_mut_ptr(), &mut digest_len),
                KernelError::InvalidArgument.code()
            );

            assert_eq!(
                krn_set_contactless_outcome_callback(ptr::null_mut(), None, ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_emit_contactless_outcome(
                    ptr::null_mut(),
                    ContactlessOutcomeCode::OnlineRequired as u8,
                    StartSignal::Start as u8,
                    0,
                    UiStatus::Processing as u8,
                    0,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    AlternateInterface::None as u8,
                ),
                KernelError::InvalidArgument.code()
            );

            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_profile_and_bundle_loaders_cover_null_and_digest_error_paths() {
        unsafe {
            assert_eq!(
                krn_load_profiles_verified(ptr::null_mut(), ptr::null(), 0, 1, 2, 26, 5, 21),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_load_certification_bundle_verified(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    26,
                    5,
                    25,
                ),
                KernelError::InvalidArgument.code()
            );

            let ctx = krn_context_new();
            assert_eq!(
                krn_load_profiles_verified(ctx, ptr::null(), 1, 1, 2, 26, 5, 21),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_load_certification_bundle_verified(
                    ctx,
                    ptr::null(),
                    1,
                    ptr::null(),
                    0,
                    0,
                    26,
                    5,
                    25,
                ),
                KernelError::InvalidArgument.code()
            );

            let mut out = [0u8; KRN_PROFILE_SHA256_LEN];
            let mut len = out.len();
            assert_eq!(
                krn_get_certification_bundle_sha256(ptr::null(), out.as_mut_ptr(), &mut len),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_certification_bundle_sha256(ctx, ptr::null_mut(), &mut len),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_certification_bundle_sha256(ctx, out.as_mut_ptr(), ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            len = out.len() - 1;
            assert_eq!(
                krn_get_certification_bundle_sha256(ctx, out.as_mut_ptr(), &mut len),
                KernelError::BufferTooSmall.code()
            );
            assert_eq!(len, KRN_PROFILE_SHA256_LEN);
            len = out.len();
            assert_eq!(
                krn_get_certification_bundle_sha256(ctx, out.as_mut_ptr(), &mut len),
                KernelError::InvalidProfile.code()
            );

            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_low_level_helpers_cover_length_and_encoding_edges() {
        assert_eq!(encoded_length_size(0x7f), 1);
        assert_eq!(encoded_length_size(0x80), 2);
        assert_eq!(encoded_length_size(0x100), 3);

        let mut out = Vec::new();
        assert_eq!(append_tlv(&mut out, &[0x9f, 0x10], &[0xaa; 0x7f]), Ok(()));
        assert_eq!(out[2], 0x7f);
        out.clear();
        assert_eq!(append_tlv(&mut out, &[0x9f, 0x10], &[0xbb; 0x80]), Ok(()));
        assert_eq!(&out[2..4], &[0x81, 0x80]);
        out.clear();
        assert_eq!(append_tlv(&mut out, &[0x9f, 0x10], &[0xcc; 0x100]), Ok(()));
        assert_eq!(&out[2..5], &[0x82, 0x01, 0x00]);

        for bad_tag in [&[][..], &[0x01, 0x02, 0x03, 0x04, 0x05][..]] {
            out.clear();
            assert_eq!(
                append_tlv(&mut out, bad_tag, &[]).unwrap_err(),
                KernelError::LengthOverflow
            );
        }

        out.clear();
        assert_eq!(
            encode_length(&mut out, usize::from(u16::MAX) + 1).unwrap_err(),
            KernelError::LengthOverflow
        );

        unsafe {
            let cfg = KrnConfigBlob {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnConfigBlob>() as u32,
                bytes: ptr::null(),
                len: 0,
            };
            assert_eq!(validate_config_blob(&cfg), Ok(()));

            let cfg = KrnConfigBlob {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnConfigBlob>() as u32,
                bytes: ptr::null(),
                len: 1,
            };
            assert_eq!(
                validate_config_blob(&cfg).unwrap_err(),
                KernelError::InvalidArgument
            );
            assert!(matches!(
                read_runtime(ptr::null()),
                Err(KernelError::InvalidArgument)
            ));
            assert_eq!(
                read_transaction_params(ptr::null()).unwrap_err(),
                KernelError::InvalidArgument
            );
        }
    }

    #[test]
    fn ffi_contactless_outcome_codecs_accept_every_stable_value() {
        for (raw, expected) in [
            (1, ContactlessOutcomeCode::Approved),
            (2, ContactlessOutcomeCode::Declined),
            (3, ContactlessOutcomeCode::OnlineRequired),
            (4, ContactlessOutcomeCode::TryAgain),
            (5, ContactlessOutcomeCode::SelectNext),
            (6, ContactlessOutcomeCode::AlternateInterface),
            (7, ContactlessOutcomeCode::Terminate),
            (8, ContactlessOutcomeCode::CvmRequired),
            (255, ContactlessOutcomeCode::ProfileDefined),
        ] {
            assert_eq!(outcome_code_from_u8(raw), Ok(expected));
        }
        assert_eq!(
            outcome_code_from_u8(9).unwrap_err(),
            KernelError::InvalidArgument
        );

        for (raw, expected) in [
            (0, StartSignal::None),
            (1, StartSignal::Start),
            (2, StartSignal::Restart),
            (3, StartSignal::Prompt),
        ] {
            assert_eq!(start_signal_from_u8(raw), Ok(expected));
        }
        assert_eq!(
            start_signal_from_u8(4).unwrap_err(),
            KernelError::InvalidArgument
        );

        for (raw, expected) in [
            (0, UiStatus::None),
            (1, UiStatus::ReadyToRead),
            (2, UiStatus::Processing),
            (3, UiStatus::Approved),
            (4, UiStatus::Declined),
            (5, UiStatus::Error),
            (6, UiStatus::TryAgain),
        ] {
            assert_eq!(ui_status_from_u8(raw), Ok(expected));
        }
        assert_eq!(
            ui_status_from_u8(7).unwrap_err(),
            KernelError::InvalidArgument
        );

        for (raw, expected) in [
            (0, AlternateInterface::None),
            (1, AlternateInterface::Contact),
            (2, AlternateInterface::Magstripe),
            (3, AlternateInterface::OtherCard),
        ] {
            assert_eq!(alternate_interface_from_u8(raw), Ok(expected));
        }
        assert_eq!(
            alternate_interface_from_u8(4).unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn retry_apdu_with_le_covers_short_and_case_variants() {
        assert_eq!(
            retry_apdu_with_le(&[0x00, 0xc0, 0x00], 0x10).unwrap_err(),
            KernelError::InvalidArgument
        );
        assert_eq!(
            retry_apdu_with_le(&[0x00, 0xc0, 0x00, 0x00], 0x10).unwrap(),
            vec![0x00, 0xc0, 0x00, 0x00, 0x10]
        );
        assert_eq!(
            retry_apdu_with_le(&[0x00, 0xc0, 0x00, 0x00, 0x00], 0x10).unwrap(),
            vec![0x00, 0xc0, 0x00, 0x00, 0x10]
        );
        assert_eq!(
            retry_apdu_with_le(&[0x00, 0xda, 0x00, 0x00, 0x02, 0xaa, 0xbb], 0x10).unwrap(),
            vec![0x00, 0xda, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0x10]
        );
        assert_eq!(
            retry_apdu_with_le(&[0x00, 0xda, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0x00], 0x10).unwrap(),
            vec![0x00, 0xda, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0x10]
        );
        assert_eq!(
            retry_apdu_with_le(&[0x00, 0xda, 0x00, 0x00, 0x02, 0xaa], 0x10).unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn ffi_write_output_handles_empty_outputs_without_buffer() {
        unsafe {
            let mut len = usize::MAX;
            assert_eq!(write_output(&[], ptr::null_mut(), &mut len), Ok(0));
            assert_eq!(len, 0);

            assert_eq!(
                write_output(&[], ptr::null_mut(), ptr::null_mut()).unwrap_err(),
                KernelError::InvalidArgument
            );
        }
    }

    #[test]
    fn apply_host_response_rejects_empty_or_oversize_payload() {
        unsafe {
            let ctx = krn_context_new();

            assert_eq!(
                krn_apply_host_response(ctx, ptr::null(), 0),
                KernelError::LengthOverflow.code()
            );
            assert_eq!(krn_get_last_error(ctx), KernelError::LengthOverflow.code());

            let oversized = vec![0u8; MAX_HOST_RESPONSE_LEN + 1];
            assert_eq!(
                krn_apply_host_response(ctx, oversized.as_ptr(), oversized.len()),
                KernelError::LengthOverflow.code()
            );
            assert_eq!(krn_get_last_error(ctx), KernelError::LengthOverflow.code());

            krn_context_free(ctx);
        }
    }

    #[test]
    fn online_authorization_package_rejects_tlv_output_above_limit() {
        let package = OnlineAuthorizationPackage {
            objects: vec![crate::gac::TagValue {
                tag: vec![0x9f, 0x10],
                value: vec![0u8; MAX_ONLINE_AUTH_DATA_LEN + 1],
            }],
        };

        assert_eq!(
            encode_online_authorization_package(&package).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn krn_api_004_rejects_reentrant_mutating_entrypoints() {
        unsafe {
            let ctx = krn_context_new();
            (*ctx).busy = true;

            assert_eq!(krn_reset(ctx), KernelError::Busy.code());
            assert_eq!(
                krn_set_transaction_params(ctx, ptr::null()),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_load_profiles_verified(ctx, ptr::null(), 0, 1, 2, 26, 5, 21),
                KernelError::Busy.code()
            );
            assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error.code());

            let mut out_len = 0usize;
            assert_eq!(
                krn_build_select_environment(ctx, false, ptr::null_mut(), &mut out_len),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_build_generate_ac(ctx, 2, ptr::null(), 1, 0, ptr::null_mut(), &mut out_len),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_get_online_authorization_data(ctx, ptr::null_mut(), &mut out_len),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_apply_host_response(ctx, ptr::null(), 0),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_process_issuer_authentication(ctx),
                KernelError::Busy.code()
            );
            assert_eq!(krn_process_issuer_scripts(ctx), KernelError::Busy.code());
            assert_eq!(
                krn_process_post_final_issuer_scripts(ctx),
                KernelError::Busy.code()
            );
            assert_eq!(krn_process_final_generate_ac(ctx), KernelError::Busy.code());

            let mut sw1 = 0u8;
            let mut sw2 = 0u8;
            assert_eq!(
                krn_get_issuer_script_result(ctx, 0, &mut sw1, &mut sw2),
                KernelError::Busy.code()
            );
            let mut version = 0u64;
            assert_eq!(
                krn_get_profile_version(ctx, &mut version),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_set_contactless_outcome_callback(ctx, None, ptr::null_mut()),
                KernelError::Busy.code()
            );
            assert_eq!(
                krn_emit_contactless_outcome(
                    ctx,
                    ContactlessOutcomeCode::OnlineRequired as u8,
                    StartSignal::Start as u8,
                    0,
                    UiStatus::Processing as u8,
                    0,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    AlternateInterface::None as u8,
                ),
                KernelError::Busy.code()
            );

            assert_eq!(krn_get_last_error(ctx), KernelError::Busy.code());
            (*ctx).busy = false;
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
    fn ffi_rejects_inconsistent_contactless_outcome_tuples() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
            let ctx = krn_context_new();
            assert_eq!(
                krn_set_contactless_outcome_callback(
                    ctx,
                    Some(capture_contactless_outcome),
                    ptr::null_mut()
                ),
                KernelError::Ok.code()
            );

            assert_eq!(
                krn_emit_contactless_outcome(
                    ctx,
                    ContactlessOutcomeCode::TryAgain as u8,
                    StartSignal::Prompt as u8,
                    4,
                    UiStatus::Processing as u8,
                    0,
                    1,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    AlternateInterface::None as u8,
                ),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst), 0);

            assert_eq!(
                krn_emit_contactless_outcome(
                    ctx,
                    ContactlessOutcomeCode::AlternateInterface as u8,
                    StartSignal::Prompt as u8,
                    3,
                    UiStatus::Error as u8,
                    0,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    AlternateInterface::None as u8,
                ),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst), 0);

            krn_context_free(ctx);
        }
    }

    #[test]
    fn contactless_limit_processing_uses_profile_limits_and_ctq_cdcvm() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.contactless_outcome_callback = Some(capture_contactless_outcome);
        ctx.contactless_outcome_user_data = ptr::null_mut();
        ctx.card_data
            .put(&[0x9f, 0x34], &[0x01, 0x00, 0x01])
            .unwrap();
        let profiles = ctx.profiles.clone().unwrap();
        let params = StoredTxnParams {
            amount_authorised_minor: 4_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: Vec::new(),
        };
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_relay_resistance_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
        assert_eq!(
            run_contactless_limit_processing(&mut ctx, runtime, &profiles, &params),
            Ok(Some(KrnOutcome::TryAgain))
        );
        assert_eq!(
            CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst),
            ContactlessOutcomeCode::CvmRequired as u8
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::TryAgain));

        ctx.fsm_state = FsmState::S8;
        ctx.state = KernelState::TerminalRiskManagement;
        ctx.final_outcome = None;
        ctx.card_data.put(&[0x9f, 0x6c], &[0x10, 0x00]).unwrap();
        CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
        assert_eq!(
            run_contactless_limit_processing(&mut ctx, runtime, &profiles, &params),
            Ok(None)
        );
        assert_eq!(CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst), 0);
        assert_eq!(ctx.final_outcome, None);
    }

    #[test]
    fn contactless_cdcvm_requires_profile_ctq_and_contactless_interface() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.card_data.put(&[0x9f, 0x6c], &[0x10, 0x00]).unwrap();
        let aid = selected_aid_profile(&ctx).unwrap();
        assert_eq!(contactless_ctq_indicates_cdcvm(&ctx, aid, true), Ok(true));
        assert_eq!(contactless_ctq_indicates_cdcvm(&ctx, aid, false), Ok(false));

        ctx.profiles.as_mut().unwrap().schemes[0].aids[0].cdcvm_supported = false;
        let aid = selected_aid_profile(&ctx).unwrap();
        assert_eq!(contactless_ctq_indicates_cdcvm(&ctx, aid, true), Ok(false));

        let mut malformed = KrnContext::new();
        install_profile_selection(&mut malformed);
        malformed.card_data.put(&[0x9f, 0x6c], &[0x10]).unwrap();
        let aid = selected_aid_profile(&malformed).unwrap();
        assert_eq!(
            contactless_ctq_indicates_cdcvm(&malformed, aid, true).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn selected_kernel_mapping_is_interface_specific() {
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        let mut profiles = ctx.profiles.clone().unwrap();
        let contactless_params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: Vec::new(),
        };
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &contactless_params, &profiles),
            Ok(())
        );

        profiles.schemes[0].kernel_type = "legacy_visa".to_string();
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &contactless_params, &profiles),
            Err(KernelError::InvalidProfile)
        );

        profiles.schemes[0].kernel_type = "c8_contactless".to_string();
        let contact_params = StoredTxnParams {
            interface_preference: 1,
            ..contactless_params
        };
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &contact_params, &profiles),
            Ok(())
        );

        profiles.schemes[0].contact_kernel_type = None;
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &contact_params, &profiles),
            Err(KernelError::InvalidProfile)
        );
        profiles.schemes[0].contact_kernel_type = Some("c8_contactless".to_string());
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &contact_params, &profiles),
            Err(KernelError::InvalidProfile)
        );
    }

    #[test]
    fn selected_mapping_and_contactless_helpers_reject_bad_profile_edges() {
        fn selected_context() -> KrnContext {
            let mut ctx = KrnContext::new();
            install_profile_selection(&mut ctx);
            ctx
        }

        let ctx = selected_context();
        let profiles = ctx.profiles.clone().unwrap();
        let contactless_params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: KRN_INTERFACE_CONTACTLESS,
            merchant_name_location: Vec::new(),
        };

        let mut unselected = selected_context();
        unselected.selected_application = None;
        assert_eq!(
            validate_selected_kernel_mapping(&unselected, &contactless_params, &profiles),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(
            run_contactless_limit_processing(
                &mut unselected,
                runtime_with_transmit(capture_relay_resistance_apdu),
                &profiles,
                &contactless_params,
            ),
            Err(KernelError::InvalidArgument)
        );

        let mut bad_scheme = selected_context();
        bad_scheme
            .selected_application
            .as_mut()
            .unwrap()
            .scheme_index = profiles.schemes.len();
        assert_eq!(
            validate_selected_kernel_mapping(&bad_scheme, &contactless_params, &profiles),
            Err(KernelError::InvalidProfile)
        );

        let mut bad_aid = selected_context();
        bad_aid.selected_application.as_mut().unwrap().aid_index = profiles.schemes[0].aids.len();
        assert_eq!(
            validate_selected_kernel_mapping(&bad_aid, &contactless_params, &profiles),
            Err(KernelError::InvalidProfile)
        );

        let invalid_interface = StoredTxnParams {
            interface_preference: 9,
            ..contactless_params.clone()
        };
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &invalid_interface, &profiles),
            Err(KernelError::InvalidArgument)
        );

        let mut contactless_rejecting_profiles = profiles.clone();
        contactless_rejecting_profiles.schemes[0].kernel_type = "contact_only".to_string();
        assert_eq!(
            run_contactless_limit_processing(
                &mut selected_context(),
                runtime_with_transmit(capture_relay_resistance_apdu),
                &contactless_rejecting_profiles,
                &contactless_params,
            ),
            Err(KernelError::InvalidProfile)
        );

        let mut missing_contactless_interface = profiles.clone();
        missing_contactless_interface.schemes[0].aids[0].interfaces = vec!["contact".to_string()];
        assert_eq!(
            run_contactless_limit_processing(
                &mut selected_context(),
                runtime_with_transmit(capture_relay_resistance_apdu),
                &missing_contactless_interface,
                &contactless_params,
            ),
            Err(KernelError::InvalidProfile)
        );

        let contact_params = StoredTxnParams {
            interface_preference: KRN_INTERFACE_CONTACT,
            ..contactless_params
        };
        let mut missing_contact_interface = profiles.clone();
        missing_contact_interface.schemes[0].aids[0].interfaces = vec!["contactless".to_string()];
        assert_eq!(
            validate_selected_kernel_mapping(&ctx, &contact_params, &missing_contact_interface),
            Err(KernelError::InvalidProfile)
        );

        let mut relay_ctx = selected_context();
        relay_ctx.contactless_outcome_callback = Some(capture_contactless_outcome);
        relay_ctx.contactless_outcome_user_data = ptr::null_mut();
        let aid_without_relay = selected_aid_profile(&relay_ctx).unwrap().clone();
        assert_eq!(
            run_required_relay_resistance(
                &mut relay_ctx,
                runtime_with_transmit(capture_relay_resistance_apdu),
                &aid_without_relay,
            ),
            Ok(None)
        );

        let relay_profile = |failure_outcome| {
            RelayResistanceProfile::new(
                vec![0x80, 0xca, 0x9f, 0x7a, 0x00],
                50,
                vec![0x90, 0x00],
                failure_outcome,
            )
            .unwrap()
        };
        let mut transport_failure_aid = aid_without_relay.clone();
        transport_failure_aid.relay_resistance =
            Some(relay_profile(RelayResistanceFailureOutcome::TryAgain));
        assert_eq!(
            run_required_relay_resistance(
                &mut relay_ctx,
                runtime_with_transmit(fail_transmit_apdu),
                &transport_failure_aid,
            ),
            Err(KernelError::HostTimeout)
        );

        for (failure_outcome, kernel_outcome, callback_code) in [
            (
                RelayResistanceFailureOutcome::AlternateInterface,
                KrnOutcome::AlternateInterface,
                ContactlessOutcomeCode::AlternateInterface,
            ),
            (
                RelayResistanceFailureOutcome::Terminate,
                KrnOutcome::Terminated,
                ContactlessOutcomeCode::Terminate,
            ),
        ] {
            let mut failing_aid = aid_without_relay.clone();
            failing_aid.relay_resistance = Some(relay_profile(failure_outcome));
            relay_ctx.fsm_state = FsmState::S8;
            relay_ctx.state = KernelState::TerminalRiskManagement;
            relay_ctx.final_outcome = None;
            RELAY_SW1.store(0x69, Ordering::SeqCst);
            RELAY_SW2.store(0x85, Ordering::SeqCst);
            CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
            assert_eq!(
                run_required_relay_resistance(
                    &mut relay_ctx,
                    runtime_with_transmit(capture_relay_resistance_apdu),
                    &failing_aid,
                ),
                Ok(Some(kernel_outcome))
            );
            assert_eq!(relay_ctx.final_outcome, Some(kernel_outcome));
            assert_eq!(
                CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst),
                callback_code as u8
            );
        }
        RELAY_SW1.store(0x90, Ordering::SeqCst);
        RELAY_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn contactless_relay_resistance_is_profile_required_and_outcome_driven() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        install_profile_selection(&mut ctx);
        ctx.contactless_outcome_callback = Some(capture_contactless_outcome);
        ctx.contactless_outcome_user_data = ptr::null_mut();
        ctx.card_data
            .put(&[0x9f, 0x34], &[0x01, 0x00, 0x01])
            .unwrap();
        let mut profiles = ctx.profiles.clone().unwrap();
        profiles.schemes[0].aids[0].relay_resistance = Some(
            RelayResistanceProfile::new(
                vec![0x80, 0xca, 0x9f, 0x7a, 0x00],
                50,
                vec![0x90, 0x00],
                RelayResistanceFailureOutcome::TryAgain,
            )
            .unwrap(),
        );
        let params = StoredTxnParams {
            amount_authorised_minor: 1_000,
            amount_other_minor: 0,
            currency_code: 840,
            currency_exponent: 2,
            terminal_country_code: 840,
            transaction_type: 0,
            terminal_type: 0x22,
            merchant_category_code: [0x53, 0x11],
            interface_preference: 2,
            merchant_name_location: Vec::new(),
        };
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_relay_resistance_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
        RELAY_SW1.store(0x90, Ordering::SeqCst);
        RELAY_SW2.store(0x00, Ordering::SeqCst);
        assert_eq!(
            run_contactless_limit_processing(&mut ctx, runtime, &profiles, &params),
            Ok(None)
        );
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xca);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 5);
        assert_eq!(TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst), 50);
        assert_eq!(CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst), 0);

        ctx.fsm_state = FsmState::S8;
        ctx.state = KernelState::TerminalRiskManagement;
        ctx.final_outcome = None;
        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        RELAY_SW1.store(0x69, Ordering::SeqCst);
        RELAY_SW2.store(0x85, Ordering::SeqCst);
        CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
        assert_eq!(
            run_contactless_limit_processing(&mut ctx, runtime, &profiles, &params),
            Ok(Some(KrnOutcome::TryAgain))
        );
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(
            CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst),
            ContactlessOutcomeCode::TryAgain as u8
        );
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::TryAgain));

        RELAY_SW1.store(0x90, Ordering::SeqCst);
        RELAY_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn contactless_run_emits_c8_alternate_interface_before_first_gac() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            CALLBACK_OUTCOME_CODE.store(0, Ordering::SeqCst);
            CALLBACK_DATA_RECORD_LEN.store(usize::MAX, Ordering::SeqCst);
            let mut ctx = ptr::null_mut();
            let runtime = KrnRuntime {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnRuntime>() as u32,
                transmit_apdu: Some(capture_select_apdu),
                get_unpredictable_number: Some(fill_unpredictable_number),
                contactless_outcome: Some(capture_contactless_outcome),
                user_data: ptr::null_mut(),
            };
            assert_eq!(
                krn_init(ptr::null(), &runtime, &mut ctx),
                KernelError::Ok.code()
            );
            let profiles = include_bytes!("../docs/scheme_profiles.cert.json");
            assert_eq!(
                krn_load_profiles_verified(ctx, profiles.as_ptr(), profiles.len(), 1, 2, 26, 5, 21),
                KernelError::Ok.code()
            );

            let params = KrnTxnParams {
                struct_size: mem::size_of::<KrnTxnParams>() as u32,
                amount_authorised_minor: 5_001,
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
                KernelError::Ok.code()
            );
            set_test_trm_random_selection_sample(ctx);
            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_eq!(
                krn_run_transaction(ctx),
                KrnOutcome::AlternateInterface.code()
            );
            assert_eq!(
                CALLBACK_OUTCOME_CODE.load(Ordering::SeqCst),
                ContactlessOutcomeCode::AlternateInterface as u8
            );
            assert_eq!(CALLBACK_DATA_RECORD_LEN.load(Ordering::SeqCst), 0);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 4);
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xb2);
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S16.code());
            assert_eq!(krn_get_last_error(ctx), KernelError::Ok.code());
            assert_eq!(
                ctx.as_ref().unwrap().final_outcome,
                Some(KrnOutcome::AlternateInterface)
            );
            krn_context_free(ctx);
        }
    }

    #[test]
    fn runtime_selection_uses_status_policy_for_get_response_and_invalidated_aids() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        for (mode, expected_aid, expected_second_ins) in [
            (1, [0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10], 0xc0),
            (2, [0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10], 0xa4),
        ] {
            unsafe {
                let script = SelectionStatusPolicyScript {
                    counter: AtomicUsize::new(0),
                    mode,
                    commands: Mutex::new(Vec::new()),
                };
                let mut ctx = ptr::null_mut();
                let runtime = KrnRuntime {
                    abi_version: KRN_ABI_VERSION,
                    struct_size: mem::size_of::<KrnRuntime>() as u32,
                    transmit_apdu: Some(capture_selection_status_policy_apdu),
                    get_unpredictable_number: Some(fill_unpredictable_number),
                    contactless_outcome: None,
                    user_data: &script as *const SelectionStatusPolicyScript as *mut c_void,
                };
                assert_eq!(
                    krn_init(ptr::null(), &runtime, &mut ctx),
                    KernelError::Ok.code()
                );
                let profiles = include_bytes!("../docs/scheme_profiles.cert.json");
                assert_eq!(
                    krn_load_profiles_verified(
                        ctx,
                        profiles.as_ptr(),
                        profiles.len(),
                        1,
                        2,
                        26,
                        5,
                        21
                    ),
                    KernelError::Ok.code()
                );
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
                assert_eq!(
                    krn_set_transaction_params(ctx, &params),
                    KernelError::Ok.code()
                );
                set_test_trm_random_selection_sample(ctx);

                assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired.code());
                assert_eq!(krn_get_last_error(ctx), KernelError::Ok.code());
                assert_eq!(krn_get_fsm_state(ctx), FsmState::S11.code());
                let ctx_ref = ctx.as_ref().unwrap();
                assert_eq!(
                    ctx_ref.selected_application.as_ref().unwrap().aid,
                    expected_aid
                );

                let commands = script.commands.lock().unwrap();
                assert_eq!(commands[1][1], expected_second_ins);
                if mode == 1 {
                    assert_eq!(commands[1], vec![0x00, 0xc0, 0x00, 0x00, 0x17]);
                } else {
                    assert_eq!(&commands[0][..5], &[0x00, 0xa4, 0x04, 0x00, 0x0e]);
                    assert_eq!(&commands[1][..5], &[0x00, 0xa4, 0x04, 0x00, 0x07]);
                    assert_eq!(&commands[2][..5], &[0x00, 0xa4, 0x04, 0x00, 0x07]);
                }
                drop(commands);
                krn_context_free(ctx);
            }
        }
    }

    #[test]
    fn runtime_partial_selection_uses_card_adf_name_for_select() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            let script = SelectionStatusPolicyScript {
                counter: AtomicUsize::new(0),
                mode: 3,
                commands: Mutex::new(Vec::new()),
            };
            let mut ctx = ptr::null_mut();
            let runtime = KrnRuntime {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnRuntime>() as u32,
                transmit_apdu: Some(capture_selection_status_policy_apdu),
                get_unpredictable_number: Some(fill_unpredictable_number),
                contactless_outcome: None,
                user_data: &script as *const SelectionStatusPolicyScript as *mut c_void,
            };
            assert_eq!(
                krn_init(ptr::null(), &runtime, &mut ctx),
                KernelError::Ok.code()
            );
            let profiles = std::str::from_utf8(include_bytes!("../docs/scheme_profiles.cert.json"))
                .unwrap()
                .replacen(r#""aid": "A0000000031010""#, r#""aid": "A000000003""#, 1);
            assert_eq!(
                krn_load_profiles_verified(ctx, profiles.as_ptr(), profiles.len(), 1, 2, 26, 5, 21),
                KernelError::Ok.code()
            );
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
            assert_eq!(
                krn_set_transaction_params(ctx, &params),
                KernelError::Ok.code()
            );
            set_test_trm_random_selection_sample(ctx);

            assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired.code());
            let ctx_ref = ctx.as_ref().unwrap();
            assert_eq!(
                ctx_ref.selected_application.as_ref().unwrap().aid,
                [0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]
            );

            let commands = script.commands.lock().unwrap();
            assert_eq!(
                commands[1],
                vec![0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00]
            );
            drop(commands);
            krn_context_free(ctx);
        }
    }

    #[test]
    fn runtime_rejects_final_select_fci_with_mismatched_adf_name() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            let script = SelectionStatusPolicyScript {
                counter: AtomicUsize::new(0),
                mode: 4,
                commands: Mutex::new(Vec::new()),
            };
            let mut ctx = ptr::null_mut();
            let runtime = KrnRuntime {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnRuntime>() as u32,
                transmit_apdu: Some(capture_selection_status_policy_apdu),
                get_unpredictable_number: Some(fill_unpredictable_number),
                contactless_outcome: None,
                user_data: &script as *const SelectionStatusPolicyScript as *mut c_void,
            };
            assert_eq!(
                krn_init(ptr::null(), &runtime, &mut ctx),
                KernelError::Ok.code()
            );
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
                KernelError::Ok.code()
            );
            set_test_trm_random_selection_sample(ctx);

            assert_eq!(krn_run_transaction(ctx), KrnOutcome::Error.code());
            assert_eq!(krn_get_last_error(ctx), KernelError::NoCommonAid.code());
            assert_eq!(krn_get_fsm_state(ctx), FsmState::Se.code());
            assert!(ctx.as_ref().unwrap().selected_application.is_none());

            let commands = script.commands.lock().unwrap();
            assert_eq!(commands.len(), 2);
            assert_eq!(
                commands[1],
                vec![0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00]
            );
            drop(commands);
            krn_context_free(ctx);
        }
    }

    #[test]
    fn runtime_core_flow_resolves_gpo_record_and_gac_followups() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        unsafe {
            let script = SelectionStatusPolicyScript {
                counter: AtomicUsize::new(0),
                mode: 3,
                commands: Mutex::new(Vec::new()),
            };
            let mut ctx = ptr::null_mut();
            let runtime = KrnRuntime {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnRuntime>() as u32,
                transmit_apdu: Some(capture_selection_status_policy_apdu),
                get_unpredictable_number: Some(fill_unpredictable_number),
                contactless_outcome: None,
                user_data: &script as *const SelectionStatusPolicyScript as *mut c_void,
            };
            assert_eq!(
                krn_init(ptr::null(), &runtime, &mut ctx),
                KernelError::Ok.code()
            );
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
                KernelError::Ok.code()
            );
            set_test_trm_random_selection_sample(ctx);

            assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired.code());
            assert_eq!(krn_get_last_error(ctx), KernelError::Ok.code());
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S11.code());

            let commands = script.commands.lock().unwrap();
            assert_eq!(commands.len(), 8);
            assert_eq!(commands[2][1], 0xa8);
            assert_eq!(commands[3], vec![0x00, 0xc0, 0x00, 0x00, 0x0c]);
            assert_eq!(commands[4][1], 0xb2);
            assert_eq!(commands[5][1], 0xc0);
            assert_eq!(commands[6][1], 0xae);
            assert_eq!(*commands[7].last().unwrap(), 0x1c);
            assert_eq!(commands[7][1], 0xae);
            drop(commands);
            krn_context_free(ctx);
        }
    }

    #[test]
    fn ffi_reports_loaded_profile_version_and_hash_for_log_identity() {
        unsafe {
            let ctx = krn_context_new();
            let mut version = 0u64;
            let mut digest = [0u8; KRN_PROFILE_SHA256_LEN];
            let mut digest_len = digest.len();
            assert_eq!(
                krn_get_profile_version(ctx, &mut version),
                KernelError::InvalidProfile.code()
            );
            assert_eq!(
                krn_get_profile_sha256(ctx, digest.as_mut_ptr(), &mut digest_len),
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
            let expected_digest = sha256(include_bytes!("../docs/scheme_profiles.cert.json"));
            digest_len = digest.len() - 1;
            assert_eq!(
                krn_get_profile_sha256(ctx, digest.as_mut_ptr(), &mut digest_len),
                KernelError::BufferTooSmall.code()
            );
            assert_eq!(digest_len, KRN_PROFILE_SHA256_LEN);
            digest_len = digest.len();
            assert_eq!(
                krn_get_profile_sha256(ctx, digest.as_mut_ptr(), &mut digest_len),
                KernelError::Ok.code()
            );
            assert_eq!(digest_len, KRN_PROFILE_SHA256_LEN);
            assert_eq!(digest, expected_digest);
            assert_eq!(
                krn_get_profile_version(ctx, ptr::null_mut()),
                KernelError::InvalidArgument.code()
            );
            assert_eq!(
                krn_get_profile_sha256(ctx, ptr::null_mut(), ptr::null_mut()),
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
                KernelError::Ok.code()
            );
            set_test_trm_random_selection_sample(ctx);
            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_eq!(krn_run_transaction(ctx), KrnOutcome::OnlineRequired.code());
            assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 5);
            assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 30);
            assert_eq!(
                TRANSMIT_TIMEOUT_MS.load(Ordering::SeqCst),
                APDU_TRANSMIT_TIMEOUT_MS
            );
            assert_eq!(krn_get_fsm_state(ctx), FsmState::S11.code());
            assert_eq!(krn_get_last_error(ctx), KernelError::Ok.code());
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
                0x89, 0x06, b'A', b'P', b'P', b'R', b'0', b'1', 0x71, 0x08, 0x86, 0x06, 0x00, 0xda,
                0x00, 0x00, 0x01, 0xaa, 0x72, 0x08, 0x86, 0x06, 0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb,
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
            assert_eq!(ctx_ref.card_data.get(&[0x89]), Some(&b"APPR01"[..]));
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
    fn read_records_retains_ordered_offline_authentication_bodies() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S4;
        ctx.state = KernelState::ReadRecords;
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_offline_auth_record_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        let afl = [
            AflEntry {
                sfi: 2,
                first_record: 1,
                last_record: 1,
                offline_auth_record_count: 1,
            },
            AflEntry {
                sfi: 11,
                first_record: 1,
                last_record: 1,
                offline_auth_record_count: 1,
            },
        ];

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(read_application_records(&mut ctx, runtime, &afl), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S5);
        assert_eq!(ctx.state, KernelState::OfflineDataAuthentication);
        assert_eq!(ctx.offline_auth_records.len(), 2);
        assert_eq!(ctx.offline_auth_records[0].sfi, 2);
        assert_eq!(
            ctx.offline_auth_records[0].body,
            vec![0x70, 0x03, 0x5a, 0x01, 0x99]
        );
        assert_eq!(ctx.offline_auth_records[1].sfi, 11);
        assert_eq!(
            ctx.offline_auth_records[1].body,
            vec![0x70, 0x03, 0x5f, 0x20, 0x00]
        );

        ctx.card_data.put(&[0x9f, 0x4a], &[0x82]).unwrap();
        ctx.card_data.put(&[0x82], &[0x80, 0x00]).unwrap();
        assert_eq!(
            crate::oda::build_static_authentication_data(&ctx.offline_auth_records, &ctx.card_data)
                .unwrap(),
            vec![0x5a, 0x01, 0x99, 0x70, 0x03, 0x5f, 0x20, 0x00, 0x80, 0x00]
        );
    }

    #[test]
    fn read_records_fail_closed_on_empty_short_end_and_tvr_statuses() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: scripted_read_record_status_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        let afl = [AflEntry {
            sfi: 2,
            first_record: 1,
            last_record: 1,
            offline_auth_record_count: 1,
        }];

        let mut empty_ctx = KrnContext::new();
        empty_ctx.fsm_state = FsmState::S4;
        assert_eq!(
            read_application_records(&mut empty_ctx, runtime, &[]),
            Ok(())
        );
        assert_eq!(empty_ctx.fsm_state, FsmState::S5);
        assert_eq!(empty_ctx.state, KernelState::OfflineDataAuthentication);

        let mut short_ctx = KrnContext::new();
        short_ctx.fsm_state = FsmState::S4;
        READ_RECORD_RESPONSE_MODE.store(0, Ordering::SeqCst);
        assert_eq!(
            read_application_records(&mut short_ctx, runtime, &afl).unwrap_err(),
            KernelError::ParseError
        );

        let mut end_ctx = KrnContext::new();
        end_ctx.fsm_state = FsmState::S4;
        READ_RECORD_RESPONSE_MODE.store(1, Ordering::SeqCst);
        assert_eq!(
            read_application_records(&mut end_ctx, runtime, &afl),
            Ok(())
        );
        assert_eq!(end_ctx.fsm_state, FsmState::S5);
        assert!(end_ctx.tvr.is_set(Tvr::B1_ICC_DATA_MISSING));

        let mut tvr_ctx = KrnContext::new();
        tvr_ctx.fsm_state = FsmState::S4;
        READ_RECORD_RESPONSE_MODE.store(2, Ordering::SeqCst);
        assert_eq!(
            read_application_records(&mut tvr_ctx, runtime, &afl),
            Ok(())
        );
        assert_eq!(tvr_ctx.fsm_state, FsmState::S5);
        assert!(tvr_ctx.tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
    }

    #[test]
    fn issuer_authentication_failure_sets_tvr_and_reaches_scripts() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S12;
        ctx.state = KernelState::IssuerAuthentication;
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: Some(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
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
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 13);
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
    fn issuer_authentication_resolves_get_response_followup() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S12;
        ctx.state = KernelState::IssuerAuthentication;
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: Some(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
            scripts: Vec::new(),
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_script_followup_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        FOLLOWUP_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        SCRIPT_FOLLOWUP_MODE.store(4, Ordering::SeqCst);
        assert_eq!(run_issuer_authentication(&mut ctx, runtime), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S13);
        assert_eq!(ctx.state, KernelState::IssuerScripts);
        assert!(ctx.tsi.is_set(Tsi::ISSUER_AUTHENTICATION_PERFORMED));
        assert!(!ctx.tvr.is_set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED));
        assert_eq!(FOLLOWUP_TRANSMIT_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(FOLLOWUP_TRANSMITTED_INS.load(Ordering::SeqCst), 0xc0);
        SCRIPT_FOLLOWUP_MODE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn issuer_script_noncritical_failure_sets_phase_tvr_and_reaches_final() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S13;
        ctx.state = KernelState::IssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
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
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        SCRIPT_SW1.store(0x6a, Ordering::SeqCst);
        SCRIPT_SW2.store(0x80, Ordering::SeqCst);
        assert_eq!(run_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xda);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x00, 0xda, 0x00, 0x00, 0x01, 0xaa]
        );
        assert_eq!(ctx.fsm_state, FsmState::S14);
        assert_eq!(ctx.state, KernelState::SecondGenerateAc);
        assert_eq!(
            ctx.issuer_script_results,
            vec![ScriptCommandResult {
                sw1: 0x6a,
                sw2: 0x80
            }]
        );
        assert_eq!(
            ctx.issuer_script_results[0].phase,
            ScriptPhase::BeforeFinalGenerateAc
        );
        let mut phase = 0u8;
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 0, &mut phase) },
            KernelError::Ok.code()
        );
        assert_eq!(phase, KRN_SCRIPT_PHASE_BEFORE_FINAL_GAC);
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 1, &mut phase) },
            KernelError::InvalidArgument.code()
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
    fn critical_issuer_script_failure_before_final_sets_before_final_tvr_and_stops() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S13;
        ctx.state = KernelState::IssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: None,
            scripts: vec![crate::issuer::IssuerScript {
                phase: crate::issuer::ScriptPhase::BeforeFinalGenerateAc,
                identifier: Some(vec![0xde, 0xad, 0xbe, 0xef]),
                commands: vec![
                    vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb],
                    vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xcc],
                ],
            }],
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(6, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        SCRIPT_SW1.store(0x69, Ordering::SeqCst);
        SCRIPT_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(
            run_issuer_scripts(&mut ctx, runtime),
            Err(KernelError::ScriptFailed)
        );
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 7);
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb]
        );
        assert_eq!(ctx.fsm_state, FsmState::Se);
        assert_eq!(ctx.state, KernelState::Error);
        assert_eq!(
            ctx.issuer_script_results,
            vec![ScriptCommandResult {
                sw1: 0x69,
                sw2: 0x85
            }]
        );
        assert_eq!(
            ctx.issuer_script_results[0].phase,
            ScriptPhase::BeforeFinalGenerateAc
        );
        assert_eq!(ctx.issuer_script_results[0].script_index, 0);
        assert_eq!(ctx.issuer_script_results[0].command_index, 0);
        assert_eq!(
            ctx.issuer_script_results[0].script_identifier,
            Some([0xde, 0xad, 0xbe, 0xef])
        );
        assert!(ctx.tsi.is_set(Tsi::SCRIPT_PROCESSING_PERFORMED));
        assert!(ctx
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC));
        assert!(!ctx
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC));
        assert_eq!(ctx.card_data.get(&[0x9b]), Some(&ctx.tsi.bytes()[..]));
        assert_eq!(ctx.card_data.get(&[0x95]), Some(&ctx.tvr.bytes()[..]));
        SCRIPT_SW1.store(0x90, Ordering::SeqCst);
        SCRIPT_SW2.store(0x00, Ordering::SeqCst);
    }

    #[test]
    fn krn_gac2_004_final_generate_ac_skipped_without_cdol2_honors_host_arc() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        for (arc, expected_outcome) in [
            ([b'0', b'0'], KrnOutcome::ApprovedOnline),
            ([b'0', b'5'], KrnOutcome::DeclinedOnline),
        ] {
            let mut ctx = KrnContext::new();
            ctx.fsm_state = FsmState::S14;
            ctx.state = KernelState::SecondGenerateAc;
            ctx.host_response = Some(HostResponse {
                authorization_response_code: arc,
                authorization_code: None,
                issuer_authentication_data: None,
                scripts: Vec::new(),
            });

            TRANSMIT_COUNT.store(0, Ordering::SeqCst);
            assert_eq!(run_final_generate_ac(&mut ctx, runtime), Ok(()));
            assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 0);
            assert_eq!(ctx.fsm_state, FsmState::S15);
            assert_eq!(ctx.state, KernelState::PostFinalIssuerScripts);
            assert_eq!(ctx.final_outcome, Some(expected_outcome));
            assert!(ctx.final_gac_response.is_none());
        }
    }

    #[test]
    fn final_generate_ac_builds_cdol2_from_host_response_and_state() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S14;
        ctx.state = KernelState::SecondGenerateAc;
        install_profile_selection(&mut ctx);
        let issuer_authentication_data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: Some(issuer_authentication_data.to_vec()),
            scripts: Vec::new(),
        });
        ctx.card_data
            .put(&[0x8d], &[0x8a, 0x02, 0x91, 0x08, 0x95, 0x05, 0x9b, 0x02])
            .unwrap();
        ctx.card_data.put(&[0x8a], b"00").unwrap();
        ctx.card_data
            .put(&[0x91], &issuer_authentication_data)
            .unwrap();
        ctx.tvr.set(Tvr::B5_ISSUER_AUTHENTICATION_FAILED);
        ctx.tsi.set(Tsi::ISSUER_AUTHENTICATION_PERFORMED);
        let expected_tvr = ctx.tvr.bytes();
        let expected_tsi = ctx.tsi.bytes();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_final_generate_ac(&mut ctx, runtime), Ok(()));

        let command = LAST_TRANSMITTED_COMMAND.lock().unwrap().clone();
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(&command[..5], &[0x80, 0xae, 0x40, 0x00, 0x11]);
        assert_eq!(&command[5..7], b"00");
        assert_eq!(&command[7..15], &issuer_authentication_data);
        assert_eq!(&command[15..20], &expected_tvr);
        assert_eq!(&command[20..22], &expected_tsi);
        assert_eq!(command[22], 0x00);
        assert_eq!(ctx.fsm_state, FsmState::S15);
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::ApprovedOnline));
        assert!(ctx.final_gac_response.is_some());
    }

    #[test]
    fn final_generate_ac_uses_authorization_code_from_applied_host_response() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S11;
        ctx.state = KernelState::OnlineAuthorization;
        ctx.card_data
            .put(&[0x8d], &[0x8a, 0x02, 0x89, 0x06, 0x95, 0x05, 0x9b, 0x02])
            .unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        let host = [
            0x8a, 0x02, b'0', b'0', 0x89, 0x06, b'A', b'P', b'P', b'R', b'0', b'1',
        ];
        assert_eq!(apply_host_response(&mut ctx, &host), Ok(()));
        assert_eq!(ctx.card_data.get(&[0x89]), Some(&b"APPR01"[..]));
        assert_eq!(ctx.fsm_state, FsmState::S13);
        assert_eq!(run_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S14);

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_final_generate_ac(&mut ctx, runtime), Ok(()));

        let command = LAST_TRANSMITTED_COMMAND.lock().unwrap().clone();
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(&command[..5], &[0x80, 0xae, 0x40, 0x00, 0x0f]);
        assert_eq!(&command[5..7], b"00");
        assert_eq!(&command[7..13], b"APPR01");
        assert_eq!(&command[13..18], &Tvr::cleared().bytes());
        assert_eq!(&command[18..20], &Tsi::cleared().bytes());
        assert_eq!(command[20], 0x00);
        assert_eq!(ctx.fsm_state, FsmState::S15);
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::ApprovedOnline));
    }

    #[test]
    fn final_gac_preserves_host_response_sources_after_rejected_record_tags() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S11;
        ctx.state = KernelState::OnlineAuthorization;
        ctx.card_data
            .put(&[0x8d], &[0x8a, 0x02, 0x89, 0x06, 0x95, 0x05, 0x9b, 0x02])
            .unwrap();
        let record_with_card_and_host_data = [
            0x70, 0x0f, 0x5a, 0x01, 0x12, 0x89, 0x06, b'B', b'A', b'D', b'9', b'9', b'9', 0x8a,
            0x02, b'0', b'5',
        ];
        assert_eq!(
            parse_read_record_body(&record_with_card_and_host_data, &mut ctx.card_data)
                .unwrap_err(),
            KernelError::ParseError
        );
        assert!(ctx.card_data.get(&[0x5a]).is_none());
        assert!(ctx.card_data.get(&[0x89]).is_none());
        assert!(ctx.card_data.get(&[0x8a]).is_none());

        let host = [
            0x8a, 0x02, b'0', b'0', 0x89, 0x06, b'A', b'P', b'P', b'R', b'0', b'1',
        ];
        assert_eq!(apply_host_response(&mut ctx, &host), Ok(()));
        assert_eq!(ctx.card_data.get(&[0x8a]), Some(&b"00"[..]));
        assert_eq!(ctx.card_data.get(&[0x89]), Some(&b"APPR01"[..]));
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(run_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(ctx.fsm_state, FsmState::S14);

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        assert_eq!(run_final_generate_ac(&mut ctx, runtime), Ok(()));

        let command = LAST_TRANSMITTED_COMMAND.lock().unwrap().clone();
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xae);
        assert_eq!(&command[..5], &[0x80, 0xae, 0x40, 0x00, 0x0f]);
        assert_eq!(&command[5..7], b"00");
        assert_eq!(&command[7..13], b"APPR01");
        assert_eq!(&command[13..18], &Tvr::cleared().bytes());
        assert_eq!(&command[18..20], &Tsi::cleared().bytes());
        assert_eq!(command[20], 0x00);
        assert_eq!(ctx.fsm_state, FsmState::S15);
        assert_eq!(ctx.final_outcome, Some(KrnOutcome::ApprovedOnline));
    }

    #[test]
    fn final_gac_rejects_missing_cdol2_source_without_zero_padding() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S14;
        ctx.state = KernelState::SecondGenerateAc;
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: None,
            scripts: Vec::new(),
        });
        ctx.card_data
            .put(&[0x8d], &[0x8a, 0x02, 0x91, 0x08])
            .unwrap();
        ctx.card_data.put(&[0x8a], b"00").unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(
            run_final_generate_ac(&mut ctx, runtime),
            Err(KernelError::MissingMandatoryTag)
        );
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 0);
    }

    fn prepare_final_gac_context(ctx: &mut KrnContext, arc: [u8; 2]) {
        ctx.fsm_state = FsmState::S14;
        ctx.state = KernelState::SecondGenerateAc;
        ctx.host_response = Some(HostResponse {
            authorization_response_code: arc,
            authorization_code: None,
            issuer_authentication_data: None,
            scripts: Vec::new(),
        });
        ctx.card_data
            .put(&[0x8d], &[0x8a, 0x02, 0x95, 0x05, 0x9b, 0x02])
            .unwrap();
        ctx.card_data.put(&[0x8a], &arc).unwrap();
    }

    #[test]
    fn final_gac_handles_declines_dynamic_numbers_referrals_and_short_responses() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut tc_ctx = KrnContext::new();
        prepare_final_gac_context(&mut tc_ctx, [b'0', b'0']);
        let tc_runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_tc_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(run_final_generate_ac(&mut tc_ctx, tc_runtime), Ok(()));
        assert_eq!(tc_ctx.final_outcome, Some(KrnOutcome::ApprovedOnline));
        assert_eq!(tc_ctx.card_data.get(&[0x9f, 0x4c]), Some(&[1, 2, 3, 4][..]));
        assert_eq!(tc_ctx.fsm_state, FsmState::S15);

        let mut aac_ctx = KrnContext::new();
        prepare_final_gac_context(&mut aac_ctx, [b'0', b'5']);
        let aac_runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_aac_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(run_final_generate_ac(&mut aac_ctx, aac_runtime), Ok(()));
        assert_eq!(aac_ctx.final_outcome, Some(KrnOutcome::DeclinedOnline));
        assert_eq!(aac_ctx.fsm_state, FsmState::S15);

        let mut referral_ctx = KrnContext::new();
        prepare_final_gac_context(&mut referral_ctx, [b'0', b'0']);
        let referral_runtime = RuntimeCallbacks {
            transmit_apdu: capture_cda_referral_generate_ac_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            run_final_generate_ac(&mut referral_ctx, referral_runtime),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(referral_ctx.fsm_state, FsmState::Se);

        let mut short_ctx = KrnContext::new();
        prepare_final_gac_context(&mut short_ctx, [b'0', b'0']);
        let short_runtime = RuntimeCallbacks {
            transmit_apdu: capture_short_apdu_response,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            run_final_generate_ac(&mut short_ctx, short_runtime),
            Err(KernelError::ParseError)
        );
    }

    #[test]
    fn post_final_issuer_script_failure_sets_after_final_tvr_and_completes() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S15;
        ctx.state = KernelState::PostFinalIssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
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
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        SCRIPT_SW1.store(0x69, Ordering::SeqCst);
        SCRIPT_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(run_post_final_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xda);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x80, 0xda, 0x00, 0x00, 0x01, 0xbb]
        );
        assert_eq!(ctx.fsm_state, FsmState::S16);
        assert_eq!(ctx.state, KernelState::FinalOutcome);
        assert_eq!(
            ctx.issuer_script_results,
            vec![ScriptCommandResult {
                sw1: 0x69,
                sw2: 0x85
            }]
        );
        assert_eq!(
            ctx.issuer_script_results[0].phase,
            ScriptPhase::AfterFinalGenerateAc
        );
        let mut phase = 0u8;
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 0, &mut phase) },
            KernelError::Ok.code()
        );
        assert_eq!(phase, KRN_SCRIPT_PHASE_AFTER_FINAL_GAC);
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
    fn issuer_script_result_metadata_api_reports_phase_position_and_identifier() {
        let mut ctx = KrnContext::new();
        ctx.issuer_script_results.extend([
            CapturedIssuerScriptResult {
                phase: ScriptPhase::BeforeFinalGenerateAc,
                script_index: 0,
                command_index: 0,
                script_identifier: Some([0xde, 0xad, 0xbe, 0xef]),
                result: ScriptCommandResult {
                    sw1: 0x90,
                    sw2: 0x00,
                },
            },
            CapturedIssuerScriptResult {
                phase: ScriptPhase::AfterFinalGenerateAc,
                script_index: 1,
                command_index: 2,
                script_identifier: None,
                result: ScriptCommandResult {
                    sw1: 0x69,
                    sw2: 0x85,
                },
            },
        ]);

        let mut phase = 0u8;
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 0, &mut phase) },
            KernelError::Ok.code()
        );
        assert_eq!(phase, KRN_SCRIPT_PHASE_BEFORE_FINAL_GAC);
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 1, &mut phase) },
            KernelError::Ok.code()
        );
        assert_eq!(phase, KRN_SCRIPT_PHASE_AFTER_FINAL_GAC);
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 2, &mut phase) },
            KernelError::InvalidArgument.code()
        );
        assert_eq!(
            unsafe { krn_get_issuer_script_result_phase(&mut ctx, 0, ptr::null_mut()) },
            KernelError::InvalidArgument.code()
        );

        let mut script_index = u16::MAX;
        let mut command_index = u16::MAX;
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_position(
                    &mut ctx,
                    0,
                    &mut script_index,
                    &mut command_index,
                )
            },
            KernelError::Ok.code()
        );
        assert_eq!((script_index, command_index), (0, 0));
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_position(
                    &mut ctx,
                    1,
                    &mut script_index,
                    &mut command_index,
                )
            },
            KernelError::Ok.code()
        );
        assert_eq!((script_index, command_index), (1, 2));
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_position(
                    &mut ctx,
                    2,
                    &mut script_index,
                    &mut command_index,
                )
            },
            KernelError::InvalidArgument.code()
        );
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_position(
                    &mut ctx,
                    0,
                    ptr::null_mut(),
                    &mut command_index,
                )
            },
            KernelError::InvalidArgument.code()
        );
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_position(
                    &mut ctx,
                    0,
                    &mut script_index,
                    ptr::null_mut(),
                )
            },
            KernelError::InvalidArgument.code()
        );

        let mut identifier_len = 0usize;
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_identifier(
                    &mut ctx,
                    0,
                    ptr::null_mut(),
                    &mut identifier_len,
                )
            },
            KernelError::BufferTooSmall.code()
        );
        assert_eq!(identifier_len, KRN_ISSUER_SCRIPT_IDENTIFIER_LEN);
        let mut identifier = [0u8; KRN_ISSUER_SCRIPT_IDENTIFIER_LEN];
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_identifier(
                    &mut ctx,
                    0,
                    identifier.as_mut_ptr(),
                    &mut identifier_len,
                )
            },
            KernelError::Ok.code()
        );
        assert_eq!(identifier, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(identifier_len, KRN_ISSUER_SCRIPT_IDENTIFIER_LEN);
        let mut absent_identifier_len = usize::MAX;
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_identifier(
                    &mut ctx,
                    1,
                    ptr::null_mut(),
                    &mut absent_identifier_len,
                )
            },
            KernelError::Ok.code()
        );
        assert_eq!(absent_identifier_len, 0);
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_identifier(
                    &mut ctx,
                    2,
                    identifier.as_mut_ptr(),
                    &mut identifier_len,
                )
            },
            KernelError::InvalidArgument.code()
        );
        assert_eq!(
            unsafe {
                krn_get_issuer_script_result_identifier(
                    &mut ctx,
                    0,
                    identifier.as_mut_ptr(),
                    ptr::null_mut(),
                )
            },
            KernelError::InvalidArgument.code()
        );
    }

    #[test]
    fn critical_issuer_script_warning_continues_and_reports_results() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S15;
        ctx.state = KernelState::PostFinalIssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: None,
            scripts: vec![crate::issuer::IssuerScript {
                phase: crate::issuer::ScriptPhase::AfterFinalGenerateAc,
                identifier: None,
                commands: vec![
                    vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb],
                    vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xcc],
                ],
            }],
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        SCRIPT_SW1.store(0x63, Ordering::SeqCst);
        SCRIPT_SW2.store(0xc1, Ordering::SeqCst);
        assert_eq!(run_post_final_issuer_scripts(&mut ctx, runtime), Ok(()));
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 10);
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xe2);
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x80, 0xe2, 0x00, 0x00, 0x01, 0xcc]
        );
        assert_eq!(ctx.fsm_state, FsmState::S16);
        assert_eq!(ctx.state, KernelState::FinalOutcome);
        assert_eq!(
            ctx.issuer_script_results,
            vec![
                ScriptCommandResult {
                    sw1: 0x63,
                    sw2: 0xc1
                },
                ScriptCommandResult {
                    sw1: 0x63,
                    sw2: 0xc1
                }
            ]
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
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
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
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        SCRIPT_SW1.store(0x69, Ordering::SeqCst);
        SCRIPT_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(
            run_post_final_issuer_scripts(&mut ctx, runtime),
            Err(KernelError::ScriptFailed)
        );
        assert_eq!(TRANSMITTED_INS.load(Ordering::SeqCst), 0xe2);
        assert_eq!(TRANSMITTED_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb]
        );
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
    fn critical_issuer_script_failure_stops_remaining_commands() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        ctx.fsm_state = FsmState::S15;
        ctx.state = KernelState::PostFinalIssuerScripts;
        install_profile_selection(&mut ctx);
        ctx.host_response = Some(HostResponse {
            authorization_response_code: [b'0', b'0'],
            authorization_code: None,
            issuer_authentication_data: None,
            scripts: vec![crate::issuer::IssuerScript {
                phase: crate::issuer::ScriptPhase::AfterFinalGenerateAc,
                identifier: None,
                commands: vec![
                    vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb],
                    vec![0x80, 0xe2, 0x00, 0x00, 0x01, 0xcc],
                ],
            }],
        });
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_select_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        TRANSMIT_COUNT.store(8, Ordering::SeqCst);
        LAST_TRANSMITTED_COMMAND.lock().unwrap().clear();
        SCRIPT_SW1.store(0x69, Ordering::SeqCst);
        SCRIPT_SW2.store(0x85, Ordering::SeqCst);
        assert_eq!(
            run_post_final_issuer_scripts(&mut ctx, runtime),
            Err(KernelError::ScriptFailed)
        );
        assert_eq!(TRANSMIT_COUNT.load(Ordering::SeqCst), 9);
        assert_eq!(
            LAST_TRANSMITTED_COMMAND.lock().unwrap().as_slice(),
            &[0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb]
        );
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
                authorization_response_code: [b'0', b'0'],
                authorization_code: None,
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

    #[test]
    fn transmit_apdu_followups_rejects_chains_above_limit() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let runtime = RuntimeCallbacks {
            transmit_apdu: capture_script_followup_apdu,
            get_unpredictable_number: fill_unpredictable_number,
            contactless_outcome: None,
            user_data: ptr::null_mut(),
        };

        FOLLOWUP_TRANSMIT_COUNT.store(0, Ordering::SeqCst);
        SCRIPT_FOLLOWUP_MODE.store(3, Ordering::SeqCst);
        let result = transmit_apdu_with_followups(
            runtime,
            &[0x00, 0xb2, 0x01, 0x0c, 0x00],
            APDU_TRANSMIT_TIMEOUT_MS,
            ApduContext::ReadRecord,
        );

        assert_eq!(result.unwrap_err(), KernelError::LengthOverflow);
        assert_eq!(
            FOLLOWUP_TRANSMIT_COUNT.load(Ordering::SeqCst),
            MAX_APDU_FOLLOWUPS + 1
        );
        assert_eq!(FOLLOWUP_TRANSMITTED_INS.load(Ordering::SeqCst), 0xc0);
        assert_eq!(FOLLOWUP_TRANSMITTED_LEN.load(Ordering::SeqCst), 5);
        SCRIPT_FOLLOWUP_MODE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn certification_bundle_loader_sets_profile_hash_bundle_hash_and_timeout_policy() {
        let _guard = FFI_TEST_LOCK.lock().unwrap();
        let mut ctx = KrnContext::new();
        let bundle = include_bytes!("../docs/certification_data_bundle.json");
        let trust = include_bytes!("../docs/certification_data_bundle_trust_anchors.json");

        unsafe {
            assert_eq!(
                krn_load_certification_bundle_verified(
                    &mut ctx,
                    bundle.as_ptr(),
                    bundle.len(),
                    trust.as_ptr(),
                    trust.len(),
                    1,
                    26,
                    5,
                    25,
                ),
                KernelError::Ok.code()
            );

            let mut bundle_digest = [0u8; KRN_PROFILE_SHA256_LEN];
            let mut bundle_digest_len = bundle_digest.len();
            assert_eq!(
                krn_get_certification_bundle_sha256(
                    &ctx,
                    bundle_digest.as_mut_ptr(),
                    &mut bundle_digest_len,
                ),
                KernelError::Ok.code()
            );
            assert_eq!(bundle_digest_len, KRN_PROFILE_SHA256_LEN);
            assert_eq!(bundle_digest, sha256(bundle));

            let mut profile_digest = [0u8; KRN_PROFILE_SHA256_LEN];
            let mut profile_digest_len = profile_digest.len();
            assert_eq!(
                krn_get_profile_sha256(
                    &mut ctx,
                    profile_digest.as_mut_ptr(),
                    &mut profile_digest_len,
                ),
                KernelError::Ok.code()
            );
            assert_eq!(profile_digest_len, KRN_PROFILE_SHA256_LEN);
            assert_eq!(ctx.profiles.as_ref().unwrap().version, 2);

            let mut policy = KrnCallbackTimeoutPolicy {
                abi_version: KRN_ABI_VERSION,
                struct_size: mem::size_of::<KrnCallbackTimeoutPolicy>() as u32,
                min_timeout_ms: 0,
                max_timeout_ms: 0,
                apdu_transport_timeout_ms: 0,
                host_authorization_timeout_ms: 0,
                pin_entry_timeout_ms: 0,
                contactless_ui_timeout_ms: 0,
            };
            assert_eq!(
                krn_get_context_callback_timeout_policy(&ctx, &mut policy),
                KernelError::Ok.code()
            );
            assert_eq!(policy.apdu_transport_timeout_ms, 500);
            assert_eq!(policy.host_authorization_timeout_ms, 30_000);
        }
    }
}
