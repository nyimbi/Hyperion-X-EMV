use crate::error::{KernelError, KernelResult};
use crate::state::Tvr;
use crate::sw::{classify, ApduContext, StatusAction, StatusWord};
use core::fmt;

pub const MAX_CVM_RULES: usize = 64;
const CVM_LIST_AMOUNT_BYTES: usize = 8;
const CVM_RULE_BYTES: usize = 2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PedPinHandle(u64);

impl PedPinHandle {
    pub fn new(raw: u64) -> KernelResult<Self> {
        if raw == 0 {
            return Err(KernelError::InvalidArgument);
        }
        Ok(Self(raw))
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PedPinHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PedPinHandle")
            .field(
                "data_policy",
                &"opaque PED handle redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvmMethod {
    OfflinePlaintextPin,
    OnlinePin,
    OfflinePlaintextPinAndSignature,
    OfflineEncipheredPin,
    OfflineEncipheredPinAndSignature,
    Signature,
    FailCvmProcessing,
    NoCvmRequired,
    SchemeSpecific(u8),
    Unknown(u8),
}

impl CvmMethod {
    pub fn from_code(code: u8) -> Self {
        match code & 0x3f {
            0x01 => Self::OfflinePlaintextPin,
            0x02 => Self::OnlinePin,
            0x03 => Self::OfflinePlaintextPinAndSignature,
            0x04 => Self::OfflineEncipheredPin,
            0x05 => Self::OfflineEncipheredPinAndSignature,
            0x06 => Self::Signature,
            0x1e => Self::FailCvmProcessing,
            0x1f => Self::NoCvmRequired,
            method @ 0x20..=0x3f => Self::SchemeSpecific(method),
            method => Self::Unknown(method),
        }
    }

    pub fn requires_offline_pin(self) -> bool {
        matches!(
            self,
            Self::OfflinePlaintextPin
                | Self::OfflinePlaintextPinAndSignature
                | Self::OfflineEncipheredPin
                | Self::OfflineEncipheredPinAndSignature
        )
    }

    pub fn requires_signature(self) -> bool {
        matches!(
            self,
            Self::OfflinePlaintextPinAndSignature
                | Self::OfflineEncipheredPinAndSignature
                | Self::Signature
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CvmRule {
    pub raw_code: u8,
    pub method: CvmMethod,
    pub condition_code: u8,
}

impl CvmRule {
    pub fn continue_on_failure(self) -> bool {
        self.raw_code & 0x40 != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CvmList {
    pub amount_x: u32,
    pub amount_y: u32,
    pub rules: Vec<CvmRule>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interface {
    Contact,
    Contactless,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CvmContext {
    pub amount_authorized: u64,
    pub transaction_currency_matches_application: bool,
    pub interface: Interface,
    pub offline_pin_supported: bool,
    pub online_pin_supported: bool,
    pub signature_supported: bool,
    pub cdcvm_performed: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CvmAction {
    NoCvm,
    OnlinePin,
    Signature,
    OfflinePlaintextPin { ped_handle: PedPinHandle },
    OfflineEncipheredPin { ped_handle: PedPinHandle },
    Cdcvm,
}

impl fmt::Debug for CvmAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCvm => f.write_str("NoCvm"),
            Self::OnlinePin => f.write_str("OnlinePin"),
            Self::Signature => f.write_str("Signature"),
            Self::OfflinePlaintextPin { .. } => f
                .debug_struct("OfflinePlaintextPin")
                .field("ped_handle", &"redacted")
                .finish(),
            Self::OfflineEncipheredPin { .. } => f
                .debug_struct("OfflineEncipheredPin")
                .field("ped_handle", &"redacted")
                .finish(),
            Self::Cdcvm => f.write_str("Cdcvm"),
        }
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct CvmPinHandles {
    pub offline_plaintext: Option<PedPinHandle>,
    pub offline_enciphered: Option<PedPinHandle>,
}

impl fmt::Debug for CvmPinHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CvmPinHandles")
            .field(
                "offline_plaintext_present",
                &self.offline_plaintext.is_some(),
            )
            .field(
                "offline_enciphered_present",
                &self.offline_enciphered.is_some(),
            )
            .field(
                "data_policy",
                &"opaque PED handles redacted for crash safety",
            )
            .finish()
    }
}

impl CvmPinHandles {
    pub fn none() -> Self {
        Self {
            offline_plaintext: None,
            offline_enciphered: None,
        }
    }

    pub fn with_offline_plaintext(handle: PedPinHandle) -> Self {
        Self {
            offline_plaintext: Some(handle),
            offline_enciphered: None,
        }
    }

    pub fn with_offline_enciphered(handle: PedPinHandle) -> Self {
        Self {
            offline_plaintext: None,
            offline_enciphered: Some(handle),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CvmOutcome {
    Selected {
        action: CvmAction,
        cvm_results: [u8; 3],
    },
    Failed {
        cvm_results: [u8; 3],
        tvr_bit: (usize, u8),
    },
}

impl fmt::Debug for CvmOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected {
                action,
                cvm_results,
            } => f
                .debug_struct("Selected")
                .field("action", action)
                .field("cvm_results", cvm_results)
                .field(
                    "data_policy",
                    &"opaque PED handles redacted for crash safety",
                )
                .finish(),
            Self::Failed {
                cvm_results,
                tvr_bit,
            } => f
                .debug_struct("Failed")
                .field("cvm_results", cvm_results)
                .field("tvr_bit", tvr_bit)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflinePinVerifyOutcome {
    pub cvm_results: [u8; 3],
    pub tries_remaining: Option<u8>,
    pub tvr_bit: Option<(usize, u8)>,
}

pub fn parse_cvm_list(input: &[u8]) -> KernelResult<CvmList> {
    if input.len() < CVM_LIST_AMOUNT_BYTES
        || (input.len() - CVM_LIST_AMOUNT_BYTES) % CVM_RULE_BYTES != 0
    {
        return Err(KernelError::ParseError);
    }
    let rule_count = (input.len() - CVM_LIST_AMOUNT_BYTES) / CVM_RULE_BYTES;
    if rule_count > MAX_CVM_RULES {
        return Err(KernelError::LengthOverflow);
    }

    let amount_x = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let amount_y = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
    let mut rules = Vec::with_capacity(rule_count);
    for pair in input[8..].chunks_exact(2) {
        let raw_code = pair[0];
        rules.push(CvmRule {
            raw_code,
            method: CvmMethod::from_code(raw_code),
            condition_code: pair[1],
        });
    }

    Ok(CvmList {
        amount_x,
        amount_y,
        rules,
    })
}

pub fn apply_offline_pin_verify_status(
    rule: CvmRule,
    sw: StatusWord,
) -> KernelResult<OfflinePinVerifyOutcome> {
    if !rule.method.requires_offline_pin() {
        return Err(KernelError::InvalidArgument);
    }

    match classify(ApduContext::Verify, sw) {
        StatusAction::Success => Ok(OfflinePinVerifyOutcome {
            cvm_results: cvm_results(rule, 0x02),
            tries_remaining: None,
            tvr_bit: None,
        }),
        StatusAction::PinFailed { tries_remaining } => Ok(OfflinePinVerifyOutcome {
            cvm_results: cvm_results(rule, 0x01),
            tries_remaining: Some(tries_remaining),
            tvr_bit: Some(if tries_remaining == 0 {
                Tvr::B3_PIN_TRY_LIMIT_EXCEEDED
            } else {
                Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
            }),
        }),
        StatusAction::Fail { error } => Err(error),
        StatusAction::GetResponse { .. }
        | StatusAction::RetryWithLe { .. }
        | StatusAction::FallbackToDirectAid
        | StatusAction::TryNextAid
        | StatusAction::EndOfRecords
        | StatusAction::ContinueWithTvr { .. }
        | StatusAction::ContinueAfterNonCriticalScriptFailure => Err(KernelError::InvalidArgument),
    }
}

pub fn evaluate(list: &CvmList, context: CvmContext, pin_handles: CvmPinHandles) -> CvmOutcome {
    for rule in &list.rules {
        if !condition_matches(*rule, list, context) {
            continue;
        }

        let Some(action) = action_for_method(rule.method, context, pin_handles) else {
            if rule.continue_on_failure() {
                continue;
            }
            return cvm_failed(*rule);
        };

        return CvmOutcome::Selected {
            action,
            cvm_results: cvm_results(*rule, 0x02),
        };
    }

    CvmOutcome::Failed {
        cvm_results: [0x3f, 0x00, 0x01],
        tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL,
    }
}

fn action_for_method(
    method: CvmMethod,
    context: CvmContext,
    pin_handles: CvmPinHandles,
) -> Option<CvmAction> {
    match method {
        CvmMethod::NoCvmRequired => Some(CvmAction::NoCvm),
        CvmMethod::OnlinePin if context.online_pin_supported => Some(CvmAction::OnlinePin),
        CvmMethod::Signature if context.signature_supported => Some(CvmAction::Signature),
        CvmMethod::OfflinePlaintextPin if context.offline_pin_supported => pin_handles
            .offline_plaintext
            .map(|ped_handle| CvmAction::OfflinePlaintextPin { ped_handle }),
        CvmMethod::OfflineEncipheredPin if context.offline_pin_supported => pin_handles
            .offline_enciphered
            .map(|ped_handle| CvmAction::OfflineEncipheredPin { ped_handle }),
        CvmMethod::OfflinePlaintextPinAndSignature
            if context.offline_pin_supported && context.signature_supported =>
        {
            pin_handles
                .offline_plaintext
                .map(|ped_handle| CvmAction::OfflinePlaintextPin { ped_handle })
        }
        CvmMethod::OfflineEncipheredPinAndSignature
            if context.offline_pin_supported && context.signature_supported =>
        {
            pin_handles
                .offline_enciphered
                .map(|ped_handle| CvmAction::OfflineEncipheredPin { ped_handle })
        }
        CvmMethod::SchemeSpecific(_)
            if context.interface == Interface::Contactless && context.cdcvm_performed =>
        {
            Some(CvmAction::Cdcvm)
        }
        CvmMethod::FailCvmProcessing => None,
        _ => None,
    }
}

fn cvm_failed(rule: CvmRule) -> CvmOutcome {
    CvmOutcome::Failed {
        cvm_results: cvm_results(rule, 0x01),
        tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL,
    }
}

fn cvm_results(rule: CvmRule, result: u8) -> [u8; 3] {
    [rule.raw_code & 0x3f, rule.condition_code, result]
}

fn condition_matches(rule: CvmRule, list: &CvmList, context: CvmContext) -> bool {
    match rule.condition_code {
        0x00 => true,
        0x06 => {
            context.transaction_currency_matches_application
                && context.amount_authorized < list.amount_x as u64
        }
        0x07 => {
            context.transaction_currency_matches_application
                && context.amount_authorized > list.amount_x as u64
        }
        0x08 => {
            context.transaction_currency_matches_application
                && context.amount_authorized < list.amount_y as u64
        }
        0x09 => {
            context.transaction_currency_matches_application
                && context.amount_authorized > list.amount_y as u64
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CvmContext {
        CvmContext {
            amount_authorized: 1_000,
            transaction_currency_matches_application: true,
            interface: Interface::Contact,
            offline_pin_supported: true,
            online_pin_supported: true,
            signature_supported: true,
            cdcvm_performed: false,
        }
    }

    #[test]
    fn parses_cvm_list_amounts_and_certified_method_codes() {
        let list = parse_cvm_list(&[
            0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x27, 0x10, 0x01, 0x00, 0x02, 0x07, 0x1f, 0x00,
        ])
        .unwrap();
        assert_eq!(list.amount_x, 5_000);
        assert_eq!(list.amount_y, 10_000);
        assert_eq!(list.rules[0].method, CvmMethod::OfflinePlaintextPin);
        assert_eq!(list.rules[1].method, CvmMethod::OnlinePin);
        assert_eq!(list.rules[2].method, CvmMethod::NoCvmRequired);
    }

    #[test]
    fn rejects_cvm_lists_above_rule_limit() {
        let mut cvm_list = vec![0x00; CVM_LIST_AMOUNT_BYTES];
        for _ in 0..=MAX_CVM_RULES {
            cvm_list.extend_from_slice(&[0x1f, 0x00]);
        }

        assert_eq!(
            parse_cvm_list(&cvm_list).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn maps_certified_cvm_method_code_table_and_masks_continue_bit() {
        for (code, method) in [
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
            assert_eq!(CvmMethod::from_code(code), method);
            assert_eq!(CvmMethod::from_code(code | 0x40), method);
        }

        assert_eq!(CvmMethod::from_code(0x00), CvmMethod::Unknown(0x00));
        assert_eq!(CvmMethod::from_code(0x07), CvmMethod::Unknown(0x07));

        let list = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x42, 0x00]).unwrap();
        let rule = list.rules[0];
        assert_eq!(rule.method, CvmMethod::OnlinePin);
        assert!(rule.continue_on_failure());
    }

    #[test]
    fn offline_pin_requires_ped_owned_opaque_handle() {
        let list = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00]).unwrap();
        let failed = evaluate(&list, context(), CvmPinHandles::none());
        assert_eq!(
            failed,
            CvmOutcome::Failed {
                cvm_results: [0x01, 0x00, 0x01],
                tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
            }
        );

        let handle = PedPinHandle::new(0xfeed_beef).unwrap();
        assert_eq!(
            evaluate(
                &list,
                context(),
                CvmPinHandles::with_offline_plaintext(handle)
            ),
            CvmOutcome::Selected {
                action: CvmAction::OfflinePlaintextPin { ped_handle: handle },
                cvm_results: [0x01, 0x00, 0x02]
            }
        );

        let enciphered_only = CvmPinHandles::with_offline_enciphered(handle);
        assert_eq!(
            evaluate(&list, context(), enciphered_only),
            CvmOutcome::Failed {
                cvm_results: [0x01, 0x00, 0x01],
                tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
            }
        );
    }

    #[test]
    fn offline_pin_debug_redacts_ped_handle_values() {
        let handle = PedPinHandle::new(0xfeed_beef).unwrap();
        let handles = CvmPinHandles::with_offline_plaintext(handle);
        let action = CvmAction::OfflinePlaintextPin { ped_handle: handle };
        let outcome = CvmOutcome::Selected {
            action,
            cvm_results: [0x01, 0x00, 0x02],
        };

        for debug in [
            format!("{handle:?}"),
            format!("{handles:?}"),
            format!("{action:?}"),
            format!("{outcome:?}"),
        ] {
            assert!(debug.contains("redacted"));
            assert!(!debug.contains("feed"));
            assert!(!debug.contains("beef"));
            assert!(!debug.contains("4276993775"));
        }
    }

    #[test]
    fn offline_pin_verify_status_updates_cvm_results_and_tvr_bits() {
        let rule = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00])
            .unwrap()
            .rules[0];

        assert_eq!(
            apply_offline_pin_verify_status(rule, StatusWord::new(0x90, 0x00)).unwrap(),
            OfflinePinVerifyOutcome {
                cvm_results: [0x01, 0x00, 0x02],
                tries_remaining: None,
                tvr_bit: None,
            }
        );
        assert_eq!(
            apply_offline_pin_verify_status(rule, StatusWord::new(0x63, 0xc2)).unwrap(),
            OfflinePinVerifyOutcome {
                cvm_results: [0x01, 0x00, 0x01],
                tries_remaining: Some(2),
                tvr_bit: Some(Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL),
            }
        );
        assert_eq!(
            apply_offline_pin_verify_status(rule, StatusWord::new(0x63, 0xc0)).unwrap(),
            OfflinePinVerifyOutcome {
                cvm_results: [0x01, 0x00, 0x01],
                tries_remaining: Some(0),
                tvr_bit: Some(Tvr::B3_PIN_TRY_LIMIT_EXCEEDED),
            }
        );
        assert_eq!(
            apply_offline_pin_verify_status(rule, StatusWord::new(0x69, 0x85)).unwrap_err(),
            KernelError::InvalidArgument
        );

        let no_cvm_rule = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x00])
            .unwrap()
            .rules[0];
        assert_eq!(
            apply_offline_pin_verify_status(no_cvm_rule, StatusWord::new(0x90, 0x00)).unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn amount_conditions_are_enforced() {
        let list = parse_cvm_list(&[
            0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x27, 0x10, 0x02, 0x07, 0x1f, 0x00,
        ])
        .unwrap();
        assert_eq!(
            evaluate(&list, context(), CvmPinHandles::none()),
            CvmOutcome::Selected {
                action: CvmAction::NoCvm,
                cvm_results: [0x1f, 0x00, 0x02]
            }
        );

        let mut high_amount = context();
        high_amount.amount_authorized = 6_000;
        assert_eq!(
            evaluate(&list, high_amount, CvmPinHandles::none()),
            CvmOutcome::Selected {
                action: CvmAction::OnlinePin,
                cvm_results: [0x02, 0x07, 0x02]
            }
        );
    }

    #[test]
    fn continue_on_failure_skips_to_next_matching_cvm_rule() {
        let list = parse_cvm_list(&[
            0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x27, 0x10, 0x41, 0x00, 0x02, 0x00,
        ])
        .unwrap();

        let mut no_offline_pin = context();
        no_offline_pin.offline_pin_supported = false;

        assert_eq!(
            evaluate(&list, no_offline_pin, CvmPinHandles::none()),
            CvmOutcome::Selected {
                action: CvmAction::OnlinePin,
                cvm_results: [0x02, 0x00, 0x02]
            }
        );
    }

    #[test]
    fn contactless_scheme_specific_cdcvm_is_profile_context_driven() {
        let list = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x00]).unwrap();
        let mut ctx = context();
        ctx.interface = Interface::Contactless;
        ctx.cdcvm_performed = true;

        assert_eq!(
            evaluate(&list, ctx, CvmPinHandles::none()),
            CvmOutcome::Selected {
                action: CvmAction::Cdcvm,
                cvm_results: [0x20, 0x00, 0x02]
            }
        );
    }

    #[test]
    fn rejects_zero_ped_handle_and_malformed_lists() {
        assert_eq!(
            PedPinHandle::new(0).unwrap_err(),
            KernelError::InvalidArgument
        );
        assert_eq!(
            parse_cvm_list(&[0, 1]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01]).unwrap_err(),
            KernelError::ParseError
        );
    }
}
