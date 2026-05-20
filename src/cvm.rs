use crate::error::{KernelError, KernelResult};
use crate::state::Tvr;

pub const MAX_CVM_RULES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvmAction {
    NoCvm,
    OnlinePin,
    Signature,
    OfflinePlaintextPin { ped_handle: PedPinHandle },
    OfflineEncipheredPin { ped_handle: PedPinHandle },
    Cdcvm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

pub fn parse_cvm_list(input: &[u8]) -> KernelResult<CvmList> {
    if input.len() < 8 || (input.len() - 8) % 2 != 0 {
        return Err(KernelError::ParseError);
    }
    let rule_count = (input.len() - 8) / 2;
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

pub fn evaluate(
    list: &CvmList,
    context: CvmContext,
    offline_pin_handle: Option<PedPinHandle>,
) -> CvmOutcome {
    for rule in &list.rules {
        if !condition_matches(*rule, list, context) {
            continue;
        }

        let Some(action) = action_for_method(rule.method, context, offline_pin_handle) else {
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
    offline_pin_handle: Option<PedPinHandle>,
) -> Option<CvmAction> {
    match method {
        CvmMethod::NoCvmRequired => Some(CvmAction::NoCvm),
        CvmMethod::OnlinePin if context.online_pin_supported => Some(CvmAction::OnlinePin),
        CvmMethod::Signature if context.signature_supported => Some(CvmAction::Signature),
        CvmMethod::OfflinePlaintextPin if context.offline_pin_supported => {
            offline_pin_handle.map(|ped_handle| CvmAction::OfflinePlaintextPin { ped_handle })
        }
        CvmMethod::OfflineEncipheredPin if context.offline_pin_supported => {
            offline_pin_handle.map(|ped_handle| CvmAction::OfflineEncipheredPin { ped_handle })
        }
        CvmMethod::OfflinePlaintextPinAndSignature
            if context.offline_pin_supported && context.signature_supported =>
        {
            offline_pin_handle.map(|ped_handle| CvmAction::OfflinePlaintextPin { ped_handle })
        }
        CvmMethod::OfflineEncipheredPinAndSignature
            if context.offline_pin_supported && context.signature_supported =>
        {
            offline_pin_handle.map(|ped_handle| CvmAction::OfflineEncipheredPin { ped_handle })
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
    fn offline_pin_requires_ped_owned_opaque_handle() {
        let list = parse_cvm_list(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00]).unwrap();
        let failed = evaluate(&list, context(), None);
        assert_eq!(
            failed,
            CvmOutcome::Failed {
                cvm_results: [0x01, 0x00, 0x01],
                tvr_bit: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL
            }
        );

        let handle = PedPinHandle::new(0xfeed_beef).unwrap();
        assert_eq!(
            evaluate(&list, context(), Some(handle)),
            CvmOutcome::Selected {
                action: CvmAction::OfflinePlaintextPin { ped_handle: handle },
                cvm_results: [0x01, 0x00, 0x02]
            }
        );
    }

    #[test]
    fn amount_conditions_are_enforced() {
        let list = parse_cvm_list(&[
            0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x27, 0x10, 0x02, 0x07, 0x1f, 0x00,
        ])
        .unwrap();
        assert_eq!(
            evaluate(&list, context(), None),
            CvmOutcome::Selected {
                action: CvmAction::NoCvm,
                cvm_results: [0x1f, 0x00, 0x02]
            }
        );

        let mut high_amount = context();
        high_amount.amount_authorized = 6_000;
        assert_eq!(
            evaluate(&list, high_amount, None),
            CvmOutcome::Selected {
                action: CvmAction::OnlinePin,
                cvm_results: [0x02, 0x07, 0x02]
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
            evaluate(&list, ctx, None),
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
