use crate::error::KernelError;
use crate::state::Tvr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusWord {
    pub sw1: u8,
    pub sw2: u8,
}

impl StatusWord {
    pub fn new(sw1: u8, sw2: u8) -> Self {
        Self { sw1, sw2 }
    }

    pub fn is_success(self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApduContext {
    SelectPse,
    SelectAid,
    Gpo,
    ReadRecord,
    Verify,
    GenerateAc,
    IssuerScript { critical: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusAction {
    Success,
    GetResponse { length: u8 },
    RetryWithLe { length: u8 },
    FallbackToDirectAid,
    TryNextAid,
    EndOfRecords,
    ContinueWithTvr { bit: (usize, u8) },
    PinFailed { tries_remaining: u8 },
    ContinueAfterNonCriticalScriptFailure,
    Fail { error: KernelError },
}

pub fn classify(context: ApduContext, sw: StatusWord) -> StatusAction {
    if sw.is_success() {
        return StatusAction::Success;
    }
    if sw.sw1 == 0x61 {
        return StatusAction::GetResponse { length: sw.sw2 };
    }
    if sw.sw1 == 0x6c {
        return StatusAction::RetryWithLe { length: sw.sw2 };
    }

    match (context, sw.sw1, sw.sw2) {
        (ApduContext::SelectPse, 0x6a, 0x82) => StatusAction::FallbackToDirectAid,
        (ApduContext::SelectPse, _, _) => StatusAction::Fail {
            error: KernelError::NoCommonAid,
        },
        (ApduContext::SelectAid, 0x6a, 0x82) | (ApduContext::SelectAid, 0x62, 0x83) => {
            StatusAction::TryNextAid
        }
        (ApduContext::SelectAid, _, _) => StatusAction::TryNextAid,
        (ApduContext::Gpo, 0x69, 0x85) => StatusAction::Fail {
            error: KernelError::MissingMandatoryTag,
        },
        (ApduContext::Gpo, _, _) => StatusAction::Fail {
            error: KernelError::MissingMandatoryTag,
        },
        (ApduContext::ReadRecord, 0x6a, 0x83) => StatusAction::EndOfRecords,
        (ApduContext::ReadRecord, _, _) => StatusAction::ContinueWithTvr {
            bit: Tvr::B1_ICC_DATA_MISSING,
        },
        (ApduContext::Verify, 0x63, sw2) if sw2 & 0xf0 == 0xc0 => StatusAction::PinFailed {
            tries_remaining: sw2 & 0x0f,
        },
        (ApduContext::Verify, _, _) => StatusAction::Fail {
            error: KernelError::InvalidArgument,
        },
        (ApduContext::GenerateAc, _, _) => StatusAction::Fail {
            error: KernelError::CardRemoved,
        },
        (ApduContext::IssuerScript { critical: false }, 0x63, _)
        | (ApduContext::IssuerScript { critical: false }, 0x6a, _)
        | (ApduContext::IssuerScript { critical: false }, 0x69, _) => {
            StatusAction::ContinueAfterNonCriticalScriptFailure
        }
        (ApduContext::IssuerScript { critical: true }, _, _) => StatusAction::Fail {
            error: KernelError::ScriptFailed,
        },
        (ApduContext::IssuerScript { critical: false }, _, _) => {
            StatusAction::ContinueAfterNonCriticalScriptFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_success_and_transport_followups_before_context_rules() {
        assert_eq!(
            classify(ApduContext::Gpo, StatusWord::new(0x90, 0x00)),
            StatusAction::Success
        );
        assert_eq!(
            classify(ApduContext::ReadRecord, StatusWord::new(0x61, 0x1a)),
            StatusAction::GetResponse { length: 0x1a }
        );
        assert_eq!(
            classify(ApduContext::ReadRecord, StatusWord::new(0x6c, 0x20)),
            StatusAction::RetryWithLe { length: 0x20 }
        );
    }

    #[test]
    fn select_status_words_are_state_specific() {
        assert_eq!(
            classify(ApduContext::SelectPse, StatusWord::new(0x6a, 0x82)),
            StatusAction::FallbackToDirectAid
        );
        assert_eq!(
            classify(ApduContext::SelectAid, StatusWord::new(0x6a, 0x82)),
            StatusAction::TryNextAid
        );
    }

    #[test]
    fn read_record_status_words_continue_or_end_without_generic_failure() {
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
    }

    #[test]
    fn verify_and_script_status_words_keep_their_own_meaning() {
        assert_eq!(
            classify(ApduContext::Verify, StatusWord::new(0x63, 0xc2)),
            StatusAction::PinFailed { tries_remaining: 2 }
        );
        assert_eq!(
            classify(
                ApduContext::IssuerScript { critical: false },
                StatusWord::new(0x6a, 0x80)
            ),
            StatusAction::ContinueAfterNonCriticalScriptFailure
        );
        assert_eq!(
            classify(
                ApduContext::IssuerScript { critical: true },
                StatusWord::new(0x6a, 0x80)
            ),
            StatusAction::Fail {
                error: KernelError::ScriptFailed
            }
        );
    }
}
