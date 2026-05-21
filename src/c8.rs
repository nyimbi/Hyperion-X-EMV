use crate::error::{KernelError, KernelResult};

pub const MAX_C8_DATA_RECORD_LEN: usize = 252;
pub const MAX_C8_DISCRETIONARY_DATA_LEN: usize = 252;
pub const MAX_RELAY_RESISTANCE_APDU_LEN: usize = 261;
pub const MAX_RELAY_RESISTANCE_RESPONSE_LEN: usize = 258;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContactlessOutcomeCode {
    Approved = 1,
    Declined = 2,
    OnlineRequired = 3,
    TryAgain = 4,
    SelectNext = 5,
    AlternateInterface = 6,
    Terminate = 7,
    CvmRequired = 8,
    ProfileDefined = 255,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StartSignal {
    None = 0,
    Start = 1,
    Restart = 2,
    Prompt = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UiStatus {
    None = 0,
    ReadyToRead = 1,
    Processing = 2,
    Approved = 3,
    Declined = 4,
    Error = 5,
    TryAgain = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AlternateInterface {
    None = 0,
    Contact = 1,
    Magstripe = 2,
    OtherCard = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiRequest {
    pub message_id: u16,
    pub status: UiStatus,
    pub hold_time_ms: u16,
}

impl UiRequest {
    pub fn none() -> Self {
        Self {
            message_id: 0,
            status: UiStatus::None,
            hold_time_ms: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactlessOutcome {
    pub outcome_code: ContactlessOutcomeCode,
    pub start_signal: StartSignal,
    pub ui: UiRequest,
    pub restart_required: bool,
    pub data_record: Vec<u8>,
    pub discretionary_data: Vec<u8>,
    pub alternate_interface: AlternateInterface,
}

impl ContactlessOutcome {
    pub fn new(
        outcome_code: ContactlessOutcomeCode,
        start_signal: StartSignal,
        ui: UiRequest,
        restart_required: bool,
        data_record: &[u8],
        discretionary_data: &[u8],
        alternate_interface: AlternateInterface,
    ) -> KernelResult<Self> {
        if data_record.len() > MAX_C8_DATA_RECORD_LEN
            || discretionary_data.len() > MAX_C8_DISCRETIONARY_DATA_LEN
        {
            return Err(KernelError::LengthOverflow);
        }

        if outcome_code != ContactlessOutcomeCode::AlternateInterface
            && alternate_interface != AlternateInterface::None
        {
            return Err(KernelError::InvalidArgument);
        }

        Ok(Self {
            outcome_code,
            start_signal,
            ui,
            restart_required,
            data_record: data_record.to_vec(),
            discretionary_data: discretionary_data.to_vec(),
            alternate_interface,
        })
    }

    pub fn as_ffi(&self) -> KrnContactlessOutcome {
        KrnContactlessOutcome {
            outcome_code: self.outcome_code as u8,
            start_signal: self.start_signal as u8,
            ui_message_id: self.ui.message_id,
            ui_status: self.ui.status as u8,
            hold_time_ms: self.ui.hold_time_ms,
            restart_required: u8::from(self.restart_required),
            data_record: self.data_record.as_ptr(),
            data_record_len: self.data_record.len(),
            discretionary_data: self.discretionary_data.as_ptr(),
            discretionary_data_len: self.discretionary_data.len(),
            alternate_interface: self.alternate_interface as u8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct KrnContactlessOutcome {
    pub outcome_code: u8,
    pub start_signal: u8,
    pub ui_message_id: u16,
    pub ui_status: u8,
    pub hold_time_ms: u16,
    pub restart_required: u8,
    pub data_record: *const u8,
    pub data_record_len: usize,
    pub discretionary_data: *const u8,
    pub discretionary_data_len: usize,
    pub alternate_interface: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactlessLimitInput {
    pub amount_authorised_minor: u64,
    pub contactless_transaction_limit: u64,
    pub contactless_cvm_limit: u64,
    pub floor_limit: u64,
    pub cvm_satisfied: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactlessLimitDecision {
    Allowed,
    CvmRequired,
    OnlineRequired,
    AlternateInterface,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayResistanceFailureOutcome {
    TryAgain,
    AlternateInterface,
    Terminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayResistanceProfile {
    pub command_apdu: Vec<u8>,
    pub max_round_trip_ms: u16,
    pub success_response: Vec<u8>,
    pub failure_outcome: RelayResistanceFailureOutcome,
}

impl RelayResistanceProfile {
    pub fn new(
        command_apdu: Vec<u8>,
        max_round_trip_ms: u16,
        success_response: Vec<u8>,
        failure_outcome: RelayResistanceFailureOutcome,
    ) -> KernelResult<Self> {
        if !(4..=MAX_RELAY_RESISTANCE_APDU_LEN).contains(&command_apdu.len())
            || !(2..=MAX_RELAY_RESISTANCE_RESPONSE_LEN).contains(&success_response.len())
            || max_round_trip_ms == 0
        {
            return Err(KernelError::InvalidProfile);
        }
        Ok(Self {
            command_apdu,
            max_round_trip_ms,
            success_response,
            failure_outcome,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayResistanceDecision {
    Passed,
    Failed(RelayResistanceFailureOutcome),
}

pub fn evaluate_relay_resistance(
    profile: &RelayResistanceProfile,
    response: &[u8],
    round_trip_ms: u16,
) -> RelayResistanceDecision {
    if round_trip_ms <= profile.max_round_trip_ms && response == profile.success_response {
        RelayResistanceDecision::Passed
    } else {
        RelayResistanceDecision::Failed(profile.failure_outcome)
    }
}

pub fn evaluate_contactless_limits(input: ContactlessLimitInput) -> ContactlessLimitDecision {
    if input.contactless_transaction_limit != 0
        && input.amount_authorised_minor > input.contactless_transaction_limit
    {
        return ContactlessLimitDecision::AlternateInterface;
    }

    if input.contactless_cvm_limit != 0
        && input.amount_authorised_minor > input.contactless_cvm_limit
        && !input.cvm_satisfied
    {
        return ContactlessLimitDecision::CvmRequired;
    }

    if input.floor_limit != 0 && input.amount_authorised_minor > input.floor_limit {
        return ContactlessLimitDecision::OnlineRequired;
    }

    ContactlessLimitDecision::Allowed
}

pub fn outcome_from_limit_decision(
    decision: ContactlessLimitDecision,
) -> KernelResult<ContactlessOutcome> {
    match decision {
        ContactlessLimitDecision::Allowed => ContactlessOutcome::new(
            ContactlessOutcomeCode::Approved,
            StartSignal::None,
            UiRequest {
                message_id: 1,
                status: UiStatus::Approved,
                hold_time_ms: 0,
            },
            false,
            &[],
            &[],
            AlternateInterface::None,
        ),
        ContactlessLimitDecision::CvmRequired => ContactlessOutcome::new(
            ContactlessOutcomeCode::CvmRequired,
            StartSignal::Prompt,
            UiRequest {
                message_id: 2,
                status: UiStatus::Processing,
                hold_time_ms: 0,
            },
            true,
            &[],
            &[],
            AlternateInterface::None,
        ),
        ContactlessLimitDecision::OnlineRequired => ContactlessOutcome::new(
            ContactlessOutcomeCode::OnlineRequired,
            StartSignal::None,
            UiRequest::none(),
            false,
            &[],
            &[],
            AlternateInterface::None,
        ),
        ContactlessLimitDecision::AlternateInterface => ContactlessOutcome::new(
            ContactlessOutcomeCode::AlternateInterface,
            StartSignal::Prompt,
            UiRequest {
                message_id: 3,
                status: UiStatus::Error,
                hold_time_ms: 0,
            },
            false,
            &[],
            &[],
            AlternateInterface::Contact,
        ),
    }
}

pub fn outcome_from_relay_resistance_failure(
    outcome: RelayResistanceFailureOutcome,
) -> KernelResult<ContactlessOutcome> {
    match outcome {
        RelayResistanceFailureOutcome::TryAgain => ContactlessOutcome::new(
            ContactlessOutcomeCode::TryAgain,
            StartSignal::Prompt,
            UiRequest {
                message_id: 4,
                status: UiStatus::TryAgain,
                hold_time_ms: 0,
            },
            true,
            &[],
            &[],
            AlternateInterface::None,
        ),
        RelayResistanceFailureOutcome::AlternateInterface => ContactlessOutcome::new(
            ContactlessOutcomeCode::AlternateInterface,
            StartSignal::Prompt,
            UiRequest {
                message_id: 3,
                status: UiStatus::Error,
                hold_time_ms: 0,
            },
            false,
            &[],
            &[],
            AlternateInterface::Contact,
        ),
        RelayResistanceFailureOutcome::Terminate => ContactlessOutcome::new(
            ContactlessOutcomeCode::Terminate,
            StartSignal::None,
            UiRequest {
                message_id: 5,
                status: UiStatus::Error,
                hold_time_ms: 0,
            },
            false,
            &[],
            &[],
            AlternateInterface::None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_model_preserves_structured_records_for_callback() {
        let outcome = ContactlessOutcome::new(
            ContactlessOutcomeCode::OnlineRequired,
            StartSignal::Start,
            UiRequest {
                message_id: 0x1234,
                status: UiStatus::Processing,
                hold_time_ms: 500,
            },
            false,
            &[0x9f, 0x27, 0x01, 0x80],
            &[0xdf, 0x01, 0x01, 0x02],
            AlternateInterface::None,
        )
        .unwrap();
        let ffi = outcome.as_ffi();
        assert_eq!(
            ffi.outcome_code,
            ContactlessOutcomeCode::OnlineRequired as u8
        );
        assert_eq!(ffi.start_signal, StartSignal::Start as u8);
        assert_eq!(ffi.ui_message_id, 0x1234);
        assert_eq!(ffi.hold_time_ms, 500);
        assert_eq!(ffi.data_record_len, 4);
        assert_eq!(ffi.discretionary_data_len, 4);
        assert!(!ffi.data_record.is_null());
        assert!(!ffi.discretionary_data.is_null());
    }

    #[test]
    fn outcome_model_bounds_records_and_alternate_interface_instruction() {
        let too_long = [0u8; MAX_C8_DATA_RECORD_LEN + 1];
        assert_eq!(
            ContactlessOutcome::new(
                ContactlessOutcomeCode::Approved,
                StartSignal::None,
                UiRequest::none(),
                false,
                &too_long,
                &[],
                AlternateInterface::None,
            )
            .unwrap_err(),
            KernelError::LengthOverflow
        );

        assert_eq!(
            ContactlessOutcome::new(
                ContactlessOutcomeCode::Approved,
                StartSignal::None,
                UiRequest::none(),
                false,
                &[],
                &[],
                AlternateInterface::Contact,
            )
            .unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn contactless_limits_are_profile_driven_and_deterministic() {
        let base = ContactlessLimitInput {
            amount_authorised_minor: 4_000,
            contactless_transaction_limit: 5_000,
            contactless_cvm_limit: 3_000,
            floor_limit: 4_500,
            cvm_satisfied: false,
        };
        assert_eq!(
            evaluate_contactless_limits(base),
            ContactlessLimitDecision::CvmRequired
        );
        assert_eq!(
            evaluate_contactless_limits(ContactlessLimitInput {
                cvm_satisfied: true,
                ..base
            }),
            ContactlessLimitDecision::Allowed
        );
        assert_eq!(
            evaluate_contactless_limits(ContactlessLimitInput {
                amount_authorised_minor: 4_600,
                cvm_satisfied: true,
                ..base
            }),
            ContactlessLimitDecision::OnlineRequired
        );
        assert_eq!(
            evaluate_contactless_limits(ContactlessLimitInput {
                amount_authorised_minor: 5_001,
                cvm_satisfied: true,
                ..base
            }),
            ContactlessLimitDecision::AlternateInterface
        );
    }

    #[test]
    fn relay_resistance_is_profile_gated_and_deterministic() {
        let profile = RelayResistanceProfile::new(
            vec![0x80, 0xCA, 0x9F, 0x7A, 0x00],
            50,
            vec![0x90, 0x00],
            RelayResistanceFailureOutcome::TryAgain,
        )
        .unwrap();

        assert_eq!(
            evaluate_relay_resistance(&profile, &[0x90, 0x00], 50),
            RelayResistanceDecision::Passed
        );
        assert_eq!(
            evaluate_relay_resistance(&profile, &[0x90, 0x00], 51),
            RelayResistanceDecision::Failed(RelayResistanceFailureOutcome::TryAgain)
        );
        assert_eq!(
            evaluate_relay_resistance(&profile, &[0x69, 0x85], 1),
            RelayResistanceDecision::Failed(RelayResistanceFailureOutcome::TryAgain)
        );
        assert_eq!(
            RelayResistanceProfile::new(
                Vec::new(),
                50,
                vec![0x90, 0x00],
                RelayResistanceFailureOutcome::TryAgain,
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }
}
