use crate::error::{KernelError, KernelResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsmState {
    S0,
    S1,
    S2,
    S2AidList,
    S2SelectAid,
    S3,
    S4,
    S4Next,
    S5,
    S5Cda,
    S6,
    S7,
    S7Retry,
    S8,
    S9,
    S10,
    S11,
    S12,
    S13,
    S13Script,
    S14,
    S15,
    S15Script,
    S16,
    Se,
}

impl FsmState {
    pub fn code(self) -> u8 {
        match self {
            FsmState::S0 => 0,
            FsmState::S1 => 1,
            FsmState::S2 => 2,
            FsmState::S2AidList => 3,
            FsmState::S2SelectAid => 4,
            FsmState::S3 => 5,
            FsmState::S4 => 6,
            FsmState::S4Next => 7,
            FsmState::S5 => 8,
            FsmState::S5Cda => 9,
            FsmState::S6 => 10,
            FsmState::S7 => 11,
            FsmState::S7Retry => 12,
            FsmState::S8 => 13,
            FsmState::S9 => 14,
            FsmState::S10 => 15,
            FsmState::S11 => 16,
            FsmState::S12 => 17,
            FsmState::S13 => 18,
            FsmState::S13Script => 19,
            FsmState::S14 => 20,
            FsmState::S15 => 21,
            FsmState::S16 => 22,
            FsmState::S15Script => 23,
            FsmState::Se => 255,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsmEvent {
    SetTransactionParams,
    CardDetected,
    CardDetectionTimeout,
    PseSelected,
    PseNotFound,
    CandidateAidAvailable,
    NoCandidateLeft,
    AidSelected,
    AidNotSupported,
    GpoTemplate77,
    GpoTemplate80,
    GpoFailed,
    RecordRead,
    EndOfRecords,
    RecordReadFailed,
    MoreAflEntries,
    AflComplete,
    OdaSuccess,
    OdaFailure,
    RestrictionsEvaluated,
    CvmSuccess,
    CvmRetryPossible,
    CvmFailureNoRetry,
    CvmRetryAvailable,
    CvmRetryExceeded,
    TrmEvaluated,
    TaaArqc,
    TaaTc,
    TaaAac,
    GacArqc,
    GacTc,
    GacAac,
    GacCda,
    GacFailed,
    CdaSuccess,
    CdaFailure,
    HostArpc,
    HostApprovalNoArpc,
    HostTimeout,
    IssuerAuthenticationSuccess,
    IssuerAuthenticationFailure,
    Gac2Tc,
    Gac2Aac,
    Gac2Failed,
    ScriptAvailable,
    NoMoreScripts,
    ScriptSuccess,
    ScriptNonCriticalFailure,
    ScriptCriticalFailure,
    FinalGenerateAcSkipped,
    FinalOutcomeComplete,
    ErrorReset,
    CardRemoved,
    ApduTimeout,
    CallbackFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsmAction {
    StoreTransactionParams,
    StartSelection,
    RetryDetection,
    BuildCandidateList,
    SelectNextAid,
    SetNoCommonAid,
    BuildGpo,
    ReadRecords,
    StartOda,
    SetIccDataMissing,
    ContinueAfl,
    RecordOdaResult,
    EvaluateRestrictions,
    EvaluateCvm,
    RetryCvm,
    EvaluateTrm,
    RunTaa,
    RequestFirstGenerateAc,
    BuildHostRequest,
    OfflineApprove,
    OfflineDecline,
    VerifyCda,
    ProcessArpc,
    ProcessIssuerScripts,
    RequestFinalGenerateAc,
    ProcessPostFinalIssuerScripts,
    FinalOutcome,
    Reset,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    pub from: FsmState,
    pub event: FsmEvent,
    pub to: FsmState,
    pub action: FsmAction,
    pub error: KernelError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFsm {
    state: FsmState,
}

impl TransactionFsm {
    pub fn new() -> Self {
        Self {
            state: FsmState::S0,
        }
    }

    pub fn state(self) -> FsmState {
        self.state
    }

    pub fn apply(&mut self, event: FsmEvent) -> KernelResult<Transition> {
        let transition = transition(self.state, event)?;
        self.state = transition.to;
        Ok(transition)
    }
}

impl Default for TransactionFsm {
    fn default() -> Self {
        Self::new()
    }
}

pub fn transition(state: FsmState, event: FsmEvent) -> KernelResult<Transition> {
    let (to, action, error) = match (state, event) {
        (FsmState::S0, FsmEvent::SetTransactionParams) => (
            FsmState::S1,
            FsmAction::StoreTransactionParams,
            KernelError::Ok,
        ),
        (FsmState::S1, FsmEvent::CardDetected) => {
            (FsmState::S2, FsmAction::StartSelection, KernelError::Ok)
        }
        (FsmState::S1, FsmEvent::CardDetectionTimeout) => {
            (FsmState::S1, FsmAction::RetryDetection, KernelError::Ok)
        }
        (FsmState::S2, FsmEvent::PseSelected) | (FsmState::S2, FsmEvent::PseNotFound) => (
            FsmState::S2AidList,
            FsmAction::BuildCandidateList,
            KernelError::Ok,
        ),
        (FsmState::S2AidList, FsmEvent::CandidateAidAvailable) => (
            FsmState::S2SelectAid,
            FsmAction::SelectNextAid,
            KernelError::Ok,
        ),
        (FsmState::S2AidList, FsmEvent::NoCandidateLeft) => (
            FsmState::Se,
            FsmAction::SetNoCommonAid,
            KernelError::NoCommonAid,
        ),
        (FsmState::S2SelectAid, FsmEvent::AidSelected) => {
            (FsmState::S3, FsmAction::BuildGpo, KernelError::Ok)
        }
        (FsmState::S2SelectAid, FsmEvent::AidNotSupported) => (
            FsmState::S2AidList,
            FsmAction::BuildCandidateList,
            KernelError::Ok,
        ),
        (FsmState::S3, FsmEvent::GpoTemplate77) => {
            (FsmState::S4, FsmAction::ReadRecords, KernelError::Ok)
        }
        (FsmState::S3, FsmEvent::GpoTemplate80) => {
            (FsmState::S5, FsmAction::StartOda, KernelError::Ok)
        }
        (FsmState::S3, FsmEvent::GpoFailed) => (
            FsmState::Se,
            FsmAction::Error,
            KernelError::MissingMandatoryTag,
        ),
        (FsmState::S4, FsmEvent::RecordRead) => {
            (FsmState::S4Next, FsmAction::ContinueAfl, KernelError::Ok)
        }
        (FsmState::S4, FsmEvent::EndOfRecords) => {
            (FsmState::S5, FsmAction::StartOda, KernelError::Ok)
        }
        (FsmState::S4, FsmEvent::RecordReadFailed) => {
            (FsmState::S5, FsmAction::SetIccDataMissing, KernelError::Ok)
        }
        (FsmState::S4Next, FsmEvent::MoreAflEntries) => {
            (FsmState::S4, FsmAction::ReadRecords, KernelError::Ok)
        }
        (FsmState::S4Next, FsmEvent::AflComplete) => {
            (FsmState::S5, FsmAction::StartOda, KernelError::Ok)
        }
        (FsmState::S5, FsmEvent::OdaSuccess) | (FsmState::S5, FsmEvent::OdaFailure) => {
            (FsmState::S6, FsmAction::RecordOdaResult, KernelError::Ok)
        }
        (FsmState::S6, FsmEvent::RestrictionsEvaluated) => {
            (FsmState::S7, FsmAction::EvaluateCvm, KernelError::Ok)
        }
        (FsmState::S7, FsmEvent::CvmSuccess) | (FsmState::S7, FsmEvent::CvmFailureNoRetry) => {
            (FsmState::S8, FsmAction::EvaluateTrm, KernelError::Ok)
        }
        (FsmState::S7, FsmEvent::CvmRetryPossible) => {
            (FsmState::S7Retry, FsmAction::RetryCvm, KernelError::Ok)
        }
        (FsmState::S7Retry, FsmEvent::CvmRetryAvailable) => {
            (FsmState::S7, FsmAction::EvaluateCvm, KernelError::Ok)
        }
        (FsmState::S7Retry, FsmEvent::CvmRetryExceeded) => {
            (FsmState::S8, FsmAction::EvaluateTrm, KernelError::Ok)
        }
        (FsmState::S8, FsmEvent::TrmEvaluated) => {
            (FsmState::S9, FsmAction::RunTaa, KernelError::Ok)
        }
        (FsmState::S9, FsmEvent::TaaArqc) => (
            FsmState::S10,
            FsmAction::RequestFirstGenerateAc,
            KernelError::Ok,
        ),
        (FsmState::S9, FsmEvent::TaaTc) => {
            (FsmState::S16, FsmAction::OfflineApprove, KernelError::Ok)
        }
        (FsmState::S9, FsmEvent::TaaAac) => {
            (FsmState::S16, FsmAction::OfflineDecline, KernelError::Ok)
        }
        (FsmState::S10, FsmEvent::GacArqc) => {
            (FsmState::S11, FsmAction::BuildHostRequest, KernelError::Ok)
        }
        (FsmState::S10, FsmEvent::GacTc) => {
            (FsmState::S16, FsmAction::OfflineApprove, KernelError::Ok)
        }
        (FsmState::S10, FsmEvent::GacAac) => {
            (FsmState::S16, FsmAction::OfflineDecline, KernelError::Ok)
        }
        (FsmState::S10, FsmEvent::GacCda) => {
            (FsmState::S5Cda, FsmAction::VerifyCda, KernelError::Ok)
        }
        (FsmState::S10, FsmEvent::GacFailed) => {
            (FsmState::Se, FsmAction::Error, KernelError::CardRemoved)
        }
        (FsmState::S5Cda, FsmEvent::CdaSuccess) | (FsmState::S5Cda, FsmEvent::CdaFailure) => {
            (FsmState::S6, FsmAction::RecordOdaResult, KernelError::Ok)
        }
        (FsmState::S11, FsmEvent::HostArpc) => {
            (FsmState::S12, FsmAction::ProcessArpc, KernelError::Ok)
        }
        (FsmState::S11, FsmEvent::HostApprovalNoArpc) => (
            FsmState::S13,
            FsmAction::ProcessIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S11, FsmEvent::HostTimeout) => {
            (FsmState::Se, FsmAction::Error, KernelError::HostTimeout)
        }
        (FsmState::S12, FsmEvent::IssuerAuthenticationSuccess)
        | (FsmState::S12, FsmEvent::IssuerAuthenticationFailure) => (
            FsmState::S13,
            FsmAction::ProcessIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S13, FsmEvent::ScriptAvailable) => (
            FsmState::S13Script,
            FsmAction::ProcessIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S13, FsmEvent::NoMoreScripts) => (
            FsmState::S14,
            FsmAction::RequestFinalGenerateAc,
            KernelError::Ok,
        ),
        (FsmState::S14, FsmEvent::Gac2Tc)
        | (FsmState::S14, FsmEvent::Gac2Aac)
        | (FsmState::S14, FsmEvent::FinalGenerateAcSkipped) => (
            FsmState::S15,
            FsmAction::ProcessPostFinalIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S14, FsmEvent::Gac2Failed) => {
            (FsmState::Se, FsmAction::Error, KernelError::CardRemoved)
        }
        (FsmState::S13Script, FsmEvent::ScriptSuccess)
        | (FsmState::S13Script, FsmEvent::ScriptNonCriticalFailure) => (
            FsmState::S13,
            FsmAction::ProcessIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S13Script, FsmEvent::ScriptCriticalFailure) => {
            (FsmState::Se, FsmAction::Error, KernelError::ScriptFailed)
        }
        (FsmState::S15, FsmEvent::ScriptAvailable) => (
            FsmState::S15Script,
            FsmAction::ProcessPostFinalIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S15, FsmEvent::NoMoreScripts) => {
            (FsmState::S16, FsmAction::FinalOutcome, KernelError::Ok)
        }
        (FsmState::S15Script, FsmEvent::ScriptSuccess)
        | (FsmState::S15Script, FsmEvent::ScriptNonCriticalFailure) => (
            FsmState::S15,
            FsmAction::ProcessPostFinalIssuerScripts,
            KernelError::Ok,
        ),
        (FsmState::S15Script, FsmEvent::ScriptCriticalFailure) => {
            (FsmState::Se, FsmAction::Error, KernelError::ScriptFailed)
        }
        (FsmState::S16, FsmEvent::FinalOutcomeComplete) | (FsmState::Se, FsmEvent::ErrorReset) => {
            (FsmState::S0, FsmAction::Reset, KernelError::Ok)
        }
        (_, FsmEvent::CardRemoved) | (_, FsmEvent::ApduTimeout) => {
            (FsmState::Se, FsmAction::Error, KernelError::CardRemoved)
        }
        (_, FsmEvent::CallbackFailure) => {
            (FsmState::Se, FsmAction::Error, KernelError::InternalError)
        }
        _ => return Err(KernelError::InvalidArgument),
    };

    Ok(Transition {
        from: state,
        event,
        to,
        action,
        error,
    })
}

pub fn validate_state_machine_annex(csv: &str) -> KernelResult<usize> {
    let mut rows = csv.lines();
    let header = rows.next().ok_or(KernelError::ParseError)?;
    if split_csv_record(header)?.len() != 6 {
        return Err(KernelError::ParseError);
    }

    let mut count = 0usize;
    for row in rows {
        if row.trim().is_empty() {
            continue;
        }
        let fields = split_csv_record(row)?;
        if fields.len() != 6 {
            return Err(KernelError::ParseError);
        }
        parse_state(fields[0])?;
        parse_state(fields[3])?;
        parse_error_code(fields[5])?;
        count += 1;
    }

    if count == 0 {
        return Err(KernelError::ParseError);
    }
    Ok(count)
}

fn split_csv_record(row: &str) -> KernelResult<Vec<&str>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let bytes = row.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        match *byte {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                out.push(trim_csv_field(&row[start..idx]));
                start = idx + 1;
            }
            _ => {}
        }
    }
    if in_quotes {
        return Err(KernelError::ParseError);
    }
    out.push(trim_csv_field(&row[start..]));
    Ok(out)
}

fn trim_csv_field(field: &str) -> &str {
    field.trim().trim_matches('"')
}

fn parse_state(value: &str) -> KernelResult<FsmState> {
    match value {
        "S0" => Ok(FsmState::S0),
        "S1" => Ok(FsmState::S1),
        "S2" => Ok(FsmState::S2),
        "S2_AID_LIST" => Ok(FsmState::S2AidList),
        "S2_SELECT_AID" => Ok(FsmState::S2SelectAid),
        "S3" => Ok(FsmState::S3),
        "S4" => Ok(FsmState::S4),
        "S4_NEXT" => Ok(FsmState::S4Next),
        "S5" => Ok(FsmState::S5),
        "S5_CDA" => Ok(FsmState::S5Cda),
        "S6" => Ok(FsmState::S6),
        "S7" => Ok(FsmState::S7),
        "S7_RETRY" => Ok(FsmState::S7Retry),
        "S8" => Ok(FsmState::S8),
        "S9" => Ok(FsmState::S9),
        "S10" => Ok(FsmState::S10),
        "S11" => Ok(FsmState::S11),
        "S12" => Ok(FsmState::S12),
        "S13" => Ok(FsmState::S13),
        "S13_SCRIPT" => Ok(FsmState::S13Script),
        "S14" => Ok(FsmState::S14),
        "S15" => Ok(FsmState::S15),
        "S15_SCRIPT" => Ok(FsmState::S15Script),
        "S16" => Ok(FsmState::S16),
        "SE" => Ok(FsmState::Se),
        _ => Err(KernelError::ParseError),
    }
}

fn parse_error_code(value: &str) -> KernelResult<()> {
    match value {
        "KRN_OK"
        | "KRN_ERR_NO_COMMON_AID"
        | "KRN_ERR_MISSING_MANDATORY_TAG"
        | "KRN_ERR_CARD_REMOVED"
        | "KRN_ERR_HOST_TIMEOUT"
        | "KRN_ERR_SCRIPT_FAILED" => Ok(()),
        _ => Err(KernelError::ParseError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE_MACHINE: &str = include_str!("../docs/state_machine.csv");

    #[test]
    fn validates_machine_readable_state_annex() {
        assert!(validate_state_machine_annex(STATE_MACHINE).unwrap() >= 45);
    }

    #[test]
    fn follows_happy_path_to_offline_approval() {
        let mut fsm = TransactionFsm::new();
        for event in [
            FsmEvent::SetTransactionParams,
            FsmEvent::CardDetected,
            FsmEvent::PseSelected,
            FsmEvent::CandidateAidAvailable,
            FsmEvent::AidSelected,
            FsmEvent::GpoTemplate77,
            FsmEvent::EndOfRecords,
            FsmEvent::OdaSuccess,
            FsmEvent::RestrictionsEvaluated,
            FsmEvent::CvmSuccess,
            FsmEvent::TrmEvaluated,
            FsmEvent::TaaTc,
        ] {
            fsm.apply(event).unwrap();
        }
        assert_eq!(fsm.state(), FsmState::S16);
    }

    #[test]
    fn distinguishes_fatal_errors_from_tvr_mediated_risk_conditions() {
        assert_eq!(
            transition(FsmState::S4, FsmEvent::RecordReadFailed)
                .unwrap()
                .to,
            FsmState::S5
        );
        let fatal = transition(FsmState::S3, FsmEvent::GpoFailed).unwrap();
        assert_eq!(fatal.to, FsmState::Se);
        assert_eq!(fatal.error, KernelError::MissingMandatoryTag);
    }

    #[test]
    fn issuer_authentication_advances_to_script_processing_without_gac2_overload() {
        for event in [
            FsmEvent::IssuerAuthenticationSuccess,
            FsmEvent::IssuerAuthenticationFailure,
        ] {
            let transition = transition(FsmState::S12, event).unwrap();
            assert_eq!(transition.to, FsmState::S13);
            assert_eq!(transition.action, FsmAction::ProcessIssuerScripts);
            assert_eq!(transition.error, KernelError::Ok);
        }
        assert_eq!(
            transition(FsmState::S12, FsmEvent::Gac2Tc).unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn final_generate_ac_phase_finishes_online_outcome() {
        assert_eq!(
            transition(FsmState::S13, FsmEvent::NoMoreScripts)
                .unwrap()
                .to,
            FsmState::S14
        );
        assert_eq!(
            transition(FsmState::S14, FsmEvent::Gac2Tc).unwrap().to,
            FsmState::S15
        );
        assert_eq!(
            transition(FsmState::S14, FsmEvent::Gac2Aac).unwrap().to,
            FsmState::S15
        );
        assert_eq!(
            transition(FsmState::S15, FsmEvent::NoMoreScripts)
                .unwrap()
                .to,
            FsmState::S16
        );
    }

    #[test]
    fn asynchronous_failures_are_explicit_error_transitions() {
        assert_eq!(
            transition(FsmState::S10, FsmEvent::CardRemoved)
                .unwrap()
                .error,
            KernelError::CardRemoved
        );
        assert_eq!(
            transition(FsmState::S11, FsmEvent::HostTimeout)
                .unwrap()
                .error,
            KernelError::HostTimeout
        );
    }
}
