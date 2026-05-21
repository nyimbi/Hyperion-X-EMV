use crate::error::{KernelError, KernelResult};
use crate::state::Tvr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalAction {
    Aac,
    Tc,
    Arqc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionCodes {
    pub denial: [u8; 5],
    pub online: [u8; 5],
    pub default: [u8; 5],
}

impl ActionCodes {
    pub fn zeroed() -> Self {
        Self {
            denial: [0; 5],
            online: [0; 5],
            default: [0; 5],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaaProfile {
    pub fallback_when_offline_unable_online: TerminalAction,
    pub no_match_default_when_online_capable: TerminalAction,
    pub no_match_default_when_offline_only: TerminalAction,
}

impl TaaProfile {
    pub fn new(
        fallback_when_offline_unable_online: TerminalAction,
        no_match_default_when_online_capable: TerminalAction,
        no_match_default_when_offline_only: TerminalAction,
    ) -> KernelResult<Self> {
        if !matches!(
            fallback_when_offline_unable_online,
            TerminalAction::Aac | TerminalAction::Tc
        ) {
            return Err(KernelError::InvalidProfile);
        }
        if !matches!(
            no_match_default_when_online_capable,
            TerminalAction::Tc | TerminalAction::Arqc
        ) {
            return Err(KernelError::InvalidProfile);
        }
        if !matches!(
            no_match_default_when_offline_only,
            TerminalAction::Tc | TerminalAction::Aac
        ) {
            return Err(KernelError::InvalidProfile);
        }

        Ok(Self {
            fallback_when_offline_unable_online,
            no_match_default_when_online_capable,
            no_match_default_when_offline_only,
        })
    }

    pub fn spec_defaults() -> Self {
        Self {
            fallback_when_offline_unable_online: TerminalAction::Aac,
            no_match_default_when_online_capable: TerminalAction::Arqc,
            no_match_default_when_offline_only: TerminalAction::Aac,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaaInput {
    pub tvr: Tvr,
    pub tac: ActionCodes,
    pub iac: ActionCodes,
    pub terminal_online_capable: bool,
    pub profile: TaaProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaaDecision {
    pub action: TerminalAction,
    pub reason: &'static str,
}

pub fn decide(input: TaaInput) -> TaaDecision {
    let tvr = input.tvr.bytes();

    if intersects(tvr, or5(input.tac.denial, input.iac.denial)) {
        return TaaDecision {
            action: TerminalAction::Aac,
            reason: "denial action code matched",
        };
    }

    if input.terminal_online_capable && intersects(tvr, or5(input.tac.online, input.iac.online)) {
        return TaaDecision {
            action: TerminalAction::Arqc,
            reason: "online action code matched",
        };
    }

    if !input.terminal_online_capable && intersects(tvr, or5(input.tac.default, input.iac.default))
    {
        return TaaDecision {
            action: input.profile.fallback_when_offline_unable_online,
            reason: "default action code matched while unable online",
        };
    }

    if input.terminal_online_capable {
        TaaDecision {
            action: input.profile.no_match_default_when_online_capable,
            reason: "no action code matched while online capable",
        }
    } else {
        TaaDecision {
            action: input.profile.no_match_default_when_offline_only,
            reason: "no action code matched while offline only",
        }
    }
}

fn intersects(left: [u8; 5], right: [u8; 5]) -> bool {
    left.iter()
        .zip(right)
        .any(|(left, right)| left & right != 0)
}

fn or5(left: [u8; 5], right: [u8; 5]) -> [u8; 5] {
    [
        left[0] | right[0],
        left[1] | right[1],
        left[2] | right[2],
        left[3] | right[3],
        left[4] | right[4],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Tvr;

    fn input(tvr: Tvr) -> TaaInput {
        TaaInput {
            tvr,
            tac: ActionCodes::zeroed(),
            iac: ActionCodes::zeroed(),
            terminal_online_capable: true,
            profile: TaaProfile::spec_defaults(),
        }
    }

    #[test]
    fn denial_action_codes_take_precedence() {
        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B1_SDA_FAILED);
        let mut input = input(tvr);
        input.iac.denial = [0x40, 0, 0, 0, 0];
        input.tac.online = [0x40, 0, 0, 0, 0];

        let decision = decide(input);
        assert_eq!(decision.action, TerminalAction::Aac);
        assert_eq!(decision.reason, "denial action code matched");
    }

    #[test]
    fn online_action_codes_request_arqc_when_online_capable() {
        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B4_FLOOR_LIMIT_EXCEEDED);
        let mut input = input(tvr);
        input.tac.online = [0, 0, 0, 0x80, 0];

        let decision = decide(input);
        assert_eq!(decision.action, TerminalAction::Arqc);
    }

    #[test]
    fn offline_unable_default_match_uses_profile_fallback() {
        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B1_ICC_DATA_MISSING);
        let mut input = input(tvr);
        input.terminal_online_capable = false;
        input.iac.default = [0x20, 0, 0, 0, 0];
        input.profile = TaaProfile::new(
            TerminalAction::Tc,
            TerminalAction::Arqc,
            TerminalAction::Aac,
        )
        .unwrap();

        let decision = decide(input);
        assert_eq!(decision.action, TerminalAction::Tc);
    }

    #[test]
    fn iac_values_participate_in_denial_online_and_default_decisions() {
        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B1_SDA_FAILED);
        let mut denial_input = input(tvr);
        denial_input.iac.denial = [0x40, 0, 0, 0, 0];
        denial_input.tac.online = [0x40, 0, 0, 0, 0];
        assert_eq!(decide(denial_input).action, TerminalAction::Aac);

        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B4_FLOOR_LIMIT_EXCEEDED);
        let mut online_input = input(tvr);
        online_input.iac.online = [0, 0, 0, 0x80, 0];
        assert_eq!(decide(online_input).action, TerminalAction::Arqc);

        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B1_ICC_DATA_MISSING);
        let mut default_input = input(tvr);
        default_input.terminal_online_capable = false;
        default_input.iac.default = [0x20, 0, 0, 0, 0];
        default_input.profile = TaaProfile::new(
            TerminalAction::Tc,
            TerminalAction::Arqc,
            TerminalAction::Aac,
        )
        .unwrap();
        assert_eq!(decide(default_input).action, TerminalAction::Tc);
    }

    #[test]
    fn no_match_defaults_are_profile_driven() {
        let mut input = input(Tvr::cleared());
        input.profile =
            TaaProfile::new(TerminalAction::Aac, TerminalAction::Tc, TerminalAction::Tc).unwrap();

        assert_eq!(decide(input).action, TerminalAction::Tc);
        input.terminal_online_capable = false;
        assert_eq!(decide(input).action, TerminalAction::Tc);
    }

    #[test]
    fn invalid_profile_combinations_are_rejected() {
        assert_eq!(
            TaaProfile::new(
                TerminalAction::Arqc,
                TerminalAction::Arqc,
                TerminalAction::Aac
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            TaaProfile::new(
                TerminalAction::Aac,
                TerminalAction::Aac,
                TerminalAction::Aac
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            TaaProfile::new(
                TerminalAction::Aac,
                TerminalAction::Arqc,
                TerminalAction::Arqc
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }
}
