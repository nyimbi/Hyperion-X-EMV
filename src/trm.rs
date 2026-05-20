use crate::state::{Tsi, Tvr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrmProfile {
    pub floor_limit: u64,
    pub random_selection_percent: u8,
    pub lower_consecutive_offline_limit: Option<u16>,
    pub upper_consecutive_offline_limit: Option<u16>,
}

impl TrmProfile {
    pub fn new(
        floor_limit: u64,
        random_selection_percent: u8,
        lower_consecutive_offline_limit: Option<u16>,
        upper_consecutive_offline_limit: Option<u16>,
    ) -> Option<Self> {
        if random_selection_percent > 100 {
            return None;
        }
        Some(Self {
            floor_limit,
            random_selection_percent,
            lower_consecutive_offline_limit,
            upper_consecutive_offline_limit,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrmInput {
    pub amount_authorized: u64,
    pub exception_file_match: bool,
    pub merchant_forced_online: bool,
    pub consecutive_offline_count: Option<u16>,
    /// Deterministic certified-profile sample in basis points, 0..=9999.
    pub random_sample_basis_points: Option<u16>,
    pub profile: TrmProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrmResult {
    pub tvr: Tvr,
    pub tsi: Tsi,
    pub force_online: bool,
}

pub fn evaluate(input: TrmInput, mut tvr: Tvr, mut tsi: Tsi) -> TrmResult {
    let mut force_online = false;

    if input.exception_file_match {
        tvr.set(Tvr::B1_CARD_ON_EXCEPTION_FILE);
        force_online = true;
    }

    if input.amount_authorized > input.profile.floor_limit {
        tvr.set(Tvr::B4_FLOOR_LIMIT_EXCEEDED);
        force_online = true;
    }

    if let (Some(count), Some(limit)) = (
        input.consecutive_offline_count,
        input.profile.lower_consecutive_offline_limit,
    ) {
        if count > limit {
            tvr.set(Tvr::B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED);
            force_online = true;
        }
    }

    if let (Some(count), Some(limit)) = (
        input.consecutive_offline_count,
        input.profile.upper_consecutive_offline_limit,
    ) {
        if count > limit {
            tvr.set(Tvr::B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED);
            force_online = true;
        }
    }

    if random_selection_triggered(
        input.profile.random_selection_percent,
        input.random_sample_basis_points,
    ) {
        tvr.set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED);
        force_online = true;
    }

    if input.merchant_forced_online {
        tvr.set(Tvr::B4_MERCHANT_FORCED_TRANSACTION_ONLINE);
        force_online = true;
    }

    tsi.set(Tsi::TERMINAL_RISK_MANAGEMENT_PERFORMED);

    TrmResult {
        tvr,
        tsi,
        force_online,
    }
}

fn random_selection_triggered(percent: u8, sample_basis_points: Option<u16>) -> bool {
    if percent == 0 {
        return false;
    }
    let Some(sample) = sample_basis_points else {
        return false;
    };
    let threshold = (percent as u16) * 100;
    sample < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> TrmProfile {
        TrmProfile::new(5_000, 5, Some(2), Some(4)).unwrap()
    }

    #[test]
    fn evaluates_floor_exception_velocity_random_and_merchant_bits() {
        let result = evaluate(
            TrmInput {
                amount_authorized: 6_000,
                exception_file_match: true,
                merchant_forced_online: true,
                consecutive_offline_count: Some(5),
                random_sample_basis_points: Some(10),
                profile: profile(),
            },
            Tvr::cleared(),
            Tsi::cleared(),
        );

        assert!(result.force_online);
        assert!(result.tvr.is_set(Tvr::B1_CARD_ON_EXCEPTION_FILE));
        assert!(result.tvr.is_set(Tvr::B4_FLOOR_LIMIT_EXCEEDED));
        assert!(result
            .tvr
            .is_set(Tvr::B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED));
        assert!(result
            .tvr
            .is_set(Tvr::B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED));
        assert!(result
            .tvr
            .is_set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED));
        assert!(result
            .tvr
            .is_set(Tvr::B4_MERCHANT_FORCED_TRANSACTION_ONLINE));
        assert!(result.tsi.is_set(Tsi::TERMINAL_RISK_MANAGEMENT_PERFORMED));
    }

    #[test]
    fn random_selection_is_deterministic_from_external_sample() {
        let profile = TrmProfile::new(10_000, 5, None, None).unwrap();
        let selected = evaluate(
            TrmInput {
                amount_authorized: 1,
                exception_file_match: false,
                merchant_forced_online: false,
                consecutive_offline_count: None,
                random_sample_basis_points: Some(499),
                profile,
            },
            Tvr::cleared(),
            Tsi::cleared(),
        );
        let not_selected = evaluate(
            TrmInput {
                random_sample_basis_points: Some(500),
                ..TrmInput {
                    amount_authorized: 1,
                    exception_file_match: false,
                    merchant_forced_online: false,
                    consecutive_offline_count: None,
                    random_sample_basis_points: Some(499),
                    profile,
                }
            },
            Tvr::cleared(),
            Tsi::cleared(),
        );

        assert!(selected
            .tvr
            .is_set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED));
        assert!(!not_selected
            .tvr
            .is_set(Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED));
    }

    #[test]
    fn rejects_invalid_profile_percent() {
        assert!(TrmProfile::new(0, 101, None, None).is_none());
    }
}
