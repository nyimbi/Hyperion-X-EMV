use crate::error::{KernelError, KernelResult};
use crate::state::Tvr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EmvDate {
    pub year: u8,
    pub month: u8,
    pub day: u8,
}

impl EmvDate {
    pub fn from_bcd(bytes: [u8; 3]) -> KernelResult<Self> {
        let year = bcd(bytes[0])?;
        let month = bcd(bytes[1])?;
        let day = bcd(bytes[2])?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(KernelError::ParseError);
        }
        Ok(Self { year, month, day })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionRegion {
    Domestic,
    International,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceType {
    Cash,
    Goods,
    Services,
    Atm,
    Cashback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationUsageControl {
    bytes: [u8; 2],
}

impl ApplicationUsageControl {
    pub fn new(bytes: [u8; 2]) -> Self {
        Self { bytes }
    }

    pub fn allows(self, region: TransactionRegion, service: ServiceType) -> bool {
        let mask = match (region, service) {
            (TransactionRegion::Domestic, ServiceType::Cash) => (0, 0x80),
            (TransactionRegion::International, ServiceType::Cash) => (0, 0x40),
            (TransactionRegion::Domestic, ServiceType::Goods) => (0, 0x20),
            (TransactionRegion::International, ServiceType::Goods) => (0, 0x10),
            (TransactionRegion::Domestic, ServiceType::Services) => (0, 0x08),
            (TransactionRegion::International, ServiceType::Services) => (0, 0x04),
            (_, ServiceType::Atm) => (0, 0x02),
            (_, ServiceType::Cashback) => (1, 0x80),
        };
        self.bytes[mask.0] & mask.1 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictionInput {
    pub transaction_date: EmvDate,
    pub application_expiration_date: EmvDate,
    pub application_effective_date: Option<EmvDate>,
    pub card_application_version: Option<[u8; 2]>,
    pub terminal_application_version: Option<[u8; 2]>,
    pub auc: ApplicationUsageControl,
    pub region: TransactionRegion,
    pub service: ServiceType,
    pub new_card: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictionResult {
    pub tvr: Tvr,
    pub failed: bool,
}

pub fn evaluate(input: RestrictionInput, mut tvr: Tvr) -> RestrictionResult {
    let mut failed = false;

    if let (Some(card), Some(terminal)) = (
        input.card_application_version,
        input.terminal_application_version,
    ) {
        if card != terminal {
            tvr.set(Tvr::B2_DIFFERENT_APPLICATION_VERSIONS);
            failed = true;
        }
    }

    if input.transaction_date > input.application_expiration_date {
        tvr.set(Tvr::B2_EXPIRED_APPLICATION);
        failed = true;
    }

    if let Some(effective_date) = input.application_effective_date {
        if input.transaction_date < effective_date {
            tvr.set(Tvr::B2_APPLICATION_NOT_YET_EFFECTIVE);
            failed = true;
        }
    }

    if !input.auc.allows(input.region, input.service) {
        tvr.set(Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED);
        failed = true;
    }

    if input.new_card {
        tvr.set(Tvr::B2_NEW_CARD);
        failed = true;
    }

    RestrictionResult { tvr, failed }
}

fn bcd(byte: u8) -> KernelResult<u8> {
    let high = byte >> 4;
    let low = byte & 0x0f;
    if high > 9 || low > 9 {
        return Err(KernelError::ParseError);
    }
    Ok(high * 10 + low)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> RestrictionInput {
        RestrictionInput {
            transaction_date: EmvDate::from_bcd([0x26, 0x05, 0x21]).unwrap(),
            application_expiration_date: EmvDate::from_bcd([0x30, 0x12, 0x31]).unwrap(),
            application_effective_date: Some(EmvDate::from_bcd([0x25, 0x01, 0x01]).unwrap()),
            card_application_version: Some([0x00, 0x01]),
            terminal_application_version: Some([0x00, 0x01]),
            auc: ApplicationUsageControl::new([0xff, 0x80]),
            region: TransactionRegion::Domestic,
            service: ServiceType::Goods,
            new_card: false,
        }
    }

    #[test]
    fn parses_valid_bcd_dates_and_rejects_invalid_values() {
        assert_eq!(
            EmvDate::from_bcd([0x26, 0x05, 0x21]).unwrap(),
            EmvDate {
                year: 26,
                month: 5,
                day: 21
            }
        );
        assert_eq!(
            EmvDate::from_bcd([0x26, 0x13, 0x01]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            EmvDate::from_bcd([0x2a, 0x01, 0x01]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn evaluates_version_dates_auc_and_new_card_bits() {
        let mut input = base_input();
        input.transaction_date = EmvDate::from_bcd([0x31, 0x01, 0x01]).unwrap();
        input.application_effective_date = Some(EmvDate::from_bcd([0x32, 0x01, 0x01]).unwrap());
        input.card_application_version = Some([0x00, 0x02]);
        input.auc = ApplicationUsageControl::new([0x00, 0x00]);
        input.new_card = true;

        let result = evaluate(input, Tvr::cleared());
        assert!(result.failed);
        assert!(result.tvr.is_set(Tvr::B2_DIFFERENT_APPLICATION_VERSIONS));
        assert!(result.tvr.is_set(Tvr::B2_EXPIRED_APPLICATION));
        assert!(result.tvr.is_set(Tvr::B2_APPLICATION_NOT_YET_EFFECTIVE));
        assert!(result.tvr.is_set(Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED));
        assert!(result.tvr.is_set(Tvr::B2_NEW_CARD));
    }

    #[test]
    fn does_not_set_non_standard_bits_for_allowed_transaction() {
        let result = evaluate(base_input(), Tvr::cleared());
        assert!(!result.failed);
        assert_eq!(result.tvr.bytes(), [0; 5]);
    }
}
