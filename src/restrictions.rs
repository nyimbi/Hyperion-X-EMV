use crate::error::{KernelError, KernelResult};
use crate::state::Tvr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EmvDate {
    pub year: u8,
    pub month: u8,
    pub day: u8,
}

impl EmvDate {
    pub fn new(year: u8, month: u8, day: u8) -> KernelResult<Self> {
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => 29,
            _ => return Err(KernelError::ParseError),
        };
        if day == 0 || day > max_day {
            return Err(KernelError::ParseError);
        }
        Ok(Self { year, month, day })
    }

    pub fn from_bcd(bytes: [u8; 3]) -> KernelResult<Self> {
        let year = bcd(bytes[0])?;
        let month = bcd(bytes[1])?;
        let day = bcd(bytes[2])?;
        Self::new(year, month, day)
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
    const DOMESTIC_CASH: (usize, u8) = (0, 0x80);
    const INTERNATIONAL_CASH: (usize, u8) = (0, 0x40);
    const DOMESTIC_GOODS: (usize, u8) = (0, 0x20);
    const INTERNATIONAL_GOODS: (usize, u8) = (0, 0x10);
    const DOMESTIC_SERVICES: (usize, u8) = (0, 0x08);
    const INTERNATIONAL_SERVICES: (usize, u8) = (0, 0x04);
    const VALID_AT_ATM: (usize, u8) = (0, 0x02);
    const VALID_OTHER_THAN_ATM: (usize, u8) = (0, 0x01);
    const DOMESTIC_CASHBACK: (usize, u8) = (1, 0x80);
    const INTERNATIONAL_CASHBACK: (usize, u8) = (1, 0x40);

    pub fn new(bytes: [u8; 2]) -> Self {
        Self { bytes }
    }

    pub fn allows(self, region: TransactionRegion, service: ServiceType) -> bool {
        let (channel_mask, service_mask) = match (region, service) {
            (TransactionRegion::Domestic, ServiceType::Cash) => {
                (Self::VALID_OTHER_THAN_ATM, Self::DOMESTIC_CASH)
            }
            (TransactionRegion::International, ServiceType::Cash) => {
                (Self::VALID_OTHER_THAN_ATM, Self::INTERNATIONAL_CASH)
            }
            (TransactionRegion::Domestic, ServiceType::Goods) => {
                (Self::VALID_OTHER_THAN_ATM, Self::DOMESTIC_GOODS)
            }
            (TransactionRegion::International, ServiceType::Goods) => {
                (Self::VALID_OTHER_THAN_ATM, Self::INTERNATIONAL_GOODS)
            }
            (TransactionRegion::Domestic, ServiceType::Services) => {
                (Self::VALID_OTHER_THAN_ATM, Self::DOMESTIC_SERVICES)
            }
            (TransactionRegion::International, ServiceType::Services) => {
                (Self::VALID_OTHER_THAN_ATM, Self::INTERNATIONAL_SERVICES)
            }
            (_, ServiceType::Atm) => (Self::VALID_AT_ATM, Self::VALID_AT_ATM),
            (TransactionRegion::Domestic, ServiceType::Cashback) => {
                (Self::VALID_OTHER_THAN_ATM, Self::DOMESTIC_CASHBACK)
            }
            (TransactionRegion::International, ServiceType::Cashback) => {
                (Self::VALID_OTHER_THAN_ATM, Self::INTERNATIONAL_CASHBACK)
            }
        };
        self.is_set(channel_mask) && self.is_set(service_mask)
    }

    fn is_set(self, mask: (usize, u8)) -> bool {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestrictionCheck {
    ApplicationVersion,
    ExpirationDate,
    EffectiveDate,
    ApplicationUsageControl,
    NewCard,
}

const RESTRICTION_CHECK_ORDER: [RestrictionCheck; 5] = [
    RestrictionCheck::ApplicationVersion,
    RestrictionCheck::ExpirationDate,
    RestrictionCheck::EffectiveDate,
    RestrictionCheck::ApplicationUsageControl,
    RestrictionCheck::NewCard,
];

pub fn evaluate(input: RestrictionInput, mut tvr: Tvr) -> RestrictionResult {
    let mut failed = false;

    for check in RESTRICTION_CHECK_ORDER {
        if let Some(bit) = check.tvr_bit(&input) {
            tvr.set(bit);
            failed = true;
        }
    }

    RestrictionResult { tvr, failed }
}

impl RestrictionCheck {
    fn tvr_bit(self, input: &RestrictionInput) -> Option<(usize, u8)> {
        match self {
            RestrictionCheck::ApplicationVersion => {
                let (Some(card), Some(terminal)) = (
                    input.card_application_version,
                    input.terminal_application_version,
                ) else {
                    return None;
                };
                (card != terminal).then_some(Tvr::B2_DIFFERENT_APPLICATION_VERSIONS)
            }
            RestrictionCheck::ExpirationDate => (input.transaction_date
                > input.application_expiration_date)
                .then_some(Tvr::B2_EXPIRED_APPLICATION),
            RestrictionCheck::EffectiveDate => input
                .application_effective_date
                .filter(|effective_date| input.transaction_date < *effective_date)
                .map(|_| Tvr::B2_APPLICATION_NOT_YET_EFFECTIVE),
            RestrictionCheck::ApplicationUsageControl => {
                (!input.auc.allows(input.region, input.service))
                    .then_some(Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED)
            }
            RestrictionCheck::NewCard => input.new_card.then_some(Tvr::B2_NEW_CARD),
        }
    }
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
            EmvDate::from_bcd([0x26, 0x02, 0x30]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            EmvDate::from_bcd([0x26, 0x04, 0x31]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            EmvDate::from_bcd([0x26, 0x00, 0x15]).unwrap_err(),
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
    fn auc_enforces_terminal_channel_and_region_specific_cashback_bits() {
        let domestic_goods_without_non_atm = ApplicationUsageControl::new([0x20, 0x00]);
        assert!(
            !domestic_goods_without_non_atm.allows(TransactionRegion::Domestic, ServiceType::Goods)
        );

        let domestic_goods = ApplicationUsageControl::new([0x21, 0x00]);
        assert!(domestic_goods.allows(TransactionRegion::Domestic, ServiceType::Goods));
        assert!(!domestic_goods.allows(TransactionRegion::International, ServiceType::Goods));

        let atm_only = ApplicationUsageControl::new([0x02, 0x00]);
        assert!(atm_only.allows(TransactionRegion::Domestic, ServiceType::Atm));
        assert!(!ApplicationUsageControl::new([0x01, 0x00])
            .allows(TransactionRegion::Domestic, ServiceType::Atm));

        let domestic_cashback = ApplicationUsageControl::new([0x01, 0x80]);
        assert!(domestic_cashback.allows(TransactionRegion::Domestic, ServiceType::Cashback));
        assert!(!domestic_cashback.allows(TransactionRegion::International, ServiceType::Cashback));

        let international_cashback = ApplicationUsageControl::new([0x01, 0x40]);
        assert!(
            international_cashback.allows(TransactionRegion::International, ServiceType::Cashback)
        );
        assert!(!international_cashback.allows(TransactionRegion::Domestic, ServiceType::Cashback));
    }

    #[test]
    fn restriction_checks_follow_emv_order_and_use_standard_tvr_bits() {
        let mut input = base_input();
        input.transaction_date = EmvDate::from_bcd([0x31, 0x01, 0x01]).unwrap();
        input.application_effective_date = Some(EmvDate::from_bcd([0x32, 0x01, 0x01]).unwrap());
        input.card_application_version = Some([0x00, 0x02]);
        input.auc = ApplicationUsageControl::new([0x00, 0x00]);
        input.new_card = true;

        assert_eq!(
            RESTRICTION_CHECK_ORDER,
            [
                RestrictionCheck::ApplicationVersion,
                RestrictionCheck::ExpirationDate,
                RestrictionCheck::EffectiveDate,
                RestrictionCheck::ApplicationUsageControl,
                RestrictionCheck::NewCard,
            ]
        );

        let bits = RESTRICTION_CHECK_ORDER
            .iter()
            .filter_map(|check| check.tvr_bit(&input))
            .collect::<Vec<_>>();
        assert_eq!(
            bits,
            vec![
                Tvr::B2_DIFFERENT_APPLICATION_VERSIONS,
                Tvr::B2_EXPIRED_APPLICATION,
                Tvr::B2_APPLICATION_NOT_YET_EFFECTIVE,
                Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED,
                Tvr::B2_NEW_CARD,
            ]
        );
        assert_eq!(
            evaluate(input, Tvr::cleared()).tvr.bytes(),
            [0x00, 0xf8, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn does_not_set_non_standard_bits_for_allowed_transaction() {
        let result = evaluate(base_input(), Tvr::cleared());
        assert!(!result.failed);
        assert_eq!(result.tvr.bytes(), [0; 5]);
    }
}
