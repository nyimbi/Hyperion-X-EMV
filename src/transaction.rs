use crate::error::{KernelError, KernelResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrencyExponent(u8);

impl CurrencyExponent {
    pub fn parse(raw: &[u8]) -> KernelResult<Self> {
        let [value]: [u8; 1] = raw.try_into().map_err(|_| KernelError::ParseError)?;
        Self::from_value(value)
    }

    pub fn from_value(value: u8) -> KernelResult<Self> {
        if value <= 9 {
            Ok(Self(value))
        } else {
            Err(KernelError::InvalidArgument)
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionType(u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeService {
    GoodsOrServices,
    Cash,
    Cashback,
}

impl RuntimeService {
    pub fn label(self) -> &'static str {
        match self {
            Self::GoodsOrServices => "goods-or-services",
            Self::Cash => "cash",
            Self::Cashback => "cashback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvmTransactionClass {
    NonCash,
    UnattendedCash,
    ManualCash,
    PurchaseWithCashback,
}

impl CvmTransactionClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::NonCash => "non-cash",
            Self::UnattendedCash => "unattended-cash",
            Self::ManualCash => "manual-cash",
            Self::PurchaseWithCashback => "purchase-with-cashback",
        }
    }
}

impl TransactionType {
    pub fn parse(raw: &[u8]) -> KernelResult<Self> {
        let [value]: [u8; 1] = raw.try_into().map_err(|_| KernelError::ParseError)?;
        Ok(Self(value))
    }

    pub fn from_value(value: u8) -> Self {
        Self(value)
    }

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn runtime_service(self) -> RuntimeService {
        match self.0 {
            0x01 => RuntimeService::Cash,
            0x09 | 0x17 => RuntimeService::Cashback,
            _ => RuntimeService::GoodsOrServices,
        }
    }

    pub fn cvm_transaction_class(self, terminal_type_is_atm: bool) -> CvmTransactionClass {
        if terminal_type_is_atm {
            CvmTransactionClass::UnattendedCash
        } else {
            match self.0 {
                0x01 => CvmTransactionClass::ManualCash,
                0x09 | 0x17 => CvmTransactionClass::PurchaseWithCashback,
                _ => CvmTransactionClass::NonCash,
            }
        }
    }

    pub fn mapping_authority(self) -> &'static str {
        match self.0 {
            0x00 | 0x01 | 0x09 | 0x17 => "runtime-cvm-trm-service-mapping",
            _ => "profile-defined-or-unmapped",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn currency_exponent_matches_transaction_param_domain() {
        assert_eq!(CurrencyExponent::parse(&[2]).unwrap().value(), 2);
        assert_eq!(
            CurrencyExponent::parse(&[10]),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(CurrencyExponent::parse(&[]), Err(KernelError::ParseError));
    }

    #[test]
    fn transaction_type_exposes_runtime_service_mapping() {
        assert_eq!(
            TransactionType::parse(&[0x00]).unwrap().runtime_service(),
            RuntimeService::GoodsOrServices
        );
        assert_eq!(
            TransactionType::parse(&[0x01])
                .unwrap()
                .cvm_transaction_class(false),
            CvmTransactionClass::ManualCash
        );
        assert_eq!(
            TransactionType::parse(&[0x09])
                .unwrap()
                .cvm_transaction_class(false),
            CvmTransactionClass::PurchaseWithCashback
        );
        assert_eq!(
            TransactionType::parse(&[0x17]).unwrap().runtime_service(),
            RuntimeService::Cashback
        );
        assert_eq!(
            TransactionType::parse(&[0x99]).unwrap().mapping_authority(),
            "profile-defined-or-unmapped"
        );
        assert_eq!(
            TransactionType::parse(&[0x00])
                .unwrap()
                .cvm_transaction_class(true),
            CvmTransactionClass::UnattendedCash
        );
        assert_eq!(TransactionType::parse(&[]), Err(KernelError::ParseError));
    }
}
