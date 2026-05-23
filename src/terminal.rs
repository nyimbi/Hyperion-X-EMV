use crate::error::{KernelError, KernelResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOperator {
    Attended,
    Unattended,
}

impl TerminalOperator {
    pub fn label(self) -> &'static str {
        match self {
            Self::Attended => "attended",
            Self::Unattended => "unattended",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalLocation {
    FinancialInstitution,
    Merchant,
    Cardholder,
}

impl TerminalLocation {
    pub fn label(self) -> &'static str {
        match self {
            Self::FinancialInstitution => "financial-institution",
            Self::Merchant => "merchant",
            Self::Cardholder => "cardholder",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalType {
    raw: u8,
    operator: TerminalOperator,
    location: TerminalLocation,
    online_capable: bool,
}

impl TerminalType {
    pub fn parse(raw: u8) -> KernelResult<Self> {
        let (operator, location, online_capable) = match raw {
            0x11 | 0x12 => (
                TerminalOperator::Attended,
                TerminalLocation::FinancialInstitution,
                true,
            ),
            0x13 => (
                TerminalOperator::Attended,
                TerminalLocation::FinancialInstitution,
                false,
            ),
            0x14 | 0x15 => (
                TerminalOperator::Unattended,
                TerminalLocation::FinancialInstitution,
                true,
            ),
            0x16 => (
                TerminalOperator::Unattended,
                TerminalLocation::FinancialInstitution,
                false,
            ),
            0x21 | 0x22 => (TerminalOperator::Attended, TerminalLocation::Merchant, true),
            0x23 => (
                TerminalOperator::Attended,
                TerminalLocation::Merchant,
                false,
            ),
            0x24 | 0x25 => (
                TerminalOperator::Unattended,
                TerminalLocation::Merchant,
                true,
            ),
            0x26 => (
                TerminalOperator::Unattended,
                TerminalLocation::Merchant,
                false,
            ),
            0x34 | 0x35 => (
                TerminalOperator::Unattended,
                TerminalLocation::Cardholder,
                true,
            ),
            0x36 => (
                TerminalOperator::Unattended,
                TerminalLocation::Cardholder,
                false,
            ),
            _ => return Err(KernelError::InvalidArgument),
        };

        Ok(Self {
            raw,
            operator,
            location,
            online_capable,
        })
    }

    pub fn raw(self) -> u8 {
        self.raw
    }

    pub fn operator(self) -> TerminalOperator {
        self.operator
    }

    pub fn location(self) -> TerminalLocation {
        self.location
    }

    pub fn online_capable(self) -> bool {
        self.online_capable
    }
}

pub fn terminal_type_online_capable(raw: u8) -> KernelResult<bool> {
    TerminalType::parse(raw).map(TerminalType::online_capable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_terminal_types_and_online_capability() {
        let attended_merchant = TerminalType::parse(0x22).unwrap();
        assert_eq!(attended_merchant.raw(), 0x22);
        assert_eq!(attended_merchant.operator(), TerminalOperator::Attended);
        assert_eq!(attended_merchant.location(), TerminalLocation::Merchant);
        assert!(attended_merchant.online_capable());

        let offline_only = TerminalType::parse(0x23).unwrap();
        assert_eq!(offline_only.operator(), TerminalOperator::Attended);
        assert_eq!(offline_only.location(), TerminalLocation::Merchant);
        assert!(!offline_only.online_capable());

        let unattended_cardholder = TerminalType::parse(0x34).unwrap();
        assert_eq!(
            unattended_cardholder.operator(),
            TerminalOperator::Unattended
        );
        assert_eq!(
            unattended_cardholder.location(),
            TerminalLocation::Cardholder
        );
        assert!(unattended_cardholder.online_capable());
    }

    #[test]
    fn rejects_unknown_terminal_types() {
        assert_eq!(
            TerminalType::parse(0x00).unwrap_err(),
            KernelError::InvalidArgument
        );
        assert_eq!(
            terminal_type_online_capable(0x99).unwrap_err(),
            KernelError::InvalidArgument
        );
    }
}
