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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdditionalTerminalCapabilities {
    raw: [u8; 5],
}

impl AdditionalTerminalCapabilities {
    pub fn parse(raw: &[u8]) -> KernelResult<Self> {
        let raw: [u8; 5] = raw.try_into().map_err(|_| KernelError::ParseError)?;
        Ok(Self { raw })
    }

    pub fn raw(self) -> [u8; 5] {
        self.raw
    }

    pub fn bit_is_set(self, byte_index: usize, mask: u8) -> bool {
        self.raw
            .get(byte_index)
            .is_some_and(|byte| byte & mask != 0)
    }

    pub fn set_bit_count(self) -> usize {
        self.raw.iter().map(|byte| byte.count_ones() as usize).sum()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalCapabilityBit {
    byte_index: usize,
    mask: u8,
    name: &'static str,
}

impl TerminalCapabilityBit {
    pub const fn new(byte_index: usize, mask: u8, name: &'static str) -> Self {
        Self {
            byte_index,
            mask,
            name,
        }
    }

    pub fn byte_index(self) -> usize {
        self.byte_index
    }

    pub fn mask(self) -> u8 {
        self.mask
    }

    pub fn name(self) -> &'static str {
        self.name
    }
}

pub const TERMINAL_CAPABILITY_ALLOWED_MASKS: [u8; 3] = [0xe0, 0xf8, 0xe8];

pub const TERMINAL_CAPABILITY_BITS: [TerminalCapabilityBit; 12] = [
    TerminalCapabilityBit::new(0, 0x80, "manual-key-entry"),
    TerminalCapabilityBit::new(0, 0x40, "magnetic-stripe"),
    TerminalCapabilityBit::new(0, 0x20, "icc-with-contacts"),
    TerminalCapabilityBit::new(1, 0x80, "plaintext-pin-for-icc-verification"),
    TerminalCapabilityBit::new(1, 0x40, "enciphered-pin-for-online-verification"),
    TerminalCapabilityBit::new(1, 0x20, "signature-paper"),
    TerminalCapabilityBit::new(1, 0x10, "enciphered-pin-for-offline-verification"),
    TerminalCapabilityBit::new(1, 0x08, "no-cvm-required"),
    TerminalCapabilityBit::new(2, 0x80, "sda-supported"),
    TerminalCapabilityBit::new(2, 0x40, "dda-supported"),
    TerminalCapabilityBit::new(2, 0x20, "card-capture-supported"),
    TerminalCapabilityBit::new(2, 0x08, "cda-supported"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalCapabilities {
    raw: [u8; 3],
}

impl TerminalCapabilities {
    pub fn parse(raw: &[u8]) -> KernelResult<Self> {
        let raw: [u8; 3] = raw.try_into().map_err(|_| KernelError::ParseError)?;
        Ok(Self { raw })
    }

    pub fn raw(self) -> [u8; 3] {
        self.raw
    }

    pub fn has_rfu_bits(self) -> bool {
        self.raw
            .iter()
            .zip(TERMINAL_CAPABILITY_ALLOWED_MASKS)
            .any(|(byte, allowed)| byte & !allowed != 0)
    }

    pub fn bit_is_set(self, bit: TerminalCapabilityBit) -> bool {
        self.raw
            .get(bit.byte_index)
            .is_some_and(|byte| byte & bit.mask != 0)
    }

    pub fn manual_key_entry(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[0])
    }

    pub fn magnetic_stripe(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[1])
    }

    pub fn icc_with_contacts(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[2])
    }

    pub fn plaintext_pin_for_icc_verification(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[3])
    }

    pub fn enciphered_pin_for_online_verification(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[4])
    }

    pub fn signature_paper(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[5])
    }

    pub fn enciphered_pin_for_offline_verification(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[6])
    }

    pub fn no_cvm_required(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[7])
    }

    pub fn sda_supported(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[8])
    }

    pub fn dda_supported(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[9])
    }

    pub fn card_capture_supported(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[10])
    }

    pub fn cda_supported(self) -> bool {
        self.bit_is_set(TERMINAL_CAPABILITY_BITS[11])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_terminal_types_and_online_capability() {
        let expected = [
            (
                0x11,
                TerminalOperator::Attended,
                TerminalLocation::FinancialInstitution,
                true,
            ),
            (
                0x12,
                TerminalOperator::Attended,
                TerminalLocation::FinancialInstitution,
                true,
            ),
            (
                0x13,
                TerminalOperator::Attended,
                TerminalLocation::FinancialInstitution,
                false,
            ),
            (
                0x14,
                TerminalOperator::Unattended,
                TerminalLocation::FinancialInstitution,
                true,
            ),
            (
                0x15,
                TerminalOperator::Unattended,
                TerminalLocation::FinancialInstitution,
                true,
            ),
            (
                0x16,
                TerminalOperator::Unattended,
                TerminalLocation::FinancialInstitution,
                false,
            ),
            (
                0x21,
                TerminalOperator::Attended,
                TerminalLocation::Merchant,
                true,
            ),
            (
                0x22,
                TerminalOperator::Attended,
                TerminalLocation::Merchant,
                true,
            ),
            (
                0x23,
                TerminalOperator::Attended,
                TerminalLocation::Merchant,
                false,
            ),
            (
                0x24,
                TerminalOperator::Unattended,
                TerminalLocation::Merchant,
                true,
            ),
            (
                0x25,
                TerminalOperator::Unattended,
                TerminalLocation::Merchant,
                true,
            ),
            (
                0x26,
                TerminalOperator::Unattended,
                TerminalLocation::Merchant,
                false,
            ),
            (
                0x34,
                TerminalOperator::Unattended,
                TerminalLocation::Cardholder,
                true,
            ),
            (
                0x35,
                TerminalOperator::Unattended,
                TerminalLocation::Cardholder,
                true,
            ),
            (
                0x36,
                TerminalOperator::Unattended,
                TerminalLocation::Cardholder,
                false,
            ),
        ];
        for (raw, operator, location, online_capable) in expected {
            let terminal_type = TerminalType::parse(raw).unwrap();
            assert_eq!(terminal_type.raw(), raw);
            assert_eq!(terminal_type.operator(), operator);
            assert_eq!(terminal_type.location(), location);
            assert_eq!(terminal_type.online_capable(), online_capable);
            assert_eq!(terminal_type_online_capable(raw).unwrap(), online_capable);
        }
        assert_eq!(TerminalOperator::Attended.label(), "attended");
        assert_eq!(TerminalOperator::Unattended.label(), "unattended");
        assert_eq!(
            TerminalLocation::FinancialInstitution.label(),
            "financial-institution"
        );
        assert_eq!(TerminalLocation::Merchant.label(), "merchant");
        assert_eq!(TerminalLocation::Cardholder.label(), "cardholder");

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

    #[test]
    fn parses_additional_terminal_capabilities_as_exact_terminal_bitmap() {
        let capabilities =
            AdditionalTerminalCapabilities::parse(&[0x70, 0x80, 0xf0, 0xf0, 0xff]).unwrap();

        assert_eq!(capabilities.raw(), [0x70, 0x80, 0xf0, 0xf0, 0xff]);
        assert!(capabilities.bit_is_set(0, 0x40));
        assert!(capabilities.bit_is_set(1, 0x80));
        assert!(capabilities.bit_is_set(2, 0x10));
        assert!(capabilities.bit_is_set(4, 0x01));
        assert_eq!(capabilities.set_bit_count(), 20);
        assert_eq!(
            AdditionalTerminalCapabilities::parse(&[0x70, 0x80, 0xf0, 0xf0]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn parses_terminal_capabilities_and_names_standard_bits() {
        let capabilities = TerminalCapabilities::parse(&[0xe0, 0xb0, 0xc8]).unwrap();

        assert_eq!(capabilities.raw(), [0xe0, 0xb0, 0xc8]);
        assert!(!capabilities.has_rfu_bits());
        assert!(capabilities.manual_key_entry());
        assert!(capabilities.magnetic_stripe());
        assert!(capabilities.icc_with_contacts());
        assert!(capabilities.plaintext_pin_for_icc_verification());
        assert!(!capabilities.enciphered_pin_for_online_verification());
        assert!(capabilities.signature_paper());
        assert!(capabilities.enciphered_pin_for_offline_verification());
        assert!(!capabilities.no_cvm_required());
        assert!(capabilities.sda_supported());
        assert!(capabilities.dda_supported());
        assert!(!capabilities.card_capture_supported());
        assert!(capabilities.cda_supported());
        let bit_summary = TERMINAL_CAPABILITY_BITS
            .iter()
            .map(|bit| (bit.byte_index(), bit.mask(), bit.name()))
            .collect::<Vec<_>>();
        assert!(bit_summary.contains(&(0, 0x20, "icc-with-contacts")));
        assert!(bit_summary.contains(&(2, 0x08, "cda-supported")));
        assert_eq!(bit_summary.len(), 12);
    }

    #[test]
    fn terminal_capabilities_flags_rfu_bits_without_rejecting_profile_review() {
        let capabilities = TerminalCapabilities::parse(&[0x01, 0x00, 0x01]).unwrap();

        assert!(capabilities.has_rfu_bits());
        assert!(!capabilities.manual_key_entry());
    }

    #[test]
    fn rejects_non_three_byte_terminal_capabilities() {
        assert_eq!(
            TerminalCapabilities::parse(&[0xe0, 0xb0]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn terminal_capability_bit_constructor_preserves_catalogue_fields() {
        let bit = TerminalCapabilityBit::new(2, 0x40, "offline PIN");
        assert_eq!(bit.byte_index(), 2);
        assert_eq!(bit.mask(), 0x40);
        assert_eq!(bit.name(), "offline PIN");
    }
}
