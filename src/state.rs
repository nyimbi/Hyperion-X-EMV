#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelState {
    Idle,
    ParamsSet,
    SelectEnvironment,
    BuildCandidateList,
    SelectAid,
    Gpo,
    ReadRecords,
    OfflineDataAuthentication,
    ProcessingRestrictions,
    Cvm,
    TerminalRiskManagement,
    TerminalActionAnalysis,
    FirstGenerateAc,
    OnlineAuthorization,
    IssuerAuthentication,
    IssuerScripts,
    FinalOutcome,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tvr([u8; 5]);

impl Tvr {
    pub const B1_OFFLINE_DATA_AUTH_NOT_PERFORMED: (usize, u8) = (0, 0x80);
    pub const B1_SDA_FAILED: (usize, u8) = (0, 0x40);
    pub const B1_ICC_DATA_MISSING: (usize, u8) = (0, 0x20);
    pub const B1_CARD_ON_EXCEPTION_FILE: (usize, u8) = (0, 0x10);
    pub const B1_DDA_FAILED: (usize, u8) = (0, 0x08);
    pub const B1_CDA_FAILED: (usize, u8) = (0, 0x04);
    pub const B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL: (usize, u8) = (2, 0x80);
    pub const B4_FLOOR_LIMIT_EXCEEDED: (usize, u8) = (3, 0x80);
    pub const B4_RANDOM_TRANSACTION_SELECTION_PERFORMED: (usize, u8) = (3, 0x10);

    pub fn cleared() -> Self {
        Self([0; 5])
    }

    pub fn set(&mut self, bit: (usize, u8)) {
        self.0[bit.0] |= bit.1;
    }

    pub fn clear(&mut self, bit: (usize, u8)) {
        self.0[bit.0] &= !bit.1;
    }

    pub fn is_set(self, bit: (usize, u8)) -> bool {
        self.0[bit.0] & bit.1 != 0
    }

    pub fn bytes(self) -> [u8; 5] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tsi([u8; 2]);

impl Tsi {
    pub const OFFLINE_DATA_AUTHENTICATION_PERFORMED: (usize, u8) = (0, 0x80);
    pub const CARDHOLDER_VERIFICATION_PERFORMED: (usize, u8) = (0, 0x40);
    pub const CARD_RISK_MANAGEMENT_PERFORMED: (usize, u8) = (0, 0x20);
    pub const ISSUER_AUTHENTICATION_PERFORMED: (usize, u8) = (0, 0x10);
    pub const TERMINAL_RISK_MANAGEMENT_PERFORMED: (usize, u8) = (0, 0x08);
    pub const SCRIPT_PROCESSING_PERFORMED: (usize, u8) = (0, 0x04);

    pub fn cleared() -> Self {
        Self([0; 2])
    }

    pub fn set(&mut self, bit: (usize, u8)) {
        self.0[bit.0] |= bit.1;
    }

    pub fn is_set(self, bit: (usize, u8)) -> bool {
        self.0[bit.0] & bit.1 != 0
    }

    pub fn bytes(self) -> [u8; 2] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tvr_starts_cleared_for_each_transaction() {
        let tvr = Tvr::cleared();
        assert_eq!(tvr.bytes(), [0; 5]);
    }

    #[test]
    fn uses_symbolic_tvr_bits() {
        let mut tvr = Tvr::cleared();
        tvr.set(Tvr::B1_CDA_FAILED);
        assert_eq!(tvr.bytes(), [0x04, 0, 0, 0, 0]);
        assert!(tvr.is_set(Tvr::B1_CDA_FAILED));
    }
}
