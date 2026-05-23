use crate::error::{KernelError, KernelResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationInterchangeProfile {
    raw: [u8; 2],
}

impl ApplicationInterchangeProfile {
    pub fn parse(raw: &[u8]) -> KernelResult<Self> {
        let raw: [u8; 2] = raw
            .try_into()
            .map_err(|_| KernelError::MissingMandatoryTag)?;
        Ok(Self { raw })
    }

    pub fn new(raw: [u8; 2]) -> Self {
        Self { raw }
    }

    pub fn raw(self) -> [u8; 2] {
        self.raw
    }

    pub fn sda_supported(self) -> bool {
        self.raw[0] & 0x80 != 0
    }

    pub fn dda_supported(self) -> bool {
        self.raw[0] & 0x40 != 0
    }

    pub fn cda_supported(self) -> bool {
        self.raw[1] & 0x80 != 0
    }

    pub fn oda_required(self) -> bool {
        self.sda_supported() || self.dda_supported() || self.cda_supported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_runtime_oda_capability_bits() {
        let aip = ApplicationInterchangeProfile::parse(&[0xc0, 0x80]).unwrap();

        assert_eq!(aip.raw(), [0xc0, 0x80]);
        assert!(aip.sda_supported());
        assert!(aip.dda_supported());
        assert!(aip.cda_supported());
        assert!(aip.oda_required());

        let none = ApplicationInterchangeProfile::new([0x00, 0x00]);
        assert!(!none.sda_supported());
        assert!(!none.dda_supported());
        assert!(!none.cda_supported());
        assert!(!none.oda_required());
    }

    #[test]
    fn rejects_non_two_byte_aip_values() {
        assert_eq!(
            ApplicationInterchangeProfile::parse(&[0x80]).unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }
}
