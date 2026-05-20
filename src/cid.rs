#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptogramType {
    Aac,
    Tc,
    Arqc,
    ApplicationAuthenticationReferral,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cid {
    raw: u8,
}

impl Cid {
    pub fn new(raw: u8) -> Self {
        Self { raw }
    }

    pub fn raw(self) -> u8 {
        self.raw
    }

    pub fn cryptogram_type(self) -> CryptogramType {
        match self.raw & 0xc0 {
            0x00 => CryptogramType::Aac,
            0x40 => CryptogramType::Tc,
            0x80 => CryptogramType::Arqc,
            _ => CryptogramType::ApplicationAuthenticationReferral,
        }
    }

    pub fn advice_required(self) -> bool {
        self.raw & 0x08 != 0
    }

    pub fn reason_advice_code(self) -> u8 {
        self.raw & 0x07
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_cryptogram_type_with_0xc0_mask() {
        assert_eq!(Cid::new(0x00).cryptogram_type(), CryptogramType::Aac);
        assert_eq!(Cid::new(0x47).cryptogram_type(), CryptogramType::Tc);
        assert_eq!(Cid::new(0x8f).cryptogram_type(), CryptogramType::Arqc);
        assert_eq!(
            Cid::new(0xc0).cryptogram_type(),
            CryptogramType::ApplicationAuthenticationReferral
        );
    }
}
