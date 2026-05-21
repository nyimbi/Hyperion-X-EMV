use crate::dol::{build_dol_with_policy, DataStore, DolEntry, DolPaddingPolicy};
use crate::error::{KernelError, KernelResult};

pub const CONTACT_PSE: &[u8] = b"1PAY.SYS.DDF01";
pub const CONTACTLESS_PPSE: &[u8] = b"2PAY.SYS.DDF01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interface {
    Contact,
    Contactless,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

impl CommandApdu {
    pub fn encode(&self) -> KernelResult<Vec<u8>> {
        if self.data.len() > u8::MAX as usize {
            return Err(KernelError::LengthOverflow);
        }

        let mut out = Vec::with_capacity(5 + self.data.len() + usize::from(self.le.is_some()));
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if !self.data.is_empty() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptogramRequest {
    Aac,
    Tc,
    Arqc,
}

impl CryptogramRequest {
    pub fn p1(self) -> u8 {
        match self {
            CryptogramRequest::Aac => 0x00,
            CryptogramRequest::Tc => 0x40,
            CryptogramRequest::Arqc => 0x80,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CdaRequestControl {
    NotRequested,
    InCdolData,
    P1LowBits(u8),
}

pub fn select_environment(interface: Interface) -> CommandApdu {
    let data = match interface {
        Interface::Contact => CONTACT_PSE,
        Interface::Contactless => CONTACTLESS_PPSE,
    };
    select_by_name(data, 0x00)
}

pub fn select_aid(aid: &[u8], p2: u8) -> KernelResult<CommandApdu> {
    if aid.is_empty() || aid.len() > 16 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(select_by_name(aid, p2))
}

pub fn get_processing_options(pdol: &[DolEntry], data: &DataStore) -> KernelResult<CommandApdu> {
    let pdol_values = build_dol_with_policy(pdol, data, DolPaddingPolicy::ZeroPadMissingAndShort)?;
    if pdol_values.len() > 252 {
        return Err(KernelError::LengthOverflow);
    }

    let mut template = Vec::with_capacity(2 + pdol_values.len());
    template.push(0x83);
    template.push(pdol_values.len() as u8);
    template.extend_from_slice(&pdol_values);

    Ok(CommandApdu {
        cla: 0x80,
        ins: 0xa8,
        p1: 0x00,
        p2: 0x00,
        data: template,
        le: Some(0x00),
    })
}

pub fn read_record(record: u8, sfi: u8) -> KernelResult<CommandApdu> {
    if record == 0 || sfi == 0 || sfi > 30 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(CommandApdu {
        cla: 0x00,
        ins: 0xb2,
        p1: record,
        p2: (sfi << 3) | 0x04,
        data: Vec::new(),
        le: Some(0x00),
    })
}

pub fn internal_authenticate(ddol_values: &[u8]) -> KernelResult<CommandApdu> {
    if ddol_values.len() > u8::MAX as usize {
        return Err(KernelError::LengthOverflow);
    }
    Ok(CommandApdu {
        cla: 0x00,
        ins: 0x88,
        p1: 0x00,
        p2: 0x00,
        data: ddol_values.to_vec(),
        le: Some(0x00),
    })
}

pub fn internal_authenticate_from_ddol(
    ddol: &[DolEntry],
    data: &DataStore,
) -> KernelResult<CommandApdu> {
    let ddol_values = build_dol_with_policy(ddol, data, DolPaddingPolicy::ZeroPadMissingAndShort)?;
    internal_authenticate(&ddol_values)
}

pub fn external_authenticate(issuer_authentication_data: &[u8]) -> KernelResult<CommandApdu> {
    if issuer_authentication_data.is_empty() || issuer_authentication_data.len() > u8::MAX as usize
    {
        return Err(KernelError::InvalidArgument);
    }
    Ok(CommandApdu {
        cla: 0x00,
        ins: 0x82,
        p1: 0x00,
        p2: 0x00,
        data: issuer_authentication_data.to_vec(),
        le: None,
    })
}

pub fn get_response(length: u8) -> CommandApdu {
    CommandApdu {
        cla: 0x00,
        ins: 0xc0,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
        le: Some(length),
    }
}

pub fn generate_ac(
    request: CryptogramRequest,
    cdol_values: &[u8],
    cda_control: CdaRequestControl,
) -> KernelResult<CommandApdu> {
    if cdol_values.len() > u8::MAX as usize {
        return Err(KernelError::LengthOverflow);
    }

    let mut p1 = request.p1();
    match cda_control {
        CdaRequestControl::NotRequested | CdaRequestControl::InCdolData => {}
        CdaRequestControl::P1LowBits(bits) => {
            if bits & 0xc0 != 0 {
                return Err(KernelError::InvalidProfile);
            }
            p1 |= bits;
        }
    }

    if p1 & 0xc0 != request.p1() {
        return Err(KernelError::InvalidProfile);
    }

    Ok(CommandApdu {
        cla: 0x80,
        ins: 0xae,
        p1,
        p2: 0x00,
        data: cdol_values.to_vec(),
        le: Some(0x00),
    })
}

fn select_by_name(name: &[u8], p2: u8) -> CommandApdu {
    CommandApdu {
        cla: 0x00,
        ins: 0xa4,
        p1: 0x04,
        p2,
        data: name.to_vec(),
        le: Some(0x00),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dol::parse_dol;

    #[test]
    fn builds_exact_contact_pse_and_contactless_ppse_selects() {
        assert_eq!(
            select_environment(Interface::Contact).encode().unwrap(),
            [
                0x00, 0xa4, 0x04, 0x00, 0x0e, b'1', b'P', b'A', b'Y', b'.', b'S', b'Y', b'S', b'.',
                b'D', b'D', b'F', b'0', b'1', 0x00
            ]
        );
        assert_eq!(
            select_environment(Interface::Contactless).encode().unwrap(),
            [
                0x00, 0xa4, 0x04, 0x00, 0x0e, b'2', b'P', b'A', b'Y', b'.', b'S', b'Y', b'S', b'.',
                b'D', b'D', b'F', b'0', b'1', 0x00
            ]
        );
    }

    #[test]
    fn builds_get_response_for_status_word_followup() {
        assert_eq!(
            get_response(0x1a).encode().unwrap(),
            [0x00, 0xc0, 0x00, 0x00, 0x1a]
        );
    }

    #[test]
    fn builds_internal_authenticate_from_ddol_values() {
        let ddol = parse_dol(&[0x9f, 0x37, 0x04, 0x9f, 0x4c, 0x02]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x37], &[0x11, 0x22, 0x33, 0x44]).unwrap();

        assert_eq!(
            internal_authenticate_from_ddol(&ddol, &data)
                .unwrap()
                .encode()
                .unwrap(),
            [0x00, 0x88, 0x00, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn builds_gpo_with_tag_83_pdol_values() {
        let pdol = parse_dol(&[0x9f, 0x66, 0x04]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x66], &[0x36, 0x00, 0x40, 0x00]).unwrap();

        assert_eq!(
            get_processing_options(&pdol, &data)
                .unwrap()
                .encode()
                .unwrap(),
            [0x80, 0xa8, 0x00, 0x00, 0x06, 0x83, 0x04, 0x36, 0x00, 0x40, 0x00, 0x00]
        );
    }

    #[test]
    fn encodes_generate_ac_type_bits_without_cda_collision() {
        assert_eq!(
            generate_ac(CryptogramRequest::Aac, &[], CdaRequestControl::NotRequested)
                .unwrap()
                .p1,
            0x00
        );
        assert_eq!(
            generate_ac(CryptogramRequest::Tc, &[], CdaRequestControl::NotRequested)
                .unwrap()
                .p1,
            0x40
        );
        assert_eq!(
            generate_ac(
                CryptogramRequest::Arqc,
                &[],
                CdaRequestControl::NotRequested
            )
            .unwrap()
            .p1,
            0x80
        );
        assert_eq!(
            generate_ac(
                CryptogramRequest::Arqc,
                &[],
                CdaRequestControl::P1LowBits(0x10)
            )
            .unwrap()
            .p1,
            0x90
        );
        assert_eq!(
            generate_ac(
                CryptogramRequest::Arqc,
                &[],
                CdaRequestControl::P1LowBits(0x40)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn validates_read_record_sfi() {
        assert_eq!(
            read_record(2, 3).unwrap().encode().unwrap(),
            [0x00, 0xb2, 0x02, 0x1c, 0x00]
        );
        assert_eq!(
            read_record(1, 31).unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn builds_external_authenticate_for_issuer_authentication_data() {
        assert_eq!(
            external_authenticate(&[0x12, 0x34, 0x56, 0x78])
                .unwrap()
                .encode()
                .unwrap(),
            [0x00, 0x82, 0x00, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78]
        );
        assert_eq!(
            external_authenticate(&[]).unwrap_err(),
            KernelError::InvalidArgument
        );
    }
}
