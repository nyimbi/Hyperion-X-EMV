use crate::cid::Cid;
use crate::dol::DataStore;
use crate::error::{KernelError, KernelResult};
use crate::tlv;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateAcResponse {
    pub cid: Cid,
    pub application_cryptogram: [u8; 8],
    pub atc: [u8; 2],
    pub issuer_application_data: Vec<u8>,
    pub icc_dynamic_number: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineAuthorizationPackage {
    pub objects: Vec<TagValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagValue {
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
}

pub fn parse_generate_ac_response(input: &[u8]) -> KernelResult<GenerateAcResponse> {
    if input.first() == Some(&0x80) {
        return parse_format_1(input);
    }
    parse_format_2(input)
}

pub fn build_online_authorization_package(
    response: &GenerateAcResponse,
    data: &DataStore,
) -> OnlineAuthorizationPackage {
    let mut objects = vec![
        TagValue {
            tag: vec![0x9f, 0x26],
            value: response.application_cryptogram.to_vec(),
        },
        TagValue {
            tag: vec![0x9f, 0x27],
            value: vec![response.cid.raw()],
        },
        TagValue {
            tag: vec![0x9f, 0x36],
            value: response.atc.to_vec(),
        },
    ];

    if !response.issuer_application_data.is_empty() {
        objects.push(TagValue {
            tag: vec![0x9f, 0x10],
            value: response.issuer_application_data.clone(),
        });
    }

    for tag in [
        &[0x9f, 0x37][..],
        &[0x95][..],
        &[0x9a][..],
        &[0x9c][..],
        &[0x9f, 0x02][..],
        &[0x5f, 0x2a][..],
        &[0x82][..],
        &[0x9f, 0x1a][..],
        &[0x5a][..],
        &[0x57][..],
    ] {
        if let Some(value) = data.get(tag) {
            objects.push(TagValue {
                tag: tag.to_vec(),
                value: value.to_vec(),
            });
        }
    }

    OnlineAuthorizationPackage { objects }
}

fn parse_format_1(input: &[u8]) -> KernelResult<GenerateAcResponse> {
    let tlvs = tlv::parse_many(input)?;
    let value = tlvs
        .first()
        .filter(|tlv| tlv.tag == [0x80])
        .map(|tlv| tlv.value)
        .ok_or(KernelError::ParseError)?;
    if value.len() < 11 {
        return Err(KernelError::ParseError);
    }

    let mut application_cryptogram = [0u8; 8];
    application_cryptogram.copy_from_slice(&value[3..11]);
    Ok(GenerateAcResponse {
        cid: Cid::new(value[0]),
        atc: [value[1], value[2]],
        application_cryptogram,
        issuer_application_data: value[11..].to_vec(),
        icc_dynamic_number: None,
    })
}

fn parse_format_2(input: &[u8]) -> KernelResult<GenerateAcResponse> {
    let tlvs = tlv::parse_many(input)?;
    let cid = fixed::<1>(&tlvs, &[0x9f, 0x27])?;
    let application_cryptogram = fixed::<8>(&tlvs, &[0x9f, 0x26])?;
    let atc = fixed::<2>(&tlvs, &[0x9f, 0x36])?;
    let issuer_application_data =
        tlv::find_first(&tlvs, &[0x9f, 0x10]).map_or_else(Vec::new, |value| value.to_vec());
    let icc_dynamic_number = tlv::find_first(&tlvs, &[0x9f, 0x4c]).map(|value| value.to_vec());

    Ok(GenerateAcResponse {
        cid: Cid::new(cid[0]),
        application_cryptogram,
        atc,
        issuer_application_data,
        icc_dynamic_number,
    })
}

fn fixed<const N: usize>(tlvs: &[tlv::Tlv<'_>], tag: &[u8]) -> KernelResult<[u8; N]> {
    let value = tlv::find_first(tlvs, tag).ok_or(KernelError::MissingMandatoryTag)?;
    if value.len() != N {
        return Err(KernelError::ParseError);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(value);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::CryptogramType;

    #[test]
    fn parses_generate_ac_format_1_template_80() {
        let response = parse_generate_ac_response(&[
            0x80, 0x0d, 0x80, 0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x99,
            0x88,
        ])
        .unwrap();
        assert_eq!(response.cid.cryptogram_type(), CryptogramType::Arqc);
        assert_eq!(response.atc, [0x12, 0x34]);
        assert_eq!(
            response.application_cryptogram,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]
        );
        assert_eq!(response.issuer_application_data, vec![0x99, 0x88]);
    }

    #[test]
    fn parses_generate_ac_format_2_template_77() {
        let response = parse_generate_ac_response(&[
            0x77, 0x1a, 0x9f, 0x27, 0x01, 0x40, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x9f, 0x10, 0x03, 0xaa, 0xbb, 0xcc,
        ])
        .unwrap();
        assert_eq!(response.cid.cryptogram_type(), CryptogramType::Tc);
        assert_eq!(response.atc, [0x00, 0x09]);
        assert_eq!(
            response.application_cryptogram,
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]
        );
        assert_eq!(response.issuer_application_data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn builds_online_authorization_package_without_generating_cryptograms() {
        let response = parse_generate_ac_response(&[
            0x80, 0x0b, 0x80, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01,
        ])
        .unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x37], &[0x01, 0x02, 0x03, 0x04]).unwrap();
        data.put(&[0x95], &[0, 0, 0, 0, 0]).unwrap();

        let package = build_online_authorization_package(&response, &data);
        assert_eq!(package.objects[0].tag, vec![0x9f, 0x26]);
        assert_eq!(package.objects[0].value, response.application_cryptogram);
        assert!(package
            .objects
            .iter()
            .any(|object| object.tag == [0x9f, 0x37]));
        assert!(package.objects.iter().any(|object| object.tag == [0x95]));
    }
}
