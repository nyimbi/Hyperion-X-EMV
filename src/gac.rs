use crate::cid::Cid;
use crate::dol::DataStore;
use crate::error::{KernelError, KernelResult};
use crate::tlv;
use core::fmt;

#[derive(Clone, Eq, PartialEq)]
pub struct GenerateAcResponse {
    pub cid: Cid,
    pub application_cryptogram: [u8; 8],
    pub atc: [u8; 2],
    pub issuer_application_data: Vec<u8>,
    pub icc_dynamic_number: Option<Vec<u8>>,
    pub signed_dynamic_application_data: Option<Vec<u8>>,
}

impl fmt::Debug for GenerateAcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenerateAcResponse")
            .field("cid", &self.cid)
            .field("atc", &self.atc)
            .field(
                "issuer_application_data_len",
                &self.issuer_application_data.len(),
            )
            .field(
                "icc_dynamic_number_len",
                &self.icc_dynamic_number.as_ref().map(Vec::len),
            )
            .field(
                "signed_dynamic_application_data_len",
                &self.signed_dynamic_application_data.as_ref().map(Vec::len),
            )
            .field(
                "data_policy",
                &"application cryptogram and dynamic authentication data redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OnlineAuthorizationPackage {
    pub objects: Vec<TagValue>,
}

impl fmt::Debug for OnlineAuthorizationPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineAuthorizationPackage")
            .field("object_count", &self.objects.len())
            .field("objects", &self.objects)
            .field("data_policy", &"object values redacted for crash safety")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TagValue {
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
}

impl fmt::Debug for TagValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TagValue")
            .field("tag", &self.tag)
            .field("value_len", &self.value.len())
            .field("data_policy", &"value redacted for crash safety")
            .finish()
    }
}

pub fn parse_generate_ac_response(input: &[u8]) -> KernelResult<GenerateAcResponse> {
    let tlvs = tlv::parse_many(input)?;
    if tlvs.len() != 1 {
        return Err(KernelError::MissingMandatoryTag);
    }

    match tlvs[0].tag {
        [0x80] => parse_format_1(tlvs[0].value),
        [0x77] => parse_format_2(&tlvs[0].children),
        _ => Err(KernelError::MissingMandatoryTag),
    }
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
        &[0x9f, 0x33][..],
        &[0x9f, 0x34][..],
        &[0x9f, 0x66][..],
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

fn parse_format_1(value: &[u8]) -> KernelResult<GenerateAcResponse> {
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
        signed_dynamic_application_data: None,
    })
}

fn parse_format_2(children: &[tlv::Tlv<'_>]) -> KernelResult<GenerateAcResponse> {
    reject_constructed_format_2_children(children)?;
    let cid = fixed::<1>(children, &[0x9f, 0x27])?;
    let application_cryptogram = fixed::<8>(children, &[0x9f, 0x26])?;
    let atc = fixed::<2>(children, &[0x9f, 0x36])?;
    let issuer_application_data = tlv::find_unique_direct(children, &[0x9f, 0x10])?
        .map_or_else(Vec::new, |value| value.to_vec());
    let icc_dynamic_number =
        tlv::find_unique_direct(children, &[0x9f, 0x4c])?.map(|value| value.to_vec());
    let signed_dynamic_application_data =
        tlv::find_unique_direct(children, &[0x9f, 0x4b])?.map(|value| value.to_vec());

    Ok(GenerateAcResponse {
        cid: Cid::new(cid[0]),
        application_cryptogram,
        atc,
        issuer_application_data,
        icc_dynamic_number,
        signed_dynamic_application_data,
    })
}

fn reject_constructed_format_2_children(children: &[tlv::Tlv<'_>]) -> KernelResult<()> {
    if children.iter().any(|child| child.constructed) {
        return Err(KernelError::ParseError);
    }
    Ok(())
}

fn fixed<const N: usize>(children: &[tlv::Tlv<'_>], tag: &[u8]) -> KernelResult<[u8; N]> {
    let value = tlv::find_unique_direct(children, tag)?.ok_or(KernelError::MissingMandatoryTag)?;
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
    fn rejects_generate_ac_without_single_supported_response_template() {
        assert_eq!(
            parse_generate_ac_response(&[
                0x9f, 0x27, 0x01, 0x40, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            ])
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            parse_generate_ac_response(&[
                0x80, 0x0b, 0x80, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01, 0x9f,
                0x10, 0x01, 0xaa,
            ])
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn rejects_nested_or_duplicate_generate_ac_format_2_data() {
        assert_eq!(
            parse_generate_ac_response(&[
                0x77, 0x16, 0xa5, 0x14, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f,
                0x26, 0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_generate_ac_response(&[
                0x77, 0x2a, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xa5, 0x14, 0x9f, 0x27, 0x01, 0x40,
                0x9f, 0x36, 0x02, 0x00, 0x0a, 0x9f, 0x26, 0x08, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_generate_ac_response(&[
                0x77, 0x1f, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x9f, 0x26, 0x08, 0x20, 0x21, 0x22,
                0x23, 0x24, 0x25, 0x26, 0x27,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_generate_ac_response(&[
                0x77, 0x1c, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x09, 0x9f, 0x26, 0x08,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x9f, 0x10, 0x01, 0xaa, 0x9f, 0x10,
                0x01, 0xbb,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
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
        data.put(&[0x9f, 0x33], &[0xe0, 0xb0, 0xc8]).unwrap();
        data.put(&[0x9f, 0x34], &[0x01, 0x00, 0x02]).unwrap();
        data.put(&[0x9f, 0x66], &[0x36, 0x00, 0x40, 0x00]).unwrap();

        let package = build_online_authorization_package(&response, &data);
        assert_eq!(package.objects[0].tag, vec![0x9f, 0x26]);
        assert_eq!(package.objects[0].value, response.application_cryptogram);
        assert!(package
            .objects
            .iter()
            .any(|object| object.tag == [0x9f, 0x37]));
        assert!(package.objects.iter().any(|object| object.tag == [0x95]));
        assert!(package
            .objects
            .iter()
            .any(|object| object.tag == [0x9f, 0x34] && object.value == [0x01, 0x00, 0x02]));
        assert!(package
            .objects
            .iter()
            .any(|object| object.tag == [0x9f, 0x33] && object.value == [0xe0, 0xb0, 0xc8]));
        assert!(package.objects.iter().any(|object| {
            object.tag == [0x9f, 0x66] && object.value == [0x36, 0x00, 0x40, 0x00]
        }));
    }

    #[test]
    fn online_authorization_debug_redacts_cryptograms_and_card_data() {
        let response = parse_generate_ac_response(&[
            0x77, 0x1f, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x12, 0x34, 0x9f, 0x26, 0x08,
            0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd, 0x9f, 0x10, 0x03, 0x11, 0x22, 0x33,
            0x9f, 0x4c, 0x02, 0x44, 0x55,
        ])
        .unwrap();
        let response_debug = format!("{response:?}");
        assert!(response_debug.contains("GenerateAcResponse"));
        assert!(response_debug.contains("redacted for crash safety"));
        for raw_byte in [
            "222", "173", "190", "239", "170", "187", "204", "221", "68", "85",
        ] {
            assert!(!response_debug.contains(raw_byte));
        }

        let mut data = DataStore::new();
        data.put(&[0x5a], &[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f])
            .unwrap();
        data.put(
            &[0x57],
            &[
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0xd2, 0x51, 0x22, 0x01, 0x23, 0x45,
            ],
        )
        .unwrap();

        let package = build_online_authorization_package(&response, &data);
        let package_debug = format!("{package:?}");
        assert!(package_debug.contains("OnlineAuthorizationPackage"));
        assert!(package_debug.contains("object values redacted"));
        assert!(package_debug.contains("value_len"));
        assert!(!package_debug.contains("123456789012345"));
        for raw_byte in [
            "222", "173", "190", "239", "170", "187", "204", "221", "18", "52", "86", "120",
        ] {
            assert!(!package_debug.contains(raw_byte));
        }
    }
}
