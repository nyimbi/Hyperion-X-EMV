use crate::afl::{parse_afl, AflEntry};
use crate::dol::{parse_dol, DolEntry};
use crate::error::{KernelError, KernelResult};
use crate::tlv;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpoResponseFormat {
    Template77,
    Template80,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpoResponse {
    pub format: GpoResponseFormat,
    pub aip: [u8; 2],
    pub afl: Vec<AflEntry>,
}

pub fn parse_pdol_from_fci(fci: &[u8]) -> KernelResult<Vec<DolEntry>> {
    let parsed = tlv::parse_many(fci)?;
    if parsed.len() != 1 || parsed[0].tag != [0x6f] || !parsed[0].constructed {
        return Err(KernelError::MissingMandatoryTag);
    }

    let mut found_pdol = None;
    for fci_child in &parsed[0].children {
        if fci_child.tag != [0xa5] || !fci_child.constructed {
            continue;
        }
        if let Some(pdol) = tlv::find_unique_direct(&fci_child.children, &[0x9f, 0x38])? {
            if found_pdol.is_some() {
                return Err(KernelError::ParseError);
            }
            found_pdol = Some(pdol);
        }
    }

    match found_pdol {
        Some(pdol) => parse_dol(pdol),
        None => Ok(Vec::new()),
    }
}

pub fn parse_gpo_response(body: &[u8]) -> KernelResult<GpoResponse> {
    let parsed = tlv::parse_many(body)?;
    if parsed.len() != 1 {
        return Err(KernelError::MissingMandatoryTag);
    }

    match parsed[0].tag {
        [0x77] => parse_template_77(&parsed[0].children),
        [0x80] => parse_template_80(parsed[0].value),
        _ => Err(KernelError::MissingMandatoryTag),
    }
}

fn parse_template_77(children: &[tlv::Tlv<'_>]) -> KernelResult<GpoResponse> {
    let aip = fixed_aip(
        tlv::find_unique_direct(children, &[0x82])?.ok_or(KernelError::MissingMandatoryTag)?,
    )?;
    let afl_value =
        tlv::find_unique_direct(children, &[0x94])?.ok_or(KernelError::MissingMandatoryTag)?;
    let afl = parse_afl(afl_value)?;
    Ok(GpoResponse {
        format: GpoResponseFormat::Template77,
        aip,
        afl,
    })
}

fn parse_template_80(value: &[u8]) -> KernelResult<GpoResponse> {
    if value.len() < 2 {
        return Err(KernelError::MissingMandatoryTag);
    }
    let aip = fixed_aip(&value[..2])?;
    let afl = if value.len() == 2 {
        Vec::new()
    } else {
        parse_afl(&value[2..])?
    };
    Ok(GpoResponse {
        format: GpoResponseFormat::Template80,
        aip,
        afl,
    })
}

fn fixed_aip(value: &[u8]) -> KernelResult<[u8; 2]> {
    if value.len() != 2 {
        return Err(KernelError::MissingMandatoryTag);
    }
    Ok([value[0], value[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pdol_from_selected_application_fci() {
        let fci = [
            0x6f, 0x11, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x06, 0x9f,
            0x38, 0x03, 0x9f, 0x37, 0x04,
        ];
        assert_eq!(
            parse_pdol_from_fci(&fci).unwrap(),
            vec![DolEntry {
                tag: vec![0x9f, 0x37],
                length: 4
            }]
        );

        assert_eq!(
            parse_pdol_from_fci(&[0x9f, 0x38, 0x03, 0x9f, 0x37, 0x04]).unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        let misplaced = [
            0x6f, 0x0a, 0xa5, 0x08, 0xbf, 0x0c, 0x05, 0x9f, 0x38, 0x02, 0x9f, 0x37,
        ];
        assert_eq!(parse_pdol_from_fci(&misplaced).unwrap(), Vec::new());
    }

    #[test]
    fn rejects_duplicate_pdol_objects_in_selected_fci() {
        let duplicate_in_a5 = [
            0x6f, 0x12, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x07, 0x9f,
            0x38, 0x00, 0x9f, 0x38, 0x01, 0x9f,
        ];
        assert_eq!(
            parse_pdol_from_fci(&duplicate_in_a5).unwrap_err(),
            KernelError::ParseError
        );

        let duplicate_across_a5 = [
            0x6f, 0x15, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x03, 0x9f,
            0x38, 0x00, 0xa5, 0x05, 0x9f, 0x38, 0x02, 0x9f, 0x37,
        ];
        assert_eq!(
            parse_pdol_from_fci(&duplicate_across_a5).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn parses_gpo_template_77_with_aip_and_afl() {
        let parsed = parse_gpo_response(&[
            0x77, 0x0a, 0x82, 0x02, 0x18, 0x00, 0x94, 0x04, 0x10, 0x01, 0x01, 0x00,
        ])
        .unwrap();
        assert_eq!(parsed.format, GpoResponseFormat::Template77);
        assert_eq!(parsed.aip, [0x18, 0x00]);
        assert_eq!(parsed.afl.len(), 1);
    }

    #[test]
    fn parses_gpo_template_80_without_afl() {
        let parsed = parse_gpo_response(&[0x80, 0x02, 0x18, 0x00]).unwrap();
        assert_eq!(parsed.format, GpoResponseFormat::Template80);
        assert_eq!(parsed.aip, [0x18, 0x00]);
        assert!(parsed.afl.is_empty());
    }

    #[test]
    fn rejects_gpo_without_mandatory_aip_afl() {
        assert_eq!(
            parse_gpo_response(&[0x77, 0x04, 0x82, 0x02, 0x18, 0x00]).unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            parse_gpo_response(&[0x80, 0x01, 0x18]).unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn rejects_nested_or_duplicate_gpo_response_data() {
        assert_eq!(
            parse_gpo_response(&[
                0x77, 0x0c, 0xa5, 0x0a, 0x82, 0x02, 0x18, 0x00, 0x94, 0x04, 0x10, 0x01, 0x01, 0x00,
            ])
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        assert_eq!(
            parse_gpo_response(&[
                0x77, 0x0e, 0x82, 0x02, 0x18, 0x00, 0x82, 0x02, 0x20, 0x00, 0x94, 0x04, 0x10, 0x01,
                0x01, 0x00,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
    }
}
