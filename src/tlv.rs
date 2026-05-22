use core::fmt;

use crate::error::{KernelError, KernelResult};

pub const MAX_TLV_DEPTH: usize = 8;
pub const MAX_TLV_NODES: usize = 512;
pub const MAX_TLV_VALUE_LENGTH: usize = 4096;

#[derive(Clone, Eq, PartialEq)]
pub struct Tlv<'a> {
    pub tag: &'a [u8],
    pub value: &'a [u8],
    pub constructed: bool,
    pub children: Vec<Tlv<'a>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct FlatTlv<'a> {
    pub tag: &'a [u8],
    pub value: &'a [u8],
    pub constructed: bool,
}

impl fmt::Debug for Tlv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tlv")
            .field("tag", &self.tag)
            .field("value_len", &self.value.len())
            .field("constructed", &self.constructed)
            .field("child_count", &self.children.len())
            .field("data_policy", &"TLV value bytes redacted for crash safety")
            .finish()
    }
}

impl fmt::Debug for FlatTlv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlatTlv")
            .field("tag", &self.tag)
            .field("value_len", &self.value.len())
            .field("constructed", &self.constructed)
            .field("data_policy", &"TLV value bytes redacted for crash safety")
            .finish()
    }
}

pub fn parse_many(input: &[u8]) -> KernelResult<Vec<Tlv<'_>>> {
    let mut offset = 0;
    let mut nodes = 0;
    parse_sequence(input, &mut offset, 0, &mut nodes)
}

pub fn flatten<'a>(tlvs: &'a [Tlv<'a>]) -> Vec<FlatTlv<'a>> {
    fn walk<'a>(tlv: &'a Tlv<'a>, out: &mut Vec<FlatTlv<'a>>) {
        out.push(FlatTlv {
            tag: tlv.tag,
            value: tlv.value,
            constructed: tlv.constructed,
        });
        for child in &tlv.children {
            walk(child, out);
        }
    }

    let mut out = Vec::new();
    for tlv in tlvs {
        walk(tlv, &mut out);
    }
    out
}

pub fn find_first<'a>(tlvs: &'a [Tlv<'a>], tag: &[u8]) -> Option<&'a [u8]> {
    for tlv in tlvs {
        if tlv.tag == tag {
            return Some(tlv.value);
        }
        if let Some(found) = find_first(&tlv.children, tag) {
            return Some(found);
        }
    }
    None
}

/// Returns one direct child value for `tag`.
///
/// This intentionally does not descend into constructed descendants. EMV
/// response-template parsers use it when object provenance matters and duplicate
/// response objects would make the card response ambiguous.
pub fn find_unique_direct<'a>(tlvs: &'a [Tlv<'a>], tag: &[u8]) -> KernelResult<Option<&'a [u8]>> {
    let mut found = None;
    for tlv in tlvs {
        if tlv.tag == tag {
            if found.is_some() {
                return Err(KernelError::ParseError);
            }
            found = Some(tlv.value);
        }
    }
    Ok(found)
}

fn parse_sequence<'a>(
    input: &'a [u8],
    offset: &mut usize,
    depth: usize,
    nodes: &mut usize,
) -> KernelResult<Vec<Tlv<'a>>> {
    if depth > MAX_TLV_DEPTH {
        return Err(KernelError::ParseError);
    }

    let mut out = Vec::new();
    while *offset < input.len() {
        if *nodes >= MAX_TLV_NODES {
            return Err(KernelError::LengthOverflow);
        }
        *nodes += 1;

        let tag_start = *offset;
        let constructed = read_tag(input, offset)?;
        let tag = &input[tag_start..*offset];
        let length = read_length(input, offset)?;
        let value_end = offset
            .checked_add(length)
            .filter(|end| *end <= input.len())
            .ok_or(KernelError::LengthOverflow)?;
        let value = &input[*offset..value_end];
        *offset = value_end;

        let children = if constructed {
            let mut child_offset = 0;
            parse_sequence(value, &mut child_offset, depth + 1, nodes)?
        } else {
            Vec::new()
        };

        out.push(Tlv {
            tag,
            value,
            constructed,
            children,
        });
    }
    Ok(out)
}

fn read_tag(input: &[u8], offset: &mut usize) -> KernelResult<bool> {
    let first = *input.get(*offset).ok_or(KernelError::ParseError)?;
    if first == 0x00 || first == 0xff {
        return Err(KernelError::ParseError);
    }
    *offset += 1;
    let constructed = first & 0x20 != 0;

    if first & 0x1f == 0x1f {
        let mut continuation_count = 0usize;
        loop {
            let byte = *input.get(*offset).ok_or(KernelError::ParseError)?;
            *offset += 1;
            continuation_count += 1;
            if continuation_count == 1 && byte & 0x7f == 0 {
                return Err(KernelError::ParseError);
            }
            if continuation_count > 3 {
                return Err(KernelError::ParseError);
            }
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    Ok(constructed)
}

fn read_length(input: &[u8], offset: &mut usize) -> KernelResult<usize> {
    let first = *input.get(*offset).ok_or(KernelError::ParseError)?;
    *offset += 1;

    if first & 0x80 == 0 {
        return Ok(first as usize);
    }

    let octets = (first & 0x7f) as usize;
    if octets == 0 || octets > 3 {
        return Err(KernelError::ParseError);
    }

    let mut length = 0usize;
    for _ in 0..octets {
        let byte = *input.get(*offset).ok_or(KernelError::ParseError)?;
        *offset += 1;
        length = (length << 8) | byte as usize;
    }
    if length > MAX_TLV_VALUE_LENGTH {
        return Err(KernelError::LengthOverflow);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_fci_template() {
        let bytes = [
            0x6f, 0x10, 0x84, 0x0e, b'1', b'P', b'A', b'Y', b'.', b'S', b'Y', b'S', b'.', b'D',
            b'D', b'F', b'0', b'1',
        ];

        let tlvs = parse_many(&bytes).expect("valid TLV");
        assert_eq!(find_first(&tlvs, &[0x84]), Some(&b"1PAY.SYS.DDF01"[..]));
        assert!(tlvs[0].constructed);
    }

    #[test]
    fn finds_unique_direct_values_without_descending() {
        let tlvs = parse_many(&[
            0x77, 0x0d, 0xa5, 0x06, 0x9f, 0x26, 0x03, 0xaa, 0xbb, 0xcc, 0x9f, 0x36, 0x02, 0x00,
            0x01,
        ])
        .unwrap();
        assert_eq!(
            find_unique_direct(&tlvs[0].children, &[0x9f, 0x36]).unwrap(),
            Some(&[0x00, 0x01][..])
        );
        assert_eq!(
            find_unique_direct(&tlvs[0].children, &[0x9f, 0x26]).unwrap(),
            None
        );

        let duplicates = parse_many(&[
            0x77, 0x0a, 0x9f, 0x36, 0x02, 0x00, 0x01, 0x9f, 0x36, 0x02, 0x00, 0x02,
        ])
        .unwrap();
        assert_eq!(
            find_unique_direct(&duplicates[0].children, &[0x9f, 0x36]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn tlv_debug_redacts_parsed_values() {
        let tlvs = parse_many(&[
            0x77, 0x11, 0x5a, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd, 0x9f, 0x26,
            0x04, 0x11, 0x22, 0x33, 0x44,
        ])
        .unwrap();
        let flat = flatten(&tlvs);

        for debug in [format!("{:?}", tlvs[0]), format!("{:?}", flat[1])] {
            assert!(debug.contains("redacted for crash safety"));
            assert!(debug.contains("value_len"));
            for raw_value_byte in ["222", "173", "190", "239", "170", "187", "204", "221"] {
                assert!(!debug.contains(raw_value_byte));
            }
        }
    }

    #[test]
    fn rejects_indefinite_lengths_for_fuzzability() {
        let err = parse_many(&[0x5a, 0x80, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, KernelError::ParseError);
    }

    #[test]
    fn rejects_zero_prefixed_high_tag_numbers() {
        let err = parse_many(&[0x9f, 0x80, 0x04, 0x01, 0x00]).unwrap_err();
        assert_eq!(err, KernelError::ParseError);
    }

    #[test]
    fn rejects_invalid_tag_field_bytes() {
        assert_eq!(
            parse_many(&[0x00, 0x00]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_many(&[0xff, 0x00]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_overlong_tags_and_configured_value_length_overflow() {
        let err = parse_many(&[0x9f, 0x81, 0x82, 0x83, 0x04, 0x00]).unwrap_err();
        assert_eq!(err, KernelError::ParseError);

        let mut value_overflow = vec![0x5a, 0x82, 0x10, 0x01];
        value_overflow.resize(MAX_TLV_VALUE_LENGTH + 5, 0x00);
        let err = parse_many(&value_overflow).unwrap_err();
        assert_eq!(err, KernelError::LengthOverflow);
    }

    #[test]
    fn rejects_truncated_values_without_panicking() {
        let err = parse_many(&[0x9f, 0x02, 0x06, 0x00]).unwrap_err();
        assert_eq!(err, KernelError::LengthOverflow);
    }
}
