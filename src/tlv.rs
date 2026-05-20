use crate::error::{KernelError, KernelResult};

pub const MAX_TLV_DEPTH: usize = 8;
pub const MAX_TLV_NODES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlv<'a> {
    pub tag: &'a [u8],
    pub value: &'a [u8],
    pub constructed: bool,
    pub children: Vec<Tlv<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlatTlv<'a> {
    pub tag: &'a [u8],
    pub value: &'a [u8],
    pub constructed: bool,
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
    *offset += 1;
    let constructed = first & 0x20 != 0;

    if first & 0x1f == 0x1f {
        let mut continuation_count = 0usize;
        loop {
            let byte = *input.get(*offset).ok_or(KernelError::ParseError)?;
            *offset += 1;
            continuation_count += 1;
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
    fn rejects_indefinite_lengths_for_fuzzability() {
        let err = parse_many(&[0x5a, 0x80, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, KernelError::ParseError);
    }

    #[test]
    fn rejects_truncated_values_without_panicking() {
        let err = parse_many(&[0x9f, 0x02, 0x06, 0x00]).unwrap_err();
        assert_eq!(err, KernelError::LengthOverflow);
    }
}
