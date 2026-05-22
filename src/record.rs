use crate::dol::DataStore;
use crate::error::{KernelError, KernelResult};
use crate::tlv;

const TERMINAL_OR_KERNEL_RECORD_TAGS: &[&[u8]] = &[
    &[0x5f, 0x2a], // Transaction Currency Code
    &[0x5f, 0x36], // Transaction Currency Exponent
    &[0x95],       // TVR
    &[0x9a],       // Transaction Date
    &[0x9b],       // TSI
    &[0x9c],       // Transaction Type
    &[0x9f, 0x02], // Amount Authorised
    &[0x9f, 0x03], // Amount Other
    &[0x9f, 0x15], // Merchant Category Code
    &[0x9f, 0x1a], // Terminal Country Code
    &[0x9f, 0x1e], // Interface Device Serial Number
    &[0x9f, 0x33], // Terminal Capabilities
    &[0x9f, 0x34], // CVM Results
    &[0x9f, 0x35], // Terminal Type
    &[0x9f, 0x37], // Unpredictable Number
    &[0x9f, 0x40], // Additional Terminal Capabilities
    &[0x9f, 0x4e], // Merchant Name and Location
    &[0x9f, 0x66], // TTQ
];

pub fn parse_read_record_body(body: &[u8], data: &mut DataStore) -> KernelResult<usize> {
    let parsed = tlv::parse_many(body)?;
    if parsed.len() != 1 || parsed[0].tag != [0x70] || !parsed[0].constructed {
        return Err(KernelError::MissingMandatoryTag);
    }

    let mut entries = Vec::new();
    for item in &parsed[0].children {
        if item.constructed {
            return Err(KernelError::ParseError);
        }
        if is_terminal_or_kernel_record_tag(item.tag) {
            return Err(KernelError::ParseError);
        }
        if entries
            .iter()
            .any(|(stored_tag, _): &(&[u8], &[u8])| *stored_tag == item.tag)
        {
            return Err(KernelError::ParseError);
        }
        entries.push((item.tag, item.value));
    }
    if entries.is_empty() {
        return Err(KernelError::MissingMandatoryTag);
    }
    for (tag, value) in &entries {
        data.put(tag, value)?;
    }
    Ok(entries.len())
}

fn is_terminal_or_kernel_record_tag(tag: &[u8]) -> bool {
    TERMINAL_OR_KERNEL_RECORD_TAGS.contains(&tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_record_template_into_card_data_store() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[0x70, 0x0a, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f],
                &mut data,
            )
            .unwrap(),
            1
        );
        assert_eq!(
            data.get(&[0x5a]),
            Some(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f][..])
        );
    }

    #[test]
    fn rejects_empty_or_malformed_record_templates() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(&[0x70, 0x00], &mut data).unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            parse_read_record_body(&[0x70, 0x03, 0x5a, 0x08, 0x12], &mut data).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn rejects_unwrapped_or_extra_record_data() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f],
                &mut data,
            )
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert!(data.get(&[0x5a]).is_none());

        assert_eq!(
            parse_read_record_body(
                &[0x70, 0x03, 0x5a, 0x01, 0x12, 0x5f, 0x24, 0x03, 0x26, 0x12, 0x31],
                &mut data
            )
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert!(data.get(&[0x5a]).is_none());
    }

    #[test]
    fn rejects_duplicate_record_data_without_partial_store() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x0e, 0x5a, 0x03, 0x12, 0x34, 0x5f, 0x5a, 0x03, 0xaa, 0xbb, 0xcc, 0x5f,
                    0x24, 0x01, 0x26,
                ],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x5a]).is_none());
        assert!(data.get(&[0x5f, 0x24]).is_none());

        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x10, 0x5a, 0x03, 0x12, 0x34, 0x5f, 0xa5, 0x09, 0x5a, 0x03, 0xaa, 0xbb,
                    0xcc, 0x5f, 0x24, 0x01, 0x26,
                ],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x5a]).is_none());
        assert!(data.get(&[0x5f, 0x24]).is_none());
    }

    #[test]
    fn rejects_terminal_owned_record_data_without_partial_store() {
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x02], &[0x00, 0x00, 0x00, 0x00, 0x20, 0x00])
            .unwrap();

        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x0c, 0x5a, 0x01, 0x12, 0x9f, 0x02, 0x06, 0x99, 0x99, 0x99, 0x99, 0x99,
                    0x99,
                ],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x5a]).is_none());
        assert_eq!(
            data.get(&[0x9f, 0x02]),
            Some(&[0x00, 0x00, 0x00, 0x00, 0x20, 0x00][..])
        );
    }

    #[test]
    fn rejects_nested_record_data_without_partial_store() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x0d, 0x5a, 0x03, 0x12, 0x34, 0x5f, 0xa5, 0x06, 0x5f, 0x24, 0x03, 0x26,
                    0x12, 0x31
                ],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x5a]).is_none());
        assert!(data.get(&[0x5f, 0x24]).is_none());
    }
}
