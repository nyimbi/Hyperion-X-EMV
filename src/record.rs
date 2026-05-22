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

const HOST_OR_ISSUER_RESPONSE_RECORD_TAGS: &[&[u8]] = &[
    &[0x89],       // Authorization Code
    &[0x8a],       // Authorization Response Code
    &[0x86],       // Issuer Script Command
    &[0x91],       // Issuer Authentication Data
    &[0x9f, 0x18], // Issuer Script Identifier
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
        if is_non_card_record_tag(item.tag) {
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
    reject_conflicting_record_values(&entries, data)?;
    validate_cardholder_data_consistency(&entries, data)?;
    for (tag, value) in &entries {
        data.put(tag, value)?;
    }
    Ok(entries.len())
}

fn is_non_card_record_tag(tag: &[u8]) -> bool {
    TERMINAL_OR_KERNEL_RECORD_TAGS.contains(&tag)
        || HOST_OR_ISSUER_RESPONSE_RECORD_TAGS.contains(&tag)
}

fn validate_cardholder_data_consistency(
    entries: &[(&[u8], &[u8])],
    data: &DataStore,
) -> KernelResult<()> {
    let pan = record_or_store_value(entries, data, &[0x5a]);
    let track2 = record_or_store_value(entries, data, &[0x57]);

    let pan_digits = pan.map(pan_digits_from_5a).transpose()?;
    let track2_pan_digits = track2.map(pan_digits_from_track2).transpose()?;
    if let (Some(pan_digits), Some(track2_pan_digits)) = (pan_digits, track2_pan_digits) {
        if pan_digits != track2_pan_digits {
            return Err(KernelError::ParseError);
        }
    }
    Ok(())
}

fn reject_conflicting_record_values(
    entries: &[(&[u8], &[u8])],
    data: &DataStore,
) -> KernelResult<()> {
    for (tag, record_value) in entries {
        if data
            .get(tag)
            .is_some_and(|stored_value| stored_value != *record_value)
        {
            return Err(KernelError::ParseError);
        }
    }
    Ok(())
}

fn record_or_store_value<'a>(
    entries: &'a [(&'a [u8], &'a [u8])],
    data: &'a DataStore,
    tag: &[u8],
) -> Option<&'a [u8]> {
    entries
        .iter()
        .find(|(entry_tag, _)| *entry_tag == tag)
        .map(|(_, value)| *value)
        .or_else(|| data.get(tag))
}

fn pan_digits_from_5a(value: &[u8]) -> KernelResult<Vec<u8>> {
    if value.is_empty() {
        return Err(KernelError::ParseError);
    }

    let mut digits = Vec::with_capacity(value.len() * 2);
    for (byte_idx, byte) in value.iter().copied().enumerate() {
        for (nibble_idx, nibble) in [byte >> 4, byte & 0x0f].into_iter().enumerate() {
            let is_final_nibble = byte_idx + 1 == value.len() && nibble_idx == 1;
            match nibble {
                0..=9 => digits.push(nibble),
                0x0f if is_final_nibble => {}
                _ => return Err(KernelError::ParseError),
            }
        }
    }
    validate_pan_length(&digits)?;
    Ok(digits)
}

fn pan_digits_from_track2(value: &[u8]) -> KernelResult<Vec<u8>> {
    if value.is_empty() {
        return Err(KernelError::ParseError);
    }

    let mut pan_digits = Vec::new();
    let mut saw_separator = false;
    let mut post_separator_digits = 0usize;
    let mut saw_padding = false;
    for byte in value.iter().copied() {
        for nibble in [byte >> 4, byte & 0x0f] {
            if saw_padding {
                if nibble != 0x0f {
                    return Err(KernelError::ParseError);
                }
                continue;
            }

            match nibble {
                0..=9 if saw_separator => post_separator_digits += 1,
                0..=9 => pan_digits.push(nibble),
                0x0d if !saw_separator && !pan_digits.is_empty() => saw_separator = true,
                0x0f if saw_separator => saw_padding = true,
                _ => return Err(KernelError::ParseError),
            }
        }
    }

    if !saw_separator || post_separator_digits < 7 {
        return Err(KernelError::ParseError);
    }
    validate_pan_length(&pan_digits)?;
    Ok(pan_digits)
}

fn validate_pan_length(digits: &[u8]) -> KernelResult<()> {
    if digits.is_empty() || digits.len() > 19 {
        return Err(KernelError::ParseError);
    }
    Ok(())
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
    fn rejects_all_terminal_or_kernel_record_tags_atomically() {
        for forbidden_tag in TERMINAL_OR_KERNEL_RECORD_TAGS {
            let mut data = DataStore::new();
            data.put(forbidden_tag, &[0xa5]).unwrap();

            let mut record = vec![0x70, (3 + forbidden_tag.len() + 2) as u8, 0x5a, 0x01, 0x12];
            record.extend_from_slice(forbidden_tag);
            record.extend_from_slice(&[0x01, 0x99]);

            assert_eq!(
                parse_read_record_body(&record, &mut data).unwrap_err(),
                KernelError::ParseError,
                "forbidden tag {forbidden_tag:02x?} should reject the record"
            );
            assert!(
                data.get(&[0x5a]).is_none(),
                "card data before forbidden tag must not be partially stored"
            );
            assert_eq!(
                data.get(forbidden_tag),
                Some(&[0xa5][..]),
                "forbidden tag {forbidden_tag:02x?} must not overwrite existing terminal data"
            );
        }
    }

    #[test]
    fn rejects_host_response_record_tags_atomically() {
        for forbidden_tag in HOST_OR_ISSUER_RESPONSE_RECORD_TAGS {
            let mut data = DataStore::new();
            data.put(forbidden_tag, &[0xa5]).unwrap();

            let mut record = vec![0x70, (3 + forbidden_tag.len() + 2) as u8, 0x5a, 0x01, 0x12];
            record.extend_from_slice(forbidden_tag);
            record.extend_from_slice(&[0x01, 0x99]);

            assert_eq!(
                parse_read_record_body(&record, &mut data).unwrap_err(),
                KernelError::ParseError,
                "host-response tag {forbidden_tag:02x?} should reject the record"
            );
            assert!(
                data.get(&[0x5a]).is_none(),
                "card data before host-response tag must not be partially stored"
            );
            assert_eq!(
                data.get(forbidden_tag),
                Some(&[0xa5][..]),
                "host-response tag {forbidden_tag:02x?} must not overwrite existing host data"
            );
        }
    }

    #[test]
    fn accepts_matching_pan_and_track2_without_unmasked_logging_dependency() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x18, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f, 0x57,
                    0x0c, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5d, 0x25, 0x12, 0x20, 0x1f,
                ],
                &mut data,
            )
            .unwrap(),
            2
        );
        assert_eq!(
            data.get(&[0x5a]),
            Some(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f][..])
        );
        assert!(data.get(&[0x57]).is_some());
    }

    #[test]
    fn rejects_mismatched_pan_and_track2_without_partial_store() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x18, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f, 0x57,
                    0x0c, 0x98, 0x76, 0x54, 0x32, 0x10, 0x98, 0x76, 0x5d, 0x25, 0x12, 0x20, 0x1f,
                ],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x5a]).is_none());
        assert!(data.get(&[0x57]).is_none());
    }

    #[test]
    fn rejects_conflicting_cardholder_data_rewrite_without_partial_store() {
        let mut data = DataStore::new();
        data.put(&[0x5a], &[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f])
            .unwrap();

        assert_eq!(
            parse_read_record_body(
                &[
                    0x70, 0x0e, 0x5a, 0x08, 0x98, 0x76, 0x54, 0x32, 0x10, 0x98, 0x76, 0x5f, 0x5f,
                    0x24, 0x01, 0x26,
                ],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            data.get(&[0x5a]),
            Some(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f][..])
        );
        assert!(data.get(&[0x5f, 0x24]).is_none());
    }

    #[test]
    fn rejects_conflicting_record_data_rewrite_without_partial_store() {
        let mut data = DataStore::new();
        data.put(&[0x5f, 0x24], &[0x26, 0x12, 0x31]).unwrap();

        assert_eq!(
            parse_read_record_body(
                &[0x70, 0x0b, 0x5f, 0x24, 0x03, 0x27, 0x01, 0x31, 0x5a, 0x03, 0x12, 0x34, 0x5f,],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(data.get(&[0x5f, 0x24]), Some(&[0x26, 0x12, 0x31][..]));
        assert!(data.get(&[0x5a]).is_none());
    }

    #[test]
    fn accepts_repeated_record_data_when_value_is_identical() {
        let mut data = DataStore::new();
        data.put(&[0x5f, 0x24], &[0x26, 0x12, 0x31]).unwrap();

        assert_eq!(
            parse_read_record_body(&[0x70, 0x06, 0x5f, 0x24, 0x03, 0x26, 0x12, 0x31], &mut data,)
                .unwrap(),
            1
        );
        assert_eq!(data.get(&[0x5f, 0x24]), Some(&[0x26, 0x12, 0x31][..]));
    }

    #[test]
    fn rejects_malformed_pan_or_track2_without_partial_store() {
        let mut data = DataStore::new();
        assert_eq!(
            parse_read_record_body(
                &[0x70, 0x0b, 0x5a, 0x03, 0x12, 0xf3, 0x45, 0x5f, 0x24, 0x03, 0x30, 0x12, 0x31,],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x5a]).is_none());
        assert!(data.get(&[0x5f, 0x24]).is_none());

        assert_eq!(
            parse_read_record_body(
                &[0x70, 0x08, 0x57, 0x06, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12],
                &mut data,
            )
            .unwrap_err(),
            KernelError::ParseError
        );
        assert!(data.get(&[0x57]).is_none());
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
