use crate::error::{KernelError, KernelResult};
use core::fmt;

pub const MAX_DOL_ENTRIES: usize = 128;
pub const MAX_DOL_OUTPUT: usize = 252;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DolEntry {
    pub tag: Vec<u8>,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DolPaddingPolicy {
    ZeroPadMissingAndShort,
    RequireExactValues,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct DataStore {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl fmt::Debug for DataStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataStore")
            .field("entry_count", &self.entries.len())
            .field("value_policy", &"values redacted for crash safety")
            .finish()
    }
}

impl DataStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn put(&mut self, tag: &[u8], value: &[u8]) -> KernelResult<()> {
        if tag.is_empty() || tag.len() > 4 {
            return Err(KernelError::InvalidArgument);
        }
        if let Some((_, existing)) = self.entries.iter_mut().find(|(stored, _)| stored == tag) {
            existing.clear();
            existing.extend_from_slice(value);
        } else {
            self.entries.push((tag.to_vec(), value.to_vec()));
        }
        Ok(())
    }

    pub fn get(&self, tag: &[u8]) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(stored, _)| stored == tag)
            .map(|(_, value)| value.as_slice())
    }
}

pub fn parse_dol(input: &[u8]) -> KernelResult<Vec<DolEntry>> {
    let mut offset = 0usize;
    let mut out = Vec::new();

    while offset < input.len() {
        if out.len() >= MAX_DOL_ENTRIES {
            return Err(KernelError::LengthOverflow);
        }
        let tag_start = offset;
        read_dol_tag(input, &mut offset)?;
        let tag = input[tag_start..offset].to_vec();
        let length = *input.get(offset).ok_or(KernelError::ParseError)? as usize;
        offset += 1;
        out.push(DolEntry { tag, length });
    }

    Ok(out)
}

pub fn build_dol(entries: &[DolEntry], data: &DataStore) -> KernelResult<Vec<u8>> {
    build_dol_with_policy(entries, data, DolPaddingPolicy::ZeroPadMissingAndShort)
}

pub fn build_dol_with_policy(
    entries: &[DolEntry],
    data: &DataStore,
    padding_policy: DolPaddingPolicy,
) -> KernelResult<Vec<u8>> {
    let total = entries.iter().try_fold(0usize, |acc, entry| {
        acc.checked_add(entry.length)
            .ok_or(KernelError::LengthOverflow)
    })?;
    if total > MAX_DOL_OUTPUT {
        return Err(KernelError::LengthOverflow);
    }

    let mut out = Vec::with_capacity(total);
    for entry in entries {
        match data.get(&entry.tag) {
            Some(value) if value.len() >= entry.length => {
                out.extend_from_slice(&value[..entry.length]);
            }
            Some(value) => {
                if padding_policy == DolPaddingPolicy::RequireExactValues {
                    return Err(KernelError::MissingMandatoryTag);
                }
                append_zero_padded(&mut out, value, entry.length);
            }
            None if entry.length == 0 => {}
            None if padding_policy == DolPaddingPolicy::RequireExactValues => {
                return Err(KernelError::MissingMandatoryTag);
            }
            None => out.resize(out.len() + entry.length, 0),
        }
    }
    Ok(out)
}

fn append_zero_padded(out: &mut Vec<u8>, value: &[u8], requested_len: usize) {
    out.extend_from_slice(value);
    out.resize(out.len() + requested_len - value.len(), 0);
}

fn read_dol_tag(input: &[u8], offset: &mut usize) -> KernelResult<()> {
    let first = *input.get(*offset).ok_or(KernelError::ParseError)?;
    *offset += 1;

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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_builds_pdol_deterministically() {
        let entries = parse_dol(&[0x9f, 0x66, 0x04, 0x9f, 0x02, 0x06, 0x9a, 0x03]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x66], &[0x36, 0x00, 0x40, 0x00]).unwrap();
        data.put(&[0x9f, 0x02], &[0x00, 0x00, 0x00, 0x00, 0x10, 0x00])
            .unwrap();

        let built = build_dol(&entries, &data).unwrap();
        assert_eq!(
            built,
            vec![0x36, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn rejects_zero_prefixed_high_tag_numbers() {
        assert_eq!(
            parse_dol(&[0x9f, 0x80, 0x04, 0x01]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn pads_short_or_missing_data_with_zeroes() {
        let entries = parse_dol(&[0x9f, 0x37, 0x04, 0x5f, 0x2a, 0x02]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x37], &[0xaa, 0xbb]).unwrap();

        assert_eq!(
            build_dol(&entries, &data).unwrap(),
            vec![0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn zero_padding_policy_is_explicit_and_deterministic() {
        let entries = parse_dol(&[0x9f, 0x37, 0x04, 0x5f, 0x2a, 0x02]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x37], &[0xaa, 0xbb]).unwrap();

        assert_eq!(
            build_dol_with_policy(&entries, &data, DolPaddingPolicy::ZeroPadMissingAndShort)
                .unwrap(),
            vec![0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn exact_value_policy_rejects_missing_or_short_dol_sources() {
        let entries = parse_dol(&[0x9f, 0x37, 0x04, 0x5f, 0x2a, 0x02]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x37], &[0xaa, 0xbb]).unwrap();

        assert_eq!(
            build_dol_with_policy(&entries, &data, DolPaddingPolicy::RequireExactValues)
                .unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        data.put(&[0x9f, 0x37], &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        assert_eq!(
            build_dol_with_policy(&entries, &data, DolPaddingPolicy::RequireExactValues)
                .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn exact_value_policy_truncates_long_values_to_requested_length() {
        let entries = parse_dol(&[0x9f, 0x37, 0x04]).unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x37], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee])
            .unwrap();

        assert_eq!(
            build_dol_with_policy(&entries, &data, DolPaddingPolicy::RequireExactValues).unwrap(),
            vec![0xaa, 0xbb, 0xcc, 0xdd]
        );
    }

    #[test]
    fn dol_output_cap_applies_before_padding_policy() {
        let entries = vec![DolEntry {
            tag: vec![0x9f, 0x37],
            length: MAX_DOL_OUTPUT + 1,
        }];
        let data = DataStore::new();

        assert_eq!(
            build_dol_with_policy(&entries, &data, DolPaddingPolicy::ZeroPadMissingAndShort)
                .unwrap_err(),
            KernelError::LengthOverflow
        );
        assert_eq!(
            build_dol_with_policy(&entries, &data, DolPaddingPolicy::RequireExactValues)
                .unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn datastore_debug_redacts_values_for_crash_safety() {
        let mut data = DataStore::new();
        data.put(&[0x5a], &[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f])
            .unwrap();
        data.put(&[0x9f, 0x37], &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();

        let debug = format!("{data:?}");
        assert!(debug.contains("DataStore"));
        assert!(debug.contains("entry_count"));
        assert!(!debug.contains("123456789012345"));
        assert!(!debug.contains("aa"));
        assert!(!debug.contains("bb"));
    }
}
