use crate::dol::DataStore;
use crate::error::{KernelError, KernelResult};
use crate::tlv;

pub fn parse_read_record_body(body: &[u8], data: &mut DataStore) -> KernelResult<usize> {
    let parsed = tlv::parse_many(body)?;
    let mut stored = 0usize;
    for item in tlv::flatten(&parsed) {
        if item.constructed {
            continue;
        }
        data.put(item.tag, item.value)?;
        stored += 1;
    }
    if stored == 0 {
        return Err(KernelError::MissingMandatoryTag);
    }
    Ok(stored)
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
}
