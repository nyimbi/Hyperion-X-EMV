use crate::apdu::{read_record, CommandApdu};
use crate::error::{KernelError, KernelResult};

const MAX_AFL_BYTES: usize = 252;
pub const MAX_AFL_ENTRIES: usize = MAX_AFL_BYTES / 4;
pub const MAX_RECORD_LOCATORS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AflEntry {
    pub sfi: u8,
    pub first_record: u8,
    pub last_record: u8,
    pub offline_auth_record_count: u8,
}

impl AflEntry {
    pub fn record_count(self) -> u8 {
        self.last_record - self.first_record + 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLocator {
    pub sfi: u8,
    pub record: u8,
    pub contributes_to_offline_auth: bool,
}

pub fn parse_afl(input: &[u8]) -> KernelResult<Vec<AflEntry>> {
    if input.is_empty() || input.len() % 4 != 0 {
        return Err(KernelError::ParseError);
    }
    let entry_count = input.len() / 4;
    if entry_count > MAX_AFL_ENTRIES {
        return Err(KernelError::LengthOverflow);
    }

    let mut entries = Vec::with_capacity(entry_count);
    for chunk in input.chunks_exact(4) {
        let sfi = chunk[0] >> 3;
        let first_record = chunk[1];
        let last_record = chunk[2];
        let offline_auth_record_count = chunk[3];

        if chunk[0] & 0x07 != 0
            || sfi == 0
            || sfi > 30
            || first_record == 0
            || last_record < first_record
        {
            return Err(KernelError::ParseError);
        }
        let record_count = last_record - first_record + 1;
        if offline_auth_record_count > record_count {
            return Err(KernelError::ParseError);
        }

        entries.push(AflEntry {
            sfi,
            first_record,
            last_record,
            offline_auth_record_count,
        });
    }

    Ok(entries)
}

pub fn record_plan(entries: &[AflEntry]) -> KernelResult<Vec<RecordLocator>> {
    let mut out = Vec::new();
    for entry in entries {
        for index in 0..entry.record_count() {
            if out.len() >= MAX_RECORD_LOCATORS {
                return Err(KernelError::LengthOverflow);
            }
            let record = entry.first_record + index;
            if out
                .iter()
                .any(|locator: &RecordLocator| locator.sfi == entry.sfi && locator.record == record)
            {
                return Err(KernelError::ParseError);
            }
            out.push(RecordLocator {
                sfi: entry.sfi,
                record,
                contributes_to_offline_auth: index < entry.offline_auth_record_count,
            });
        }
    }
    Ok(out)
}

pub fn read_record_commands(entries: &[AflEntry]) -> KernelResult<Vec<CommandApdu>> {
    record_plan(entries)?
        .iter()
        .map(|locator| read_record(locator.record, locator.sfi))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_afl_and_marks_offline_auth_records() {
        let entries = parse_afl(&[0x10, 0x01, 0x03, 0x02]).unwrap();
        assert_eq!(
            entries,
            vec![AflEntry {
                sfi: 2,
                first_record: 1,
                last_record: 3,
                offline_auth_record_count: 2
            }]
        );

        let plan = record_plan(&entries).unwrap();
        assert_eq!(
            plan,
            vec![
                RecordLocator {
                    sfi: 2,
                    record: 1,
                    contributes_to_offline_auth: true
                },
                RecordLocator {
                    sfi: 2,
                    record: 2,
                    contributes_to_offline_auth: true
                },
                RecordLocator {
                    sfi: 2,
                    record: 3,
                    contributes_to_offline_auth: false
                }
            ]
        );
    }

    #[test]
    fn builds_read_record_commands_from_afl_order() {
        let entries = parse_afl(&[0x18, 0x02, 0x03, 0x00]).unwrap();
        let encoded: Vec<Vec<u8>> = read_record_commands(&entries)
            .unwrap()
            .iter()
            .map(|cmd| cmd.encode().unwrap())
            .collect();
        assert_eq!(
            encoded,
            vec![
                vec![0x00, 0xb2, 0x02, 0x1c, 0x00],
                vec![0x00, 0xb2, 0x03, 0x1c, 0x00]
            ]
        );
    }

    #[test]
    fn rejects_malformed_afl_entries() {
        assert_eq!(
            parse_afl(&[0x00, 0x01, 0x01, 0x00]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_afl(&[0x10, 0x03, 0x02, 0x00]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_afl(&[0x10, 0x01, 0x02, 0x03]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_afl(&[0x10, 0x01, 0x02]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_afl_sfi_bytes_with_nonzero_low_bits() {
        assert_eq!(
            parse_afl(&[0x13, 0x01, 0x01, 0x00]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn accepts_maximum_afl_entry_count_without_overflow() {
        assert_eq!(MAX_AFL_ENTRIES, 63);
        assert_eq!(MAX_AFL_ENTRIES * 4, MAX_AFL_BYTES);

        let mut afl = Vec::new();
        for index in 0..MAX_AFL_ENTRIES {
            let sfi = (index % 30 + 1) as u8;
            let record = (index / 30 + 1) as u8;
            afl.extend_from_slice(&[sfi << 3, record, record, 0x00]);
        }

        let entries = parse_afl(&afl).unwrap();
        assert_eq!(entries.len(), MAX_AFL_ENTRIES);
        let plan = record_plan(&entries).unwrap();
        assert_eq!(plan.len(), MAX_AFL_ENTRIES);
    }

    #[test]
    fn rejects_afl_lists_above_entry_limit() {
        let mut afl = Vec::new();
        for _ in 0..=MAX_AFL_ENTRIES {
            afl.extend_from_slice(&[0x10, 0x01, 0x01, 0x00]);
        }

        assert_eq!(parse_afl(&afl).unwrap_err(), KernelError::LengthOverflow);
    }

    #[test]
    fn rejects_record_plans_above_locator_limit() {
        let entries = [
            AflEntry {
                sfi: 1,
                first_record: 1,
                last_record: 255,
                offline_auth_record_count: 0,
            },
            AflEntry {
                sfi: 2,
                first_record: 1,
                last_record: 255,
                offline_auth_record_count: 0,
            },
        ];

        assert_eq!(
            record_plan(&entries).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn rejects_duplicate_afl_record_locators() {
        let entries = parse_afl(&[0x10, 0x01, 0x02, 0x00, 0x10, 0x02, 0x03, 0x00]).unwrap();
        assert_eq!(record_plan(&entries).unwrap_err(), KernelError::ParseError);
        assert_eq!(
            read_record_commands(&entries).unwrap_err(),
            KernelError::ParseError
        );
    }
}
