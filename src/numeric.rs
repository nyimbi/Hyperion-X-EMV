use crate::error::{KernelError, KernelResult};

pub fn encode_numeric_bcd_fixed(value: u64, bytes: usize) -> KernelResult<Vec<u8>> {
    let digits = bytes.checked_mul(2).ok_or(KernelError::LengthOverflow)?;
    let max = 10u64
        .checked_pow(digits as u32)
        .ok_or(KernelError::LengthOverflow)?;
    if value >= max {
        return Err(KernelError::InvalidArgument);
    }

    let mut out = vec![0u8; bytes];
    let mut remaining = value;
    for index in (0..digits).rev() {
        let digit = (remaining % 10) as u8;
        remaining /= 10;
        let byte = index / 2;
        if index % 2 == 0 {
            out[byte] |= digit << 4;
        } else {
            out[byte] |= digit;
        }
    }
    Ok(out)
}

pub fn decode_numeric_bcd_fixed(bytes: &[u8]) -> KernelResult<u64> {
    let digits = bcd_digits(bytes)?;
    digits.into_iter().try_fold(0u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit)))
            .ok_or(KernelError::LengthOverflow)
    })
}

pub fn bcd_digits(bytes: &[u8]) -> KernelResult<Vec<u8>> {
    let digits = bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    if digits.iter().all(|digit| *digit <= 9) {
        Ok(digits)
    } else {
        Err(KernelError::ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_fixed_numeric_bcd_amounts() {
        let encoded = encode_numeric_bcd_fixed(1_234_567_890, 6).unwrap();

        assert_eq!(encoded, [0x00, 0x12, 0x34, 0x56, 0x78, 0x90]);
        assert_eq!(decode_numeric_bcd_fixed(&encoded).unwrap(), 1_234_567_890);
        assert_eq!(
            bcd_digits(&encoded).unwrap(),
            vec![0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        );
    }

    #[test]
    fn rejects_fixed_numeric_bcd_overflow_and_non_bcd_nibbles() {
        assert_eq!(
            encode_numeric_bcd_fixed(1_000_000_000_000, 6),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(
            decode_numeric_bcd_fixed(&[0x00, 0x00, 0x00, 0x0A, 0x00, 0x00]),
            Err(KernelError::ParseError)
        );
    }
}
