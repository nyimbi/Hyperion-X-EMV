use core::fmt;

pub type KernelResult<T> = Result<T, KernelError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum KernelError {
    Ok = 0,
    InvalidArgument = 1,
    BufferTooSmall = 2,
    ParseError = 3,
    LengthOverflow = 4,
    UnsupportedCdaRequest = 5,
    InvalidProfile = 6,
    MissingMandatoryTag = 7,
    NoCommonAid = 8,
    CardRemoved = 9,
    HostTimeout = 10,
    ScriptFailed = 11,
    Busy = 12,
    RngFailure = 13,
    InternalError = 255,
}

pub const ERROR_TABLE: &[KernelError] = &[
    KernelError::Ok,
    KernelError::InvalidArgument,
    KernelError::BufferTooSmall,
    KernelError::ParseError,
    KernelError::LengthOverflow,
    KernelError::UnsupportedCdaRequest,
    KernelError::InvalidProfile,
    KernelError::MissingMandatoryTag,
    KernelError::NoCommonAid,
    KernelError::CardRemoved,
    KernelError::HostTimeout,
    KernelError::ScriptFailed,
    KernelError::Busy,
    KernelError::RngFailure,
    KernelError::InternalError,
];

impl KernelError {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i32) -> Option<Self> {
        ERROR_TABLE
            .iter()
            .copied()
            .find(|error| error.code() == code)
    }

    pub fn name(self) -> &'static str {
        match self {
            KernelError::Ok => "KRN_OK",
            KernelError::InvalidArgument => "KRN_ERR_INVALID_ARGUMENT",
            KernelError::BufferTooSmall => "KRN_ERR_BUFFER_TOO_SMALL",
            KernelError::ParseError => "KRN_ERR_PARSE_ERROR",
            KernelError::LengthOverflow => "KRN_ERR_LENGTH_OVERFLOW",
            KernelError::UnsupportedCdaRequest => "KRN_ERR_UNSUPPORTED_CDA_REQUEST",
            KernelError::InvalidProfile => "KRN_ERR_INVALID_PROFILE",
            KernelError::MissingMandatoryTag => "KRN_ERR_MISSING_MANDATORY_TAG",
            KernelError::NoCommonAid => "KRN_ERR_NO_COMMON_AID",
            KernelError::CardRemoved => "KRN_ERR_CARD_REMOVED",
            KernelError::HostTimeout => "KRN_ERR_HOST_TIMEOUT",
            KernelError::ScriptFailed => "KRN_ERR_SCRIPT_FAILED",
            KernelError::Busy => "KRN_ERR_BUSY",
            KernelError::RngFailure => "KRN_ERR_RNG_FAILURE",
            KernelError::InternalError => "KRN_ERR_INTERNAL",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            KernelError::Ok => "operation completed successfully",
            KernelError::InvalidArgument => "an ABI argument, state, or value is invalid",
            KernelError::BufferTooSmall => "caller output buffer is too small",
            KernelError::ParseError => "input data could not be parsed deterministically",
            KernelError::LengthOverflow => "input or output exceeds a bounded kernel limit",
            KernelError::UnsupportedCdaRequest => "requested CDA encoding is unsupported",
            KernelError::InvalidProfile => "signed profile data is missing, invalid, or rejected",
            KernelError::MissingMandatoryTag => "mandatory EMV data object is absent or malformed",
            KernelError::NoCommonAid => "no mutually supported application identifier was found",
            KernelError::CardRemoved => "card transport failed or the card became unavailable",
            KernelError::HostTimeout => "online host response timed out",
            KernelError::ScriptFailed => "critical issuer script processing failed",
            KernelError::Busy => "context is already processing another operation",
            KernelError::RngFailure => "platform RNG callback failed or returned weak output",
            KernelError::InternalError => "unexpected internal kernel error",
        }
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KernelError::Ok => "ok",
            KernelError::InvalidArgument => "invalid argument",
            KernelError::BufferTooSmall => "buffer too small",
            KernelError::ParseError => "parse error",
            KernelError::LengthOverflow => "length overflow",
            KernelError::UnsupportedCdaRequest => "unsupported CDA request",
            KernelError::InvalidProfile => "invalid profile",
            KernelError::MissingMandatoryTag => "missing mandatory tag",
            KernelError::NoCommonAid => "no common AID",
            KernelError::CardRemoved => "card removed",
            KernelError::HostTimeout => "host timeout",
            KernelError::ScriptFailed => "script failed",
            KernelError::Busy => "kernel busy",
            KernelError::RngFailure => "RNG failure",
            KernelError::InternalError => "internal error",
        })
    }
}

impl std::error::Error for KernelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_table_codes_names_descriptions_and_display_are_complete() {
        let expected = [
            (
                KernelError::Ok,
                0,
                "KRN_OK",
                "operation completed successfully",
                "ok",
            ),
            (
                KernelError::InvalidArgument,
                1,
                "KRN_ERR_INVALID_ARGUMENT",
                "an ABI argument, state, or value is invalid",
                "invalid argument",
            ),
            (
                KernelError::BufferTooSmall,
                2,
                "KRN_ERR_BUFFER_TOO_SMALL",
                "caller output buffer is too small",
                "buffer too small",
            ),
            (
                KernelError::ParseError,
                3,
                "KRN_ERR_PARSE_ERROR",
                "input data could not be parsed deterministically",
                "parse error",
            ),
            (
                KernelError::LengthOverflow,
                4,
                "KRN_ERR_LENGTH_OVERFLOW",
                "input or output exceeds a bounded kernel limit",
                "length overflow",
            ),
            (
                KernelError::UnsupportedCdaRequest,
                5,
                "KRN_ERR_UNSUPPORTED_CDA_REQUEST",
                "requested CDA encoding is unsupported",
                "unsupported CDA request",
            ),
            (
                KernelError::InvalidProfile,
                6,
                "KRN_ERR_INVALID_PROFILE",
                "signed profile data is missing, invalid, or rejected",
                "invalid profile",
            ),
            (
                KernelError::MissingMandatoryTag,
                7,
                "KRN_ERR_MISSING_MANDATORY_TAG",
                "mandatory EMV data object is absent or malformed",
                "missing mandatory tag",
            ),
            (
                KernelError::NoCommonAid,
                8,
                "KRN_ERR_NO_COMMON_AID",
                "no mutually supported application identifier was found",
                "no common AID",
            ),
            (
                KernelError::CardRemoved,
                9,
                "KRN_ERR_CARD_REMOVED",
                "card transport failed or the card became unavailable",
                "card removed",
            ),
            (
                KernelError::HostTimeout,
                10,
                "KRN_ERR_HOST_TIMEOUT",
                "online host response timed out",
                "host timeout",
            ),
            (
                KernelError::ScriptFailed,
                11,
                "KRN_ERR_SCRIPT_FAILED",
                "critical issuer script processing failed",
                "script failed",
            ),
            (
                KernelError::Busy,
                12,
                "KRN_ERR_BUSY",
                "context is already processing another operation",
                "kernel busy",
            ),
            (
                KernelError::RngFailure,
                13,
                "KRN_ERR_RNG_FAILURE",
                "platform RNG callback failed or returned weak output",
                "RNG failure",
            ),
            (
                KernelError::InternalError,
                255,
                "KRN_ERR_INTERNAL",
                "unexpected internal kernel error",
                "internal error",
            ),
        ];

        assert_eq!(ERROR_TABLE.len(), expected.len());
        for (error, code, name, description, display) in expected {
            assert!(ERROR_TABLE.contains(&error));
            assert_eq!(error.code(), code);
            assert_eq!(KernelError::from_code(code), Some(error));
            assert_eq!(error.name(), name);
            assert_eq!(error.description(), description);
            assert_eq!(error.to_string(), display);
        }
        assert_eq!(KernelError::from_code(-1), None);
        assert_eq!(KernelError::from_code(254), None);
    }
}
