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
    InternalError = 255,
}

impl KernelError {
    pub fn code(self) -> i32 {
        self as i32
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
            KernelError::InternalError => "internal error",
        })
    }
}

impl std::error::Error for KernelError {}
