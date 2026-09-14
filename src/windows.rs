//! Deterministic Windows constants shared by analysis front ends.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IoctlMethod {
    Buffered = 0,
    InDirect = 1,
    OutDirect = 2,
    Neither = 3,
}

impl IoctlMethod {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Buffered => "METHOD_BUFFERED",
            Self::InDirect => "METHOD_IN_DIRECT",
            Self::OutDirect => "METHOD_OUT_DIRECT",
            Self::Neither => "METHOD_NEITHER",
        }
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedCtlCode {
    pub code: u32,
    pub device_type: u32,
    pub function: u32,
    pub method: IoctlMethod,
    pub access: u32,
}

/// Decode the Windows `CTL_CODE` bit layout without model interpretation.
pub const fn decode_ctl_code(code: u32) -> DecodedCtlCode {
    let method = match code & 0x3 {
        0 => IoctlMethod::Buffered,
        1 => IoctlMethod::InDirect,
        2 => IoctlMethod::OutDirect,
        _ => IoctlMethod::Neither,
    };
    DecodedCtlCode {
        code,
        device_type: (code >> 16) & 0xffff,
        access: (code >> 14) & 0x3,
        function: (code >> 2) & 0xfff,
        method,
    }
}

/// Canonical names for statuses currently protected by regression tests.
/// Unknown values remain unknown rather than being guessed.
pub const fn ntstatus_name(status: u32) -> Option<&'static str> {
    match status {
        0xC000000D => Some("STATUS_INVALID_PARAMETER"),
        0xC0000010 => Some("STATUS_INVALID_DEVICE_REQUEST"),
        0xC00000BB => Some("STATUS_NOT_SUPPORTED"),
        0xC0000225 => Some("STATUS_NOT_FOUND"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctl_code_500016_is_method_out_direct() {
        let decoded = decode_ctl_code(0x500016);
        assert_eq!(decoded.device_type, 0x50);
        assert_eq!(decoded.function, 5);
        assert_eq!(decoded.method, IoctlMethod::OutDirect);
        assert_eq!(decoded.method.name(), "METHOD_OUT_DIRECT");
        assert_eq!(decoded.access, 0);
    }

    #[test]
    fn canonical_ntstatus_regressions() {
        assert_eq!(ntstatus_name(0xC000000D), Some("STATUS_INVALID_PARAMETER"));
        assert_eq!(
            ntstatus_name(0xC0000010),
            Some("STATUS_INVALID_DEVICE_REQUEST")
        );
        assert_eq!(ntstatus_name(0xC00000BB), Some("STATUS_NOT_SUPPORTED"));
        assert_eq!(ntstatus_name(0xC0000225), Some("STATUS_NOT_FOUND"));
        assert_eq!(ntstatus_name(0xDEADBEEF), None);
    }
}
