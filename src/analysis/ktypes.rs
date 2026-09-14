//! Windows-internals type layouts: field tables for the handful of kernel
//! structures a driver audit reads directly. The intent is IDA-style *names*
//! on raw offset accesses (*`DriverObject->MajorFunction[14]`* instead of
//! *`*(u64*)(rbx + 0xE0)`*), applied where the base type is known without
//! guessing: the device-control stack slot, the driver object's dispatch
//! table, a UNICODE_STRING, and an IOCTL parameter block.
//!
//! Offsets are the documented x64 layouts used by `x64dbg`/WinDbg symbol
//! viewers on modern kernels; 32-bit drivers are out of scope (the driver pass
//! is already 64-bit gated).

use serde::Serialize;

/// A field: byte offset, name, and a short type spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KField {
    pub offset: u64,
    pub width: u8,
    pub name: &'static str,
    pub ty: &'static str,
}

macro_rules! fields {
    ($($off:expr, $width:expr, $name:literal, $ty:literal);+ $(;)?) => {{
        &[ $( KField { offset: $off, width: $width, name: $name, ty: $ty }, )+ ]
    }};
}

/// x64 `_UNICODE_STRING`.
#[allow(dead_code)] // deferred IR type-renaming
pub static UNICODE_STRING: &[KField] = fields![
    0x00, 2, "Length", "u16";
    0x02, 2, "MaximumLength", "u16";
    0x08, 8, "Buffer", "PWSTR";
];

/// x64 `_LIST_ENTRY`, a public intrusive-list ABI primitive.
pub static LIST_ENTRY: &[KField] = fields![
    0x00, 8, "Flink", "PLIST_ENTRY";
    0x08, 8, "Blink", "PLIST_ENTRY";
];

/// Public x64 `_DRIVER_OBJECT`. `MajorFunction` is the dispatch table: slot
/// `n` at `0x70 + 8*n`; `0x50` is the distinct `FastIoDispatch` pointer.
#[allow(dead_code)] // deferred IR type-renaming
pub static DRIVER_OBJECT: &[KField] = fields![
    0x00, 2, "Type", "u16";
    0x02, 2, "Size", "u16";
    0x08, 8, "DeviceObject", "PDEVICE_OBJECT";
    0x10, 4, "Flags", "u32";
    0x18, 8, "DriverStart", "ptr";
    0x20, 4, "DriverSize", "u32";
    0x28, 8, "DriverSection", "ptr";
    0x30, 8, "DriverExtension", "PDRIVER_EXTENSION";
    0x38, 16, "DriverName", "UNICODE_STRING";
    0x48, 8, "HardwareDatabase", "PUNICODE_STRING";
    0x50, 8, "FastIoDispatch", "PFAST_IO_DISPATCH";
    0x58, 8, "DriverInit", "PDRIVER_INITIALIZE";
    0x60, 8, "DriverStartIo", "PDRIVER_STARTIO";
    0x68, 8, "DriverUnload", "PDRIVER_UNLOAD";
    0x70, 224, "MajorFunction", "PDRIVER_DISPATCH[28]";
];

/// x64 `_IO_STACK_LOCATION`, `Parameters` union at 0x08; the
/// `DeviceIoControl` member is what a dispatch handler reads.
pub static IO_STACK_LOCATION: &[KField] = fields![
    0x00, 1, "MajorFunction", "u8";
    0x01, 1, "MinorFunction", "u8";
    0x02, 1, "Flags", "u8";
    0x03, 1, "Control", "u8";
    0x08, 4, "Parameters.DeviceIoControl.OutputBufferLength", "u32";
    0x0c, 4, "Parameters.DeviceIoControl.InputBufferLength", "u32";
    0x10, 4, "Parameters.DeviceIoControl.IoControlCode", "u32";
    0x18, 8, "Parameters.DeviceIoControl.Type3InputBuffer", "ptr";
];

/// The public `MajorFunction` table base for x64.
pub const MAJOR_BASES: [u64; 1] = [0x70];
pub const FAST_IO_DISPATCH_OFFSET: u64 = 0x50;

/// Field lookup inside a known structure.
pub fn field(ty: &'static [KField], offset: u64) -> Option<&'static KField> {
    ty.iter().find(|f| f.offset == offset)
}

/// Render a dispatch-table slot access as `MajorFunction[IRP_MJ_*]`.
/// `offset` is interpreted against the public x64 base.
#[allow(dead_code)] // deferred IR type-renaming
pub fn dispatch_slot(offset: u64) -> Option<String> {
    for base in MAJOR_BASES {
        if offset >= base && (offset - base).is_multiple_of(8) {
            let idx = (offset - base) / 8;
            if idx < 28 {
                return Some(format!("MajorFunction[{idx}] /* {} */", irp(idx)));
            }
        }
    }
    None
}

/// IRP major function names, index = IRP_MJ_* value.
pub fn irp(index: u64) -> &'static str {
    const N: [&str; 28] = [
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP",
    ];
    N.get(index as usize).copied().unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_layouts_match_expected_offsets() {
        // UNICODE_STRING.Buffer is 8 bytes in (alignment skip after two u16).
        assert_eq!(field(UNICODE_STRING, 0x08).map(|f| f.name), Some("Buffer"));
        // Parameters.DeviceIoControl.IoControlCode is what a handler compares.
        assert_eq!(
            field(IO_STACK_LOCATION, 0x10).map(|f| f.name),
            Some("Parameters.DeviceIoControl.IoControlCode")
        );
        assert!(!MAJOR_BASES.is_empty());
    }

    #[test]
    fn dispatch_slots_render_by_major() {
        // IRP_MJ_DEVICE_CONTROL (14) at the public x64 base.
        assert_eq!(
            dispatch_slot(0x70 + 8 * 14),
            Some("MajorFunction[14] /* IRP_MJ_DEVICE_CONTROL */".into())
        );
        // 0x50 is FastIoDispatch, never MajorFunction[0].
        assert_eq!(dispatch_slot(FAST_IO_DISPATCH_OFFSET), None);
        // A non-slot offset is None, never a name.
        assert_eq!(dispatch_slot(0x20), None);
    }
}
