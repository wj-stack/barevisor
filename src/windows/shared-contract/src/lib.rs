//! Shared IOCTL codes and buffer layouts for `win_hv` and its user-mode client.
//! Must stay `no_std` so the kernel driver can depend on this crate.

#![no_std]

/// Logical contract version (bump when IOCTL shapes change).
pub const CONTRACT_VERSION: &str = "0.2.0";

/// `FILE_DEVICE_UNKNOWN` for `CTL_CODE`.
pub const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
/// `FILE_ANY_ACCESS` for `CTL_CODE`.
pub const FILE_ANY_ACCESS: u32 = 0;
/// `METHOD_BUFFERED` for `CTL_CODE`.
pub const METHOD_BUFFERED: u32 = 0;

/// `CTL_CODE` equivalent (matches Windows `CTL_CODE` macro layout).
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Verifies hypervisor reachability via `HV_HYPERCALL_PING`.
pub const IOCTL_PING: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x900,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Reads guest memory at `MemIoRequest::address` through a hypercall.
pub const IOCTL_READ_MEMORY: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x902,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Writes guest memory at `MemIoRequest::address` through a hypercall.
pub const IOCTL_WRITE_MEMORY: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x903,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Returns the directory table base (CR3) for `GetCr3ByPidRequest::process_id`.
pub const IOCTL_GET_CR3_BY_PID: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x904,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Translates `TranslateGvaRequest::{cr3,gva}` to GPA/HPA.
pub const IOCTL_TRANSLATE_GVA: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x906,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Reads guest memory at `ReadGvaRequest::{cr3,gva}` after GVA->GPA->HPA translation.
pub const IOCTL_READ_GVA: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x907,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Maximum bytes per read/write IOCTL (must match `hv::hypercall::HV_MEM_IO_MAX_LEN`).
pub const MEM_IO_MAX_LEN: usize = 4096;

/// Fixed response for [`IOCTL_PING`] (ASCII `BVRH` as LE `u32`).
pub const PING_RESPONSE_U32: u32 = 0x4852_5642;

/// Default basename for `\\Device\\{basename}` / `\\DosDevices\\{basename}` / `\\.\{basename}`.
pub const DEVICE_BASENAME: &str = "BarevisorHv";

/// User-mode path (UTF-8) — pass to `CreateFileW` after UTF-16 conversion.
pub const USER_DEVICE_PATH: &str = r"\\.\BarevisorHv";

/// Input header for [`IOCTL_READ_MEMORY`] and [`IOCTL_WRITE_MEMORY`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemIoRequest {
    /// Guest virtual address to read from or write to.
    pub address: u64,
    /// Number of bytes to transfer (must be `<=` [`MEM_IO_MAX_LEN`]).
    pub size: u32,
}

/// Input for [`IOCTL_GET_CR3_BY_PID`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetCr3ByPidRequest {
    /// Target process ID.
    pub process_id: u32,
}

/// Output for [`IOCTL_GET_CR3_BY_PID`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetCr3ByPidResponse {
    /// `1` when the process was found, otherwise `0`.
    pub found: u8,
    /// Reserved; must be zero.
    pub _padding: [u8; 7],
    /// `DirectoryTableBase` from the target `EPROCESS` (`KPROCESS`).
    pub cr3: u64,
}

/// Input for [`IOCTL_TRANSLATE_GVA`] and [`IOCTL_READ_GVA`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslateGvaRequest {
    /// Guest page table root (`CR3` / `DirectoryTableBase`).
    pub cr3: u64,
    /// Guest virtual address to translate.
    pub gva: u64,
}

/// Output for [`IOCTL_TRANSLATE_GVA`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslateGvaResponse {
    /// `1` when translation succeeded, otherwise `0`.
    pub success: u8,
    /// Reserved; must be zero.
    pub _padding: [u8; 7],
    /// Guest physical address.
    pub gpa: u64,
    /// Host physical address.
    pub hpa: u64,
}

/// Input for [`IOCTL_READ_GVA`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadGvaRequest {
    /// Guest page table root (`CR3` / `DirectoryTableBase`).
    pub cr3: u64,
    /// Guest virtual address to read.
    pub gva: u64,
    /// Number of bytes to read (must be `<=` [`MEM_IO_MAX_LEN`]).
    pub size: u32,
    /// Reserved; must be zero.
    pub _padding: u32,
}
