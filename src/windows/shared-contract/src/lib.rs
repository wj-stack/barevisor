//! Shared IOCTL codes and buffer layouts for `win_hv` and its user-mode client.
//! Must stay `no_std` so the kernel driver can depend on this crate.

#![no_std]

/// Logical contract version (bump when IOCTL shapes change).
pub const CONTRACT_VERSION: &str = "0.6.1";

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

/// Writes bytes to a host physical address (`PhysMemIoRequest::address`).
pub const IOCTL_WRITE_PHYSICAL: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x908,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Installs an EPT Hook2 inline detour at `EptHook2Request::target_gva`.
pub const IOCTL_EPT_HOOK2: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x909,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Removes an EPT Hook2 installed at `EptUnhookRequest::target_gva`.
pub const IOCTL_EPT_UNHOOK: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x90A,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Returns `KeServiceDescriptorTable` / shadow table addresses (HyperDbg-style scan).
pub const IOCTL_GET_SSDT: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x90B,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Resolves an ntoskrnl SSDT handler by export name (`GetSsdtFunctionRequest::name`).
pub const IOCTL_GET_SSDT_FUNCTION: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x90C,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Returns `SsdtHookInfoResponse` for the `ssdt_hook` example driver.
pub const IOCTL_SSDT_HOOK_GET_INFO: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x910,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Installs the `ssdt_hook` example EPT detour (calls `IOCTL_EPT_HOOK2` under the hood).
pub const IOCTL_SSDT_HOOK_INSTALL: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x911,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// Removes the `ssdt_hook` example EPT detour.
pub const IOCTL_SSDT_HOOK_UNINSTALL: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x912,
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

/// Basename for the `ssdt_hook` example device (`\\.\SsdtHook`).
pub const SSDT_HOOK_DEVICE_BASENAME: &str = "SsdtHook";

/// User-mode path for [`SSDT_HOOK_DEVICE_BASENAME`].
pub const SSDT_HOOK_USER_DEVICE_PATH: &str = r"\\.\SsdtHook";

/// Input header for [`IOCTL_READ_MEMORY`] and [`IOCTL_WRITE_MEMORY`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemIoRequest {
    /// Guest virtual address to read from or write to.
    pub address: u64,
    /// Number of bytes to transfer (must be `<=` [`MEM_IO_MAX_LEN`]).
    pub size: u32,
}

/// Input header for [`IOCTL_WRITE_PHYSICAL`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhysMemIoRequest {
    /// Host physical address to write.
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
    /// Kernel `DirectoryTableBase` from `KPROCESS`.
    pub cr3: u64,
}

/// Manual four-level page table walk via physical memory (`MmCopyMemory`).
/// HyperDbg path 2.
pub const TRANSLATE_METHOD_PAGE_WALK: u32 = 0;
/// Switch to target kernel CR3 then `MmGetPhysicalAddress`. HyperDbg path 1.
pub const TRANSLATE_METHOD_CR3_SWITCH: u32 = 1;

/// Input for [`IOCTL_TRANSLATE_GVA`] and [`IOCTL_READ_GVA`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslateGvaRequest {
    /// When non-zero, `cr3` is ignored and kernel CR3 is resolved from this PID.
    pub process_id: u32,
    /// Translation method ([`TRANSLATE_METHOD_PAGE_WALK`] or [`TRANSLATE_METHOD_CR3_SWITCH`]).
    pub method: u32,
    /// Kernel page table root when `process_id` is zero.
    pub cr3: u64,
    /// Guest virtual address to translate.
    pub gva: u64,
}

/// CR3 resolution failed (process lookup, attach, etc.).
pub const TRANSLATE_FAIL_CR3: u8 = 1;
/// Invalid GVA or page table root.
pub const TRANSLATE_FAIL_INVALID: u8 = 2;
/// PML4 entry missing or physical mapping failed.
pub const TRANSLATE_FAIL_PML4: u8 = 3;
/// PDPT entry missing or physical mapping failed.
pub const TRANSLATE_FAIL_PDPT: u8 = 4;
/// PD entry missing or physical mapping failed.
pub const TRANSLATE_FAIL_PD: u8 = 5;
/// PTE entry missing or physical mapping failed.
pub const TRANSLATE_FAIL_PTE: u8 = 6;
/// `MmGetPhysicalAddress` returned zero after CR3 switch.
pub const TRANSLATE_FAIL_MMGPA: u8 = 7;

/// Output for [`IOCTL_TRANSLATE_GVA`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslateGvaResponse {
    /// `1` when translation succeeded, otherwise `0`.
    pub success: u8,
    /// Final page size on success: `4` = 4KB, `3` = 2MB, `2` = 1GB; `0` for CR3-switch path.
    pub walk_level: u8,
    /// Failure stage when `success == 0` (see `TRANSLATE_FAIL_*`).
    pub fail_stage: u8,
    /// Method used ([`TRANSLATE_METHOD_PAGE_WALK`] or [`TRANSLATE_METHOD_CR3_SWITCH`]).
    pub method: u8,
    /// `NTSTATUS` on failure; `0` on success.
    pub status: i32,
    /// CR3 value actually used for the walk.
    pub used_cr3: u64,
    /// Physical address of the selected PML4 entry.
    pub pml4e_pa: u64,
    /// Physical address of the selected PDPT entry.
    pub pdpe_pa: u64,
    /// Physical address of the selected PD entry (`0` for 1GB pages).
    pub pde_pa: u64,
    /// Physical address of the selected PT entry (`0` for 1GB/2MB pages).
    pub pte_pa: u64,
    /// Guest physical address.
    pub gpa: u64,
    /// Host physical address.
    pub hpa: u64,
}

/// Invalid parameter for [`IOCTL_EPT_HOOK2`] / [`IOCTL_EPT_UNHOOK`].
pub const EPT_HOOK2_ERR_INVALID: u8 = 1;
/// CR3 / process lookup failed.
pub const EPT_HOOK2_ERR_CR3: u8 = 2;
/// GVA→GPA translation failed.
pub const EPT_HOOK2_ERR_TRANSLATE: u8 = 3;
/// GPA is outside the supported identity EPT range (< 512 GB).
pub const EPT_HOOK2_ERR_GPA_RANGE: u8 = 4;
/// The target page is already hooked.
pub const EPT_HOOK2_ERR_ALREADY_HOOKED: u8 = 5;
/// Instruction length / disassembly failed.
pub const EPT_HOOK2_ERR_DISASM: u8 = 6;
/// Hook patch would cross a page boundary.
pub const EPT_HOOK2_ERR_PAGE_BOUNDARY: u8 = 7;
/// Pool allocation failed.
pub const EPT_HOOK2_ERR_ALLOC: u8 = 8;
/// Hypervisor rejected the install/uninstall request.
pub const EPT_HOOK2_ERR_HYPERVISOR: u8 = 9;
/// CPU lacks EPT execute-only support.
pub const EPT_HOOK2_ERR_NO_EXEC_ONLY: u8 = 10;
/// No hook registered for the given address.
pub const EPT_HOOK2_ERR_NOT_FOUND: u8 = 11;

/// Input for [`IOCTL_EPT_HOOK2`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EptHook2Request {
    /// Target process ID (`0` = use the current CR3).
    pub process_id: u32,
    /// SSDT syscall index for synthesized trampoline (`0` = auto-detect stub at target).
    pub syscall_number: u32,
    /// Guest virtual address of the function to hook.
    pub target_gva: u64,
    /// Guest virtual address of the detour handler.
    pub hook_gva: u64,
}

/// Output for [`IOCTL_EPT_HOOK2`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EptHook2Response {
    /// `1` on success, otherwise `0`.
    pub success: u8,
    /// [`EPT_HOOK2_ERR_*`] on failure.
    pub error_code: u8,
    /// Bytes overwritten in the fake executable page.
    pub patched_len: u8,
    /// Reserved; must be zero.
    pub _padding: u8,
    /// Kernel VA of the trampoline (original-call gateway).
    pub trampoline_gva: u64,
    /// Page-aligned guest physical address of the hooked page.
    pub target_gpa: u64,
}

/// Input for [`IOCTL_EPT_UNHOOK`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EptUnhookRequest {
    /// Guest virtual address used when the hook was installed.
    pub target_gva: u64,
    /// Target process ID (`0` = use the current CR3).
    pub process_id: u32,
    /// Reserved; must be zero.
    pub _padding: u32,
}

/// SSDT scan failed (ntoskrnl not found or pattern missing).
pub const SSDT_ERR_NOT_FOUND: u8 = 1;
/// Export name not found via `MmGetSystemRoutineAddress`.
pub const SSDT_ERR_EXPORT: u8 = 2;
/// No SSDT entry matched the export address.
pub const SSDT_ERR_NO_MATCH: u8 = 3;
/// Request export name is empty or too long.
pub const SSDT_ERR_NAME: u8 = 4;

/// Output for [`IOCTL_GET_SSDT`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetSsdtResponse {
    /// `1` on success, otherwise `0`.
    pub success: u8,
    /// [`SSDT_ERR_*`] on failure.
    pub error_code: u8,
    /// Reserved; must be zero.
    pub _padding: [u8; 6],
    /// `ntoskrnl.exe` image base.
    pub ntoskrnl_base: u64,
    /// `ntoskrnl.exe` image size.
    pub ntoskrnl_size: u32,
    /// Reserved; must be zero.
    pub _padding2: u32,
    /// Kernel VA of `KeServiceDescriptorTable`.
    pub ke_service_descriptor_table: u64,
    /// `KiServiceTable` (native SSDT) from entry `[0]`.
    pub service_table_base: u64,
    /// Number of native system services.
    pub number_of_services: u32,
    /// Reserved; must be zero.
    pub _padding3: u32,
    /// Kernel VA of `KeServiceDescriptorTableShadow`.
    pub ke_service_descriptor_table_shadow: u64,
    /// Shadow entry `[0]` service table (copy of native SSDT).
    pub shadow_service_table_base: u64,
    /// Shadow entry `[0]` service count.
    pub shadow_number_of_services: u32,
    /// Shadow entry `[1]` service count (win32k), `0` when absent.
    pub win32k_number_of_services: u32,
    /// Shadow entry `[1]` service table (`win32k!W32pServiceTable`), `0` when absent.
    pub win32k_service_table_base: u64,
}

/// Maximum export name length for [`IOCTL_GET_SSDT_FUNCTION`] (UTF-8 bytes, NUL excluded).
pub const SSDT_FUNCTION_NAME_MAX: usize = 64;

/// Input for [`IOCTL_GET_SSDT_FUNCTION`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GetSsdtFunctionRequest {
    /// NUL-terminated ASCII export name (e.g. `NtOpenProcess`).
    pub name: [u8; SSDT_FUNCTION_NAME_MAX],
}

impl Default for GetSsdtFunctionRequest {
    fn default() -> Self {
        Self {
            name: [0; SSDT_FUNCTION_NAME_MAX],
        }
    }
}

/// Output for [`IOCTL_GET_SSDT_FUNCTION`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetSsdtFunctionResponse {
    /// `1` on success, otherwise `0`.
    pub success: u8,
    /// [`SSDT_ERR_*`] on failure.
    pub error_code: u8,
    /// Reserved; must be zero.
    pub _padding: [u8; 6],
    /// SSDT syscall index for the matched handler.
    pub syscall_number: u32,
    /// Kernel VA of the handler (from SSDT decode).
    pub function_address: u64,
    /// Ground-truth address from `MmGetSystemRoutineAddress`.
    pub export_address: u64,
}

/// Fixed export name length in [`SsdtHookInfoResponse::export_name`].
pub const SSDT_HOOK_EXPORT_NAME_LEN: usize = 16;

/// Output for [`IOCTL_SSDT_HOOK_GET_INFO`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SsdtHookInfoResponse {
    /// `1` when `target_gva` / `hook_gva` are valid.
    pub ready: u8,
    /// `1` when an EPT hook is currently installed.
    pub installed: u8,
    /// Reserved; must be zero.
    pub _padding: [u8; 6],
    /// Kernel VA of the SSDT target (e.g. `NtOpenProcess`).
    pub target_gva: u64,
    /// Kernel VA of the detour handler in `ssdt_hook.sys`.
    pub hook_gva: u64,
    /// NUL-terminated ASCII export name (e.g. `NtOpenProcess`).
    pub export_name: [u8; SSDT_HOOK_EXPORT_NAME_LEN],
    /// Trampoline VA after install (`0` before install).
    pub trampoline_gva: u64,
}

/// Input for [`IOCTL_READ_GVA`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadGvaRequest {
    /// When non-zero, `cr3` is ignored and CR3 is resolved from this PID.
    pub process_id: u32,
    /// Number of bytes to read (must be `<=` [`MEM_IO_MAX_LEN`]).
    pub size: u32,
    /// Manual page table root when `process_id` is zero.
    pub cr3: u64,
    /// Guest virtual address to read.
    pub gva: u64,
}
