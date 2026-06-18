//! Hypercall interface between the guest and the host hypervisor.
//!
//! Guest code issues `VMCALL` (Intel) or `VMMCALL` (AMD). The host handles the
//! request in `host::handle_vmcall` and resumes the guest with results in
//! registers.

/// Verifies that Barevisor is handling hypercalls.
pub const HV_HYPERCALL_PING: u64 = 0;

/// Reads `size` bytes from guest virtual address `address` into guest buffer `buffer_va`.
pub const HV_HYPERCALL_READ_MEMORY: u64 = 1;

/// Writes `size` bytes from guest buffer `buffer_va` to guest virtual address `address`.
pub const HV_HYPERCALL_WRITE_MEMORY: u64 = 2;

/// Installs an EPT Hook2 mapping (RCX=GPA page base, RDX=fake page HPA).
pub const HV_HYPERCALL_INSTALL_EPT_HOOK2: u64 = 3;

/// Removes an EPT Hook2 mapping (RCX=GPA page base).
pub const HV_HYPERCALL_UNINSTALL_EPT_HOOK2: u64 = 4;

/// Restores the default installed hook view after a hooked syscall returns (RCX=GPA page base).
pub const HV_HYPERCALL_RESTORE_EPT_HOOK2: u64 = 5;

/// Exits virtualization on the current logical processor.
pub const HV_HYPERCALL_VMXOFF: u64 = 6;

/// Returned in RAX when a hypercall succeeds.
pub const HV_HYPERCALL_SUCCESS: u64 = 0;

/// Returned in RAX when the hypercall number is not recognized.
pub const HV_HYPERCALL_INVALID: u64 = 1;

/// Returned in RAX when hypercall arguments are invalid.
pub const HV_HYPERCALL_INVALID_PARAMETER: u64 = 2;

/// Maximum bytes transferred by a single read/write hypercall.
pub const HV_MEM_IO_MAX_LEN: usize = 4096;

/// Returned in RCX on success from [`HV_HYPERCALL_PING`].
pub const HV_HYPERCALL_PING_RESPONSE: u64 = 0x4256_5248; // "BVRH"

/// Issues a hypercall from the guest.
///
/// # Arguments
/// - `hypercall`: hypercall number in RAX
/// - `arg0`..`arg3`: arguments in RCX, RDX, R8, R9
///
/// # Returns
/// `(status, rcx, rdx, r8)` after the hypercall returns.
#[inline]
pub fn issue(hypercall: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> (u64, u64, u64, u64) {
    let mut rax = hypercall;
    let mut rcx = arg0;
    let mut rdx = arg1;
    let mut r8 = arg2;
    let r9 = arg3;

    let is_intel = x86::cpuid::CpuId::new()
        .get_vendor_info()
        .is_some_and(|v| v.as_str() == "GenuineIntel");

    unsafe {
        if is_intel {
            core::arch::asm!(
                "vmcall",
                inout("rax") rax,
                inout("rcx") rcx,
                inout("rdx") rdx,
                inout("r8") r8,
                in("r9") r9,
                options(nostack),
            );
        } else {
            core::arch::asm!(
                "vmmcall",
                inout("rax") rax,
                inout("rcx") rcx,
                inout("rdx") rdx,
                inout("r8") r8,
                in("r9") r9,
                options(nostack),
            );
        }
    }

    (rax, rcx, rdx, r8)
}

/// Returns `true` if Barevisor handled the ping hypercall.
#[inline]
pub fn ping() -> bool {
    let (status, rcx, _, _) = issue(HV_HYPERCALL_PING, 0, 0, 0, 0);
    status == HV_HYPERCALL_SUCCESS && rcx == HV_HYPERCALL_PING_RESPONSE
}

/// Reads guest memory through the hypervisor.
#[inline]
pub fn read_memory(address: u64, buffer: *mut u8, size: usize) -> bool {
    if size == 0 || size > HV_MEM_IO_MAX_LEN || buffer.is_null() {
        return false;
    }
    let (status, _, _, _) = issue(
        HV_HYPERCALL_READ_MEMORY,
        address,
        size as u64,
        buffer as u64,
        0,
    );
    status == HV_HYPERCALL_SUCCESS
}

/// Writes guest memory through the hypervisor.
#[inline]
pub fn write_memory(address: u64, buffer: *const u8, size: usize) -> bool {
    if size == 0 || size > HV_MEM_IO_MAX_LEN || buffer.is_null() {
        return false;
    }
    let (status, _, _, _) = issue(
        HV_HYPERCALL_WRITE_MEMORY,
        address,
        size as u64,
        buffer as u64,
        0,
    );
    status == HV_HYPERCALL_SUCCESS
}

/// Installs an EPT Hook2 page hook in the hypervisor.
#[inline]
pub fn install_ept_hook2(gpa_page_base: u64, fake_page_hpa: u64) -> bool {
    let (status, _, _, _) = issue(
        HV_HYPERCALL_INSTALL_EPT_HOOK2,
        gpa_page_base,
        fake_page_hpa,
        0,
        0,
    );
    status == HV_HYPERCALL_SUCCESS
}

/// Removes an EPT Hook2 page hook from the hypervisor.
#[inline]
pub fn uninstall_ept_hook2(gpa_page_base: u64) -> bool {
    let (status, _, _, _) = issue(HV_HYPERCALL_UNINSTALL_EPT_HOOK2, gpa_page_base, 0, 0, 0);
    status == HV_HYPERCALL_SUCCESS
}

/// Restores the default installed hook view (original PFN, execute blocked).
#[inline]
pub fn restore_ept_hook2(gpa_page_base: u64) -> bool {
    let (status, _, _, _) = issue(HV_HYPERCALL_RESTORE_EPT_HOOK2, gpa_page_base, 0, 0, 0);
    status == HV_HYPERCALL_SUCCESS
}

/// Issues the devirtualize hypercall. Does not return if the hypervisor handles it.
#[inline]
pub fn devirtualize() {
    let is_intel = x86::cpuid::CpuId::new()
        .get_vendor_info()
        .is_some_and(|v| v.as_str() == "GenuineIntel");

    unsafe {
        if is_intel {
            core::arch::asm!(
                "vmcall",
                in("rax") HV_HYPERCALL_VMXOFF,
                options(nostack),
            );
        } else {
            core::arch::asm!(
                "vmmcall",
                in("rax") HV_HYPERCALL_VMXOFF,
                options(nostack),
            );
        }
    }
}
