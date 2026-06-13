//! Hypercall interface between the guest and the host hypervisor.
//!
//! Guest code issues `VMCALL` (Intel) or `VMMCALL` (AMD). The host handles the
//! request in `host::handle_vmcall` and resumes the guest with results in
//! registers.

/// Verifies that Barevisor is handling hypercalls.
pub const HV_HYPERCALL_PING: u64 = 0;

/// Returned in RAX when a hypercall succeeds.
pub const HV_HYPERCALL_SUCCESS: u64 = 0;

/// Returned in RAX when the hypercall number is not recognized.
pub const HV_HYPERCALL_INVALID: u64 = 1;

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
