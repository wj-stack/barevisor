//! Guest-to-hypervisor hypercalls issued via VMCALL (Intel) or VMMCALL (AMD).

use core::arch::asm;
use crate::hypervisor::Registers;

/// Exits virtualization on the current logical processor.
pub const DEVIRTUALIZE: u64 = 0;

/// Issues the devirtualize hypercall. Does not return if the hypervisor handles it.
#[inline]
pub fn devirtualize() {
    let is_intel = x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel";
    unsafe {
        if is_intel {
            log::info!("Issuing VMCALL to devirtualize: is_intel = true");
            asm!("int3");
            asm!("vmcall", in("rax") DEVIRTUALIZE, options(nostack));
            asm!("int3");
            log::info!("VMCALL to devirtualize returned");
        } else {
            log::info!("Issuing VMMCALL to devirtualize: is_intel = false");
            asm!("vmmcall", in("rax") DEVIRTUALIZE, options(nostack));
            log::info!("VMMCALL to devirtualize returned");
        }
    }
}
