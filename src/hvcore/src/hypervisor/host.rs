//! This module implements architecture agnostic parts of the host code.

use x86::{
    controlregs::{Cr4, Xcr0},
    cpuid::cpuid,
};

use crate::hypervisor::{
    HV_CPUID_INTERFACE, HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, OUR_HV_VENDOR_NAME_EBX,
    OUR_HV_VENDOR_NAME_ECX, OUR_HV_VENDOR_NAME_EDX, apic_id,
    hypercall::{
        HV_HYPERCALL_INSTALL_EPT_HOOK2, HV_HYPERCALL_INVALID, HV_HYPERCALL_INVALID_PARAMETER,
        HV_HYPERCALL_PING, HV_HYPERCALL_PING_RESPONSE, HV_HYPERCALL_READ_MEMORY,
        HV_HYPERCALL_RESTORE_EPT_HOOK2, HV_HYPERCALL_SUCCESS, HV_HYPERCALL_UNINSTALL_EPT_HOOK2,
        HV_HYPERCALL_VMXOFF, HV_HYPERCALL_WRITE_MEMORY,
        HV_MEM_IO_MAX_LEN,
    },
    registers::Registers,
    x86_instructions::{cr4, cr4_write, rdmsr, wrmsr, xsetbv},
};

use super::{amd::Amd, intel::{self, Intel}};

/// The entry point of the hypervisor.
pub(crate) fn main(registers: &Registers) -> ! {
    // Disable interrupt for a couple of reasons. (1) to avoid panic due to
    // interrupt, and (2) to avoid inconsistent guest initial state.
    //
    // (1): In this path, we will switch to the host IDT if specified. The host
    // IDT only panics on any interrupt. This is an issue on UEFI where we update
    // the IDT.
    // (2): An interrupt may change the system register values before and after,
    // which could leave the guest initial state inconsistent because we copy the
    // current system register values one by one for the guest. For example, we
    // set a SS value as non-zero for the guest, interrupt occurs and SS becomes
    // zero, then we set SS access rights for the guest based on SS being zero.
    // That would leave the guest SS and SS access rights inconsistent. This is
    // an issue on Windows.
    //
    // Note that NMI is still possible and can cause the same issue. We just
    // never observed it causing the described issues.
    unsafe { x86::irq::disable() };

    // Start the host on the current processor.
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        virtualize_core::<Intel>(registers)
    } else {
        virtualize_core::<Amd>(registers)
    }
}

/// Enables the virtualization extension, sets up and runs the guest indefinitely.
fn virtualize_core<Arch: Architecture>(registers: &Registers) -> ! {
    log::info!("Initializing the guest");

    // Enable processor's virtualization technology.
    let mut vt = Arch::VirtualizationExtension::default();
    vt.enable();

    // Create a new (empty) guest instance and set up its initial state.
    let id = apic_id::processor_id_from(apic_id::get()).unwrap();
    let mut guest = Arch::Guest::new(id);
    guest.activate();
    guest.initialize(registers);

    log::info!("Starting the guest");
    loop {
        // Then, run the guest until VM-exit occurs. Some of events are handled
        // within the architecture specific code and nothing to do here.
        match guest.run() {
            VmExitReason::Cpuid(info) => handle_cpuid(&mut guest, &info),
            VmExitReason::Rdmsr(info) => handle_rdmsr(&mut guest, &info),
            VmExitReason::Wrmsr(info) => handle_wrmsr(&mut guest, &info),
            VmExitReason::XSetBv(info) => handle_xsetbv(&mut guest, &info),
            VmExitReason::VmCall(info) => {
                if guest.regs().rax == HV_HYPERCALL_VMXOFF {
                    devirtualize_processor(&mut guest, &mut vt, &info);
                } else {
                    handle_vmcall(&mut guest, &info);
                }
            }
            VmExitReason::EptViolation(vcpu_id) => {
                let qualification = intel::guest::vmcs_exit_qualification();
                let guest_phys = intel::guest::vmcs_guest_physical_address();
                if !intel::ept_hook::handle_ept_violation(vcpu_id, qualification, guest_phys) {
                    log::error!("Unexpected EPT violation");
                }
            }
            VmExitReason::MonitorTrapFlag(_) => {
                log::error!("Unexpected MTF VM-exit");
            }
            VmExitReason::EptMisconfiguration => {
                static MISCONFIG_COUNT: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0);
                let guest_phys = intel::guest::vmcs_guest_physical_address();
                let qualification = intel::guest::vmcs_exit_qualification();
                let guest_rip = intel::guest::vmcs_guest_rip();
                let guest_gva = intel::guest::vmcs_guest_linear_address();
                let page_base = guest_phys & !0xFFF;
                let n = MISCONFIG_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
                crate::hv_dbg!(
                    "host ept_misconfig #{n}: gpa={guest_phys:#x} page={page_base:#x} qual={qualification:#x} rip={guest_rip:#x} gva={guest_gva:#x}"
                );
                let ept = intel::guest::ept_state().lock();
                match ept.pml1_entry(page_base) {
                    Ok(entry) => {
                        let (pfn, r, w, x) = entry.access_summary();
                        crate::hv_dbg!(
                            "host ept_misconfig pte: raw={:#x} pfn={pfn:#x} r={} w={} x={} large={} mt={}",
                            entry.raw_value(),
                            u8::from(r),
                            u8::from(w),
                            u8::from(x),
                            u8::from(entry.is_large()),
                            entry.memory_type_value()
                        );
                    }
                    Err(err) => {
                        crate::hv_dbg!("host ept_misconfig pte lookup failed: {err:?}");
                        match ept.pde_entry(page_base) {
                            Ok(pde) => {
                                crate::hv_dbg!(
                                    "host ept_misconfig pde: raw={:#x} pfn={:#x} large={} mt={}",
                                    pde.raw_value(),
                                    pde.page_pfn(),
                                    u8::from(pde.is_large()),
                                    pde.memory_type_value()
                                );
                            }
                            Err(pde_err) => {
                                crate::hv_dbg!("host ept_misconfig pde lookup failed: {pde_err:?}");
                            }
                        }
                    }
                }
                drop(ept);
                log::error!("EPT misconfiguration at gpa={guest_phys:#x}");
            }
            VmExitReason::InitSignal | VmExitReason::StartupIpi | VmExitReason::NestedPageFault => {
            }
        }
    }
}

/// Leaves VMX root operation on the current processor. Mirrors Hypervisor From
/// Scratch's `VmxVmxoff`: restore guest CPU state, clear the VMCS, execute
/// VMXOFF, then return to the guest at the instruction after VMCALL.
fn devirtualize_processor<T: Guest, E: Extension>(
    guest: &mut T,
    vt: &mut E,
    info: &InstructionInfo,
) -> ! {
    log::info!("Devirtualizing the current processor");
    guest.regs().rip = info.next_rip;
    guest.load_guest_cpu_state();
    guest.deactivate();
    vt.disable();
    unsafe { guest.regs().restore() };
}

fn handle_cpuid<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let leaf = guest.regs().rax as u32;
    let sub_leaf = guest.regs().rcx as u32;
    log::trace!("CPUID {leaf:#x?} {sub_leaf:#x?}");
    let mut cpuid_result = cpuid!(leaf, sub_leaf);

    if leaf == 1 {
        // On the Intel processor, CPUID.1.ECX[5] indicates if VT-x is supported.
        // Clear this to prevent other hypervisor tries to use it. On AMD, it is
        // a reserved bit.
        // See: Table 3-10. Feature Information Returned in the ECX Register
        cpuid_result.ecx &= !(1 << 5);
    } else if leaf == HV_CPUID_VENDOR_AND_MAX_FUNCTIONS {
        // If the hypervisor vendor name is asked, return our hypervisor name,
        // so that `is_our_hypervisor_present` can detect the presence.
        cpuid_result.ebx = OUR_HV_VENDOR_NAME_EBX;
        cpuid_result.ecx = OUR_HV_VENDOR_NAME_ECX;
        cpuid_result.edx = OUR_HV_VENDOR_NAME_EDX;
    } else if leaf == HV_CPUID_INTERFACE {
        // Return non "Hv#1" into EAX. This indicate that our hypervisor does NOT
        // conform to the Microsoft hypervisor interface. This prevents the guest
        // from using the interface for optimum performance, but simplifies
        // implementation of our hypervisor. This is required only when testing
        // in the virtualization platform that supports the Microsoft hypervisor
        // interface, such as VMware, and not required for a baremetal.
        // See: Hypervisor Top Level Functional Specification
        cpuid_result.eax = 0;
    }

    guest.regs().rax = u64::from(cpuid_result.eax);
    guest.regs().rbx = u64::from(cpuid_result.ebx);
    guest.regs().rcx = u64::from(cpuid_result.ecx);
    guest.regs().rdx = u64::from(cpuid_result.edx);
    guest.regs().rip = info.next_rip;
}

/// Handles the `RDMSR` instruction for the range not covered by MSR bitmaps.
fn handle_rdmsr<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let msr = guest.regs().rcx as u32;
    log::trace!("RDMSR {msr:#x?}");

    // Passthrough any MSR access. Beware of that VM-exit occurs even for an
    // invalid MSR access which causes #GP(0).
    // See: 26.1.1 Relative Priority of Faults and VM Exits
    //
    // One solution is to catch the exception and inject it into the guest.
    let value = rdmsr(msr);

    guest.regs().rax = value & 0xffff_ffff;
    guest.regs().rdx = value >> 32;
    guest.regs().rip = info.next_rip;
}

/// Handles the `WRMSR` instruction for the range not covered by MSR bitmaps.
fn handle_wrmsr<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let msr = guest.regs().rcx as u32;
    let value = (guest.regs().rax & 0xffff_ffff) | ((guest.regs().rdx & 0xffff_ffff) << 32);
    log::trace!("WRMSR {msr:#x?} {value:#x?}");

    // See the comment in `handle_rdmsr`.
    wrmsr(msr, value);

    guest.regs().rip = info.next_rip;
}

// Handles the `XSETBV` instruction.
fn handle_xsetbv<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let xcr: u32 = guest.regs().rcx as u32;
    let value = (guest.regs().rax & 0xffff_ffff) | ((guest.regs().rdx & 0xffff_ffff) << 32);
    let value = Xcr0::from_bits(value).unwrap();
    log::trace!("XSETBV {xcr:#x?} {value:#x?}");

    // The host CR4 might not have this bit, which is required for executing the
    // `XSETBV` instruction. Set this bit and run the instruction.
    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);

    // XCR may be invalid and this instruction may cause #GP(0). See the comment
    // in `handle_rdmsr`.
    xsetbv(xcr, value);

    guest.regs().rip = info.next_rip;
}

/// Handles the `VMCALL` / `VMMCALL` instruction.
fn handle_vmcall<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let hypercall = guest.regs().rax;
    log::trace!("VMCALL {hypercall:#x?}");

    let status = match hypercall {
        HV_HYPERCALL_PING => {
            guest.regs().rcx = HV_HYPERCALL_PING_RESPONSE;
            HV_HYPERCALL_SUCCESS
        }
        HV_HYPERCALL_READ_MEMORY | HV_HYPERCALL_WRITE_MEMORY => {
            handle_memory_hypercall(guest, hypercall)
        }
        HV_HYPERCALL_INSTALL_EPT_HOOK2 => handle_install_ept_hook2(guest),
        HV_HYPERCALL_UNINSTALL_EPT_HOOK2 => handle_uninstall_ept_hook2(guest),
        HV_HYPERCALL_RESTORE_EPT_HOOK2 => handle_restore_ept_hook2(guest),
        _ => {
            crate::hv_dbg!("host vmcall: unknown hypercall={hypercall:#x}");
            HV_HYPERCALL_INVALID
        }
    };

    guest.regs().rax = status;
    guest.regs().rip = info.next_rip;
}

fn handle_memory_hypercall<T: Guest>(guest: &mut T, hypercall: u64) -> u64 {
    let address = guest.regs().rcx;
    let size = guest.regs().rdx as usize;
    let buffer_va = guest.regs().r8;

    if size == 0 || size > HV_MEM_IO_MAX_LEN {
        return HV_HYPERCALL_INVALID_PARAMETER;
    }
    if !is_canonical_va(address) || !is_canonical_va(buffer_va) {
        return HV_HYPERCALL_INVALID_PARAMETER;
    }

    let (src, dst) = if hypercall == HV_HYPERCALL_READ_MEMORY {
        (address as *const u8, buffer_va as *mut u8)
    } else {
        (buffer_va as *const u8, address as *mut u8)
    };

    if src.is_null() || dst.is_null() {
        return HV_HYPERCALL_INVALID_PARAMETER;
    }

    // SAFETY: The default host configuration shares guest page tables, so guest
    // virtual addresses are directly accessible while handling the hypercall.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, size);
    }
    HV_HYPERCALL_SUCCESS
}

fn handle_install_ept_hook2<T: Guest>(guest: &mut T) -> u64 {
    if !is_intel_processor() {
        return HV_HYPERCALL_INVALID;
    }
    let gpa_page_base = guest.regs().rcx & !0xFFF;
    let fake_page_hpa = guest.regs().rdx & !0xFFF;
    if gpa_page_base == 0 || fake_page_hpa == 0 {
        return HV_HYPERCALL_INVALID_PARAMETER;
    }

    let mut ept = intel::guest::ept_state().lock();
    match intel::ept_hook::install(&mut ept, gpa_page_base, fake_page_hpa) {
        Ok(()) => HV_HYPERCALL_SUCCESS,
        Err(_) => HV_HYPERCALL_INVALID_PARAMETER,
    }
}

fn handle_uninstall_ept_hook2<T: Guest>(guest: &mut T) -> u64 {
    if !is_intel_processor() {
        return HV_HYPERCALL_INVALID;
    }
    let gpa_page_base = guest.regs().rcx & !0xFFF;
    if gpa_page_base == 0 {
        return HV_HYPERCALL_INVALID_PARAMETER;
    }

    let mut ept = intel::guest::ept_state().lock();
    match intel::ept_hook::uninstall(&mut ept, gpa_page_base) {
        Ok(()) => HV_HYPERCALL_SUCCESS,
        Err(_) => HV_HYPERCALL_INVALID_PARAMETER,
    }
}

fn handle_restore_ept_hook2<T: Guest>(guest: &mut T) -> u64 {
    if !is_intel_processor() {
        return HV_HYPERCALL_INVALID;
    }
    let gpa_page_base = guest.regs().rcx & !0xFFF;
    if gpa_page_base == 0 {
        return HV_HYPERCALL_INVALID_PARAMETER;
    }

    let mut ept = intel::guest::ept_state().lock();
    if intel::ept_hook::restore_installed_view(&mut ept, gpa_page_base) {
        HV_HYPERCALL_SUCCESS
    } else {
        HV_HYPERCALL_INVALID_PARAMETER
    }
}

fn is_canonical_va(address: u64) -> bool {
    address <= 0x0000_7FFF_FFFF_FFFF || address >= 0xFFFF_8000_0000_0000
}

fn is_intel_processor() -> bool {
    x86::cpuid::CpuId::new()
        .get_vendor_info()
        .is_some_and(|vendor| vendor.as_str() == "GenuineIntel")
}

/// Represents a processor architecture that implements hardware-assisted virtualization.
pub(crate) trait Architecture {
    type VirtualizationExtension: Extension;
    type Guest: Guest;
}

/// Represents an implementation of a hardware-assisted virtualization extension.
pub(crate) trait Extension: Default {
    /// Enables the hardware-assisted virtualization extension.
    fn enable(&mut self);

    /// Disables the hardware-assisted virtualization extension.
    fn disable(&mut self);
}

/// Represents an implementation of a guest.
pub(crate) trait Guest {
    /// Creates an empty uninitialized guest, which must be activated with
    /// `activate` first.
    fn new(id: usize) -> Self;

    /// Tells the processor to operate on this guest. Must be called before any
    /// other functions are used.
    fn activate(&mut self);

    /// Initializes the guest based on `registers` and the current system register
    /// values.
    fn initialize(&mut self, registers: &Registers);

    /// Runs the guest until VM-exit occurs.
    fn run(&mut self) -> VmExitReason;

    /// Tells the processor to stop operating on this guest. Must be called
    /// before [`Extension::disable`].
    fn deactivate(&mut self);

    /// Loads guest system register values into the physical processor before
    /// leaving VMX root operation.
    fn load_guest_cpu_state(&self);

    /// Gets a reference to some of guest registers.
    fn regs(&mut self) -> &mut Registers;
}

/// The reasons of VM-exit and additional information.
pub(crate) enum VmExitReason {
    Cpuid(InstructionInfo),
    Rdmsr(InstructionInfo),
    Wrmsr(InstructionInfo),
    XSetBv(InstructionInfo),
    VmCall(InstructionInfo),
    EptViolation(usize),
    EptMisconfiguration,
    MonitorTrapFlag(usize),
    InitSignal,
    StartupIpi,
    NestedPageFault,
}

pub(crate) struct InstructionInfo {
    /// The next RIP of the guest in case the current instruction is emulated.
    pub(crate) next_rip: u64,
}
