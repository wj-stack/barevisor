//! Intel VMXOFF teardown (port of HyperDbg `VmxPerformVmxoff` / `HvRestoreRegisters`).

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::boxed::Box;
use spin::Once;
use x86::{dtables::DescriptorTablePointer, vmx::vmcs};

use crate::hypervisor::{
    apic_id::{self, PROCESSOR_COUNT},
    hypercall::HV_HYPERCALL_SUCCESS,
    x86_instructions::{cr3_write, cr4_write, lgdt, lidt, wrmsr},
};

use super::guest::VmxGuest;

fn devirt_log(step: &str) {
    let apic = apic_id::get();
    let proc_id = apic_id::processor_id_from(apic).unwrap_or(usize::MAX);
    crate::hv_dbg!("devirt: cpu {proc_id} apic {apic:#x}: {step}");
}

fn devirt_log_ctx(step: &str, rip: u64, rsp: u64, cr3: u64, cr4: u64) {
    let apic = apic_id::get();
    let proc_id = apic_id::processor_id_from(apic).unwrap_or(usize::MAX);
    crate::hv_dbg!(
        "devirt: cpu {proc_id} apic {apic:#x}: {step} rip={rip:#x} rsp={rsp:#x} cr3={cr3:#x} cr4={cr4:#x}"
    );
}

pub(crate) struct DevirtState {
    pub guest_rip: AtomicU64,
    pub guest_rsp: AtomicU64,
    pub is_done: AtomicBool,
}

static PER_CPU_DEVIRT: Once<Box<[DevirtState]>> = Once::new();

static DEVIRT_EPT_PREPARED: AtomicBool = AtomicBool::new(false);

/// Clears EPT hooks and flushes caches. Must run in VMX root (not guest).
fn devirt_prepare_ept() {
    if DEVIRT_EPT_PREPARED.swap(true, Ordering::SeqCst) {
        devirt_log("ept_prepare skipped (already done)");
        return;
    }
    devirt_log("ept_prepare uninstall_all + INVEPT all");
    super::ept_hook::uninstall_all();
    super::epts::invept_all_contexts();
    devirt_log("ept_prepare done");
}

pub(crate) fn reset_devirt_prepare_state() {
    DEVIRT_EPT_PREPARED.store(false, Ordering::SeqCst);
}

fn per_cpu_devirt() -> &'static [DevirtState] {
    PER_CPU_DEVIRT.call_once(|| {
        let n = PROCESSOR_COUNT.load(Ordering::Relaxed).max(1);
        (0..n)
            .map(|_| DevirtState {
                guest_rip: AtomicU64::new(0),
                guest_rsp: AtomicU64::new(0),
                is_done: AtomicBool::new(false),
            })
            .collect()
    })
}

fn current_devirt_state() -> &'static DevirtState {
    let id = apic_id::processor_id_from(apic_id::get()).unwrap_or(0);
    &per_cpu_devirt()[id]
}

#[unsafe(no_mangle)]
pub extern "C" fn devirt_guest_rsp() -> u64 {
    current_devirt_state().guest_rsp.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
pub extern "C" fn devirt_guest_rip() -> u64 {
    current_devirt_state().guest_rip.load(Ordering::SeqCst)
}

fn vmread_u64(field: u32) -> u64 {
    unsafe { x86::bits64::vmx::vmread(field) }.unwrap()
}

fn vmread_u16(field: u32) -> u16 {
    vmread_u64(field) as u16
}

/// Port of HyperDbg `HvRestoreRegisters` — before VMXOFF.
pub(crate) fn hv_restore_registers() {
    devirt_log("restore: FS/GS base MSRs");
    wrmsr(x86::msr::IA32_FS_BASE, vmread_u64(vmcs::guest::FS_BASE));
    wrmsr(x86::msr::IA32_GS_BASE, vmread_u64(vmcs::guest::GS_BASE));

    devirt_log("restore: GDTR");
    let gdtr = DescriptorTablePointer::<u64> {
        limit: vmread_u64(vmcs::guest::GDTR_LIMIT) as u16,
        base: vmread_u64(vmcs::guest::GDTR_BASE) as *const u64,
    };
    lgdt(&gdtr);

    devirt_log("restore: segment selectors DS/ES/SS/FS");
    unsafe {
        load_segment_selector(vmread_u16(vmcs::guest::DS_SELECTOR), "ds");
        load_segment_selector(vmread_u16(vmcs::guest::ES_SELECTOR), "es");
        load_segment_selector(vmread_u16(vmcs::guest::SS_SELECTOR), "ss");
        load_segment_selector(vmread_u16(vmcs::guest::FS_SELECTOR), "fs");
    }

    devirt_log("restore: IDTR");
    let idtr = DescriptorTablePointer::<u64> {
        limit: vmread_u64(vmcs::guest::IDTR_LIMIT) as u16,
        base: vmread_u64(vmcs::guest::IDTR_BASE) as *const u64,
    };
    lidt(&idtr);

    devirt_log("restore: done");
}

unsafe fn load_segment_selector(selector: u16, name: &str) {
    match name {
        "ds" => asm!("mov ds, {}", in(reg) selector, options(nostack, preserves_flags)),
        "es" => asm!("mov es, {}", in(reg) selector, options(nostack, preserves_flags)),
        "ss" => asm!("mov ss, {}", in(reg) selector, options(nostack, preserves_flags)),
        "fs" => asm!("mov fs, {}", in(reg) selector, options(nostack, preserves_flags)),
        _ => {}
    }
}

unsafe extern "C" {
    fn restore_guest_xmm_regs(regs: *const u8);
    fn exit_vmx_to_guest(regs: *mut u8) -> !;
}

/// Port of HyperDbg `VmxPerformVmxoff`. Does not return.
pub(crate) fn perform_vmxoff(guest: &mut VmxGuest) -> ! {
    use x86::controlregs::Cr4;

    devirt_log("perform_vmxoff enter (VMX root)");

    // INVEPT/VMX instructions trap from guest; run EPT teardown in VMX root.
    devirt_prepare_ept();

    let guest_cr3 = vmread_u64(vmcs::guest::CR3);
    cr3_write(guest_cr3);
    devirt_log_ctx("guest CR3 loaded", 0, 0, guest_cr3, 0);

    let mut guest_rip = vmread_u64(vmcs::guest::RIP);
    let guest_rsp = vmread_u64(vmcs::guest::RSP);
    let instr_len = vmread_u64(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
    guest_rip = guest_rip.wrapping_add(instr_len);

    let state = current_devirt_state();
    state.guest_rip.store(guest_rip, Ordering::SeqCst);
    state.guest_rsp.store(guest_rsp, Ordering::SeqCst);
    state.is_done.store(true, Ordering::SeqCst);

    devirt_log_ctx(
        "saved return context",
        guest_rip,
        guest_rsp,
        guest_cr3,
        vmread_u64(vmcs::guest::CR4),
    );

    devirt_log("hv_restore_registers");
    hv_restore_registers();

    let regs_ptr = guest.regs_mut() as *mut _ as *mut u8;
    devirt_log("restore_guest_xmm_regs");
    unsafe { restore_guest_xmm_regs(regs_ptr) };

    // VMREAD is illegal after VMXOFF — capture guest CR4 while the VMCS is still valid.
    let guest_cr4 = vmread_u64(vmcs::guest::CR4);

    devirt_log("VMCLEAR + VMXOFF");
    guest.vmclear_and_vmxoff();

    cr4_write(Cr4::from_bits_truncate(guest_cr4 as usize) & !Cr4::CR4_ENABLE_VMX);
    devirt_log_ctx("CR4.VMXE cleared", guest_rip, guest_rsp, guest_cr3, guest_cr4);

    guest.regs_mut().rax = HV_HYPERCALL_SUCCESS;

    devirt_log("exit_vmx_to_guest (native return)");
    unsafe { exit_vmx_to_guest(regs_ptr) }
}
