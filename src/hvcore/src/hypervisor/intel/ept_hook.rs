//! EPT Hook2: hidden inline detour via execute-only fake pages.

use alloc::vec::Vec;
use spin::Mutex;
use x86::bits64::paging::BASE_PAGE_SIZE;
use crate::hypervisor::x86_instructions::rdmsr;

use super::epts::{EptEntry, EptError, EptState, invept_single_context};
use super::guest::set_monitor_trap_flag;

const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
const MAX_HOOKS: usize = 16;
const MAX_VCPUS: usize = 256;
const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
struct EptHookedPage {
    gpa_page_base: u64,
    original_pte: EptEntry,
    hooked_pte: EptEntry,
}

static HOOKS: Mutex<Vec<EptHookedPage>> = Mutex::new(Vec::new());
static MTF_GPA: [Mutex<Option<u64>>; MAX_VCPUS] =
    [const { Mutex::new(None) }; MAX_VCPUS];

/// Returns whether the processor supports EPT execute-only pages.
pub(crate) fn execute_only_supported() -> bool {
    let cap = rdmsr(IA32_VMX_EPT_VPID_CAP);
    cap & 1 != 0
}

pub(crate) fn install(
    ept: &mut EptState,
    gpa_page_base: u64,
    fake_page_hpa: u64,
) -> Result<(), HookError> {
    if !execute_only_supported() {
        return Err(HookError::NoExecuteOnly);
    }
    if gpa_page_base & 0xFFF != 0 || fake_page_hpa & 0xFFF != 0 {
        return Err(HookError::InvalidParameter);
    }
    if gpa_page_base >= SIZE_512_GB {
        return Err(HookError::OutOfRange);
    }

    let mut hooks = HOOKS.lock();
    if hooks.len() >= MAX_HOOKS {
        return Err(HookError::TooManyHooks);
    }
    if hooks.iter().any(|h| h.gpa_page_base == gpa_page_base) {
        return Err(HookError::AlreadyHooked);
    }

    ept.split_2mb_to_4kb(gpa_page_base)
        .map_err(|_| HookError::EptError)?;

    let original_pte = *ept.pml1_entry_mut(gpa_page_base).map_err(|_| HookError::EptError)?;
    let hooked_pte = EptEntry::as_execute_only_fake(original_pte, fake_page_hpa);

    *ept.pml1_entry_mut(gpa_page_base).map_err(|_| HookError::EptError)? = hooked_pte;
    invept_single_context(ept.eptp());

    hooks.push(EptHookedPage {
        gpa_page_base,
        original_pte,
        hooked_pte,
    });
    Ok(())
}

pub(crate) fn uninstall(ept: &mut EptState, gpa_page_base: u64) -> Result<(), HookError> {
    let page_base = gpa_page_base & !(BASE_PAGE_SIZE as u64 - 1);
    let mut hooks = HOOKS.lock();
    let index = hooks
        .iter()
        .position(|h| h.gpa_page_base == page_base)
        .ok_or(HookError::NotFound)?;
    let hook = hooks.remove(index);

    *ept.pml1_entry_mut(page_base)
        .map_err(|_| HookError::EptError)? = hook.original_pte;
    invept_single_context(ept.eptp());
    Ok(())
}

pub(crate) fn handle_ept_violation(vcpu_id: usize, qualification: u64, guest_phys_addr: u64) -> bool {
    let page_base = guest_phys_addr & !(BASE_PAGE_SIZE as u64 - 1);
    let hook = {
        let hooks = HOOKS.lock();
        hooks
            .iter()
            .find(|h| h.gpa_page_base == page_base)
            .copied()
    };
    let Some(hook) = hook else {
        return false;
    };

    let read_access = qualification & 0b1 != 0;
    let write_access = qualification & 0b10 != 0;

    let mut ept = super::guest::ept_state().lock();
    let Ok(entry) = ept.pml1_entry_mut(page_base) else {
        return true;
    };

    if read_access || write_access {
        *entry = hook.original_pte;
        invept_single_context(ept.eptp());
        *MTF_GPA[vcpu_id.min(MAX_VCPUS - 1)].lock() = Some(page_base);
        set_monitor_trap_flag(true);
    } else {
        *entry = hook.hooked_pte;
        invept_single_context(ept.eptp());
    }

    true
}

pub(crate) fn handle_mtf(vcpu_id: usize) -> bool {
    let page_base = {
        let mut slot = MTF_GPA[vcpu_id.min(MAX_VCPUS - 1)].lock();
        let Some(gpa) = *slot else {
            return false;
        };
        *slot = None;
        gpa
    };

    let hook = hook_copy_for(page_base);
    let mut ept = super::guest::ept_state().lock();
    if let Ok(entry) = ept.pml1_entry_mut(page_base) {
        *entry = hook.hooked_pte;
        invept_single_context(ept.eptp());
    }
    set_monitor_trap_flag(false);
    true
}

fn hook_copy_for(gpa_page_base: u64) -> EptHookedPage {
    HOOKS
        .lock()
        .iter()
        .find(|h| h.gpa_page_base == gpa_page_base)
        .copied()
        .expect("hook must exist while handling violation")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookError {
    InvalidParameter,
    OutOfRange,
    AlreadyHooked,
    NotFound,
    TooManyHooks,
    NoExecuteOnly,
    EptError,
}

impl From<EptError> for HookError {
    fn from(_: EptError) -> Self {
        Self::EptError
    }
}
