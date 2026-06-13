//! EPT Hook2: hidden inline detour via execute-only fake pages.

use alloc::vec::Vec;
use spin::Mutex;
use x86::bits64::paging::BASE_PAGE_SIZE;
use crate::hypervisor::x86_instructions::rdmsr;

use super::epts::{EptEntry, EptError, EptState, invept_single_context};
use super::guest::set_monitor_trap_flag;

const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
const MAX_HOOKS: usize = super::epts::MAX_EPT_DYNAMIC_SPLITS;
const MAX_VCPUS: usize = 256;
const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;

// Intel EPT violation qualification (Vol. 3C §28.3.1), matching HyperDbg checks.
const QUAL_READ_ACCESS: u64 = 1 << 0;
const QUAL_WRITE_ACCESS: u64 = 1 << 1;
const QUAL_EPT_READABLE: u64 = 1 << 3;
const QUAL_EPT_WRITABLE: u64 = 1 << 4;

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

    {
        let hooks = HOOKS.lock();
        if hooks.len() >= MAX_HOOKS {
            return Err(HookError::TooManyHooks);
        }
        if hooks.iter().any(|h| h.gpa_page_base == gpa_page_base) {
            return Err(HookError::AlreadyHooked);
        }
    }

    ept.split_2mb_to_4kb(gpa_page_base)
        .map_err(|_| HookError::EptError)?;

    let original_pte = *ept.pml1_entry_mut(gpa_page_base).map_err(|_| HookError::EptError)?;
    let hooked_pte = EptEntry::as_execute_only_fake(original_pte, fake_page_hpa);
    let hook_entry = EptHookedPage {
        gpa_page_base,
        original_pte,
        hooked_pte,
    };

    // Register before activating the hooked PTE so violation handlers can find it.
    {
        let mut hooks = HOOKS.lock();
        if hooks.iter().any(|h| h.gpa_page_base == gpa_page_base) {
            return Err(HookError::AlreadyHooked);
        }
        hooks.push(hook_entry);
    }

    *ept.pml1_entry_mut(gpa_page_base).map_err(|_| HookError::EptError)? = hooked_pte;
    invept_single_context(ept.eptp());

    log::trace!(
        "ept_hook installed gpa={gpa_page_base:#x} fake_hpa={fake_page_hpa:#x}"
    );
    Ok(())
}

pub(crate) fn uninstall(ept: &mut EptState, gpa_page_base: u64) -> Result<(), HookError> {
    let page_base = gpa_page_base & !(BASE_PAGE_SIZE as u64 - 1);

    let hook = {
        let mut hooks = HOOKS.lock();
        let index = hooks
            .iter()
            .position(|h| h.gpa_page_base == page_base)
            .ok_or(HookError::NotFound)?;
        hooks.remove(index)
    };

    *ept.pml1_entry_mut(page_base)
        .map_err(|_| HookError::EptError)? = hook.original_pte;
    invept_single_context(ept.eptp());
    log::trace!("ept_hook uninstalled gpa={page_base:#x}");
    Ok(())
}

pub(crate) fn handle_ept_violation(vcpu_id: usize, qualification: u64, guest_phys_addr: u64) -> bool {
    let page_base = guest_phys_addr & !(BASE_PAGE_SIZE as u64 - 1);

    // Lock order must always be EPT -> HOOKS (install holds EPT then HOOKS).
    let mut ept = super::guest::ept_state().lock();
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

    let Ok(entry) = ept.pml1_entry_mut(page_base) else {
        log::error!(
            "ept_hook violation: pml1 lookup failed vcpu={vcpu_id} gpa={page_base:#x} qual={qualification:#x}"
        );
        return false;
    };

    // HyperDbg: !EptReadable && ReadAccess / !EptWritable && WriteAccess
    let read_violation =
        qualification & QUAL_READ_ACCESS != 0 && qualification & QUAL_EPT_READABLE == 0;
    let write_violation =
        qualification & QUAL_WRITE_ACCESS != 0 && qualification & QUAL_EPT_WRITABLE == 0;

    if read_violation || write_violation {
        // Swap to original PFN for one guest instruction, then restore via MTF.
        *entry = hook.original_pte;
        invept_single_context(ept.eptp());
        *MTF_GPA[vcpu_slot(vcpu_id)].lock() = Some(page_base);
        if !set_monitor_trap_flag(true) {
            log::error!("ept_hook violation: failed to enable MTF vcpu={vcpu_id}");
            *MTF_GPA[vcpu_slot(vcpu_id)].lock() = None;
            return false;
        }
        log::trace!(
            "ept_hook violation: data -> original vcpu={vcpu_id} gpa={page_base:#x} qual={qualification:#x}"
        );
    }

    true
}

pub(crate) fn handle_mtf(vcpu_id: usize) -> bool {
    let slot_index = vcpu_slot(vcpu_id);
    let page_base = {
        let mut slot = MTF_GPA[slot_index].lock();
        let Some(gpa) = *slot else {
            log::error!("ept_hook mtf: no pending restore vcpu={vcpu_id}");
            let _ = set_monitor_trap_flag(false);
            return false;
        };
        *slot = None;
        gpa
    };

    let mut ept = super::guest::ept_state().lock();
    let hook = {
        let hooks = HOOKS.lock();
        hooks
            .iter()
            .find(|h| h.gpa_page_base == page_base)
            .copied()
    };
    let Some(hook) = hook else {
        log::error!("ept_hook mtf: hook missing gpa={page_base:#x} vcpu={vcpu_id}");
        let _ = set_monitor_trap_flag(false);
        return false;
    };

    match ept.pml1_entry_mut(page_base) {
        Ok(entry) => {
            *entry = hook.hooked_pte;
            invept_single_context(ept.eptp());
        }
        Err(_) => {
            log::error!("ept_hook mtf: pml1 lookup failed gpa={page_base:#x}");
            let _ = set_monitor_trap_flag(false);
            return false;
        }
    }

    if !set_monitor_trap_flag(false) {
        log::error!("ept_hook mtf: failed to disable MTF vcpu={vcpu_id}");
        return false;
    }
    true
}

fn vcpu_slot(vcpu_id: usize) -> usize {
    vcpu_id.min(MAX_VCPUS - 1)
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
    fn from(err: EptError) -> Self {
        match err {
            EptError::NoSplitSlots => HookError::TooManyHooks,
            _ => HookError::EptError,
        }
    }
}
