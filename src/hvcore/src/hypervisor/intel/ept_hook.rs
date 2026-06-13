//! EPT hook: hidden inline detour via split-view EPT permissions (HyperDbg Hook2).
//!
//! Install keeps the original PFN readable/writable but clears execute. Execute
//! violations swap in the fake execute-only page; read/write on the fake view
//! restores the original RWX PFN and stays there (TinyVT-style, no MTF).

use spin::Mutex;
use x86::bits64::paging::BASE_PAGE_SIZE;

use crate::hypervisor::x86_instructions::rdmsr;

use super::epts::{EptEntry, EptError, EptState, invept_single_context};

const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
const MAX_HOOKS: usize = super::epts::MAX_EPT_DYNAMIC_SPLITS;
const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
struct EptHookedPage {
    gpa_page_base: u64,
    /// Full PTE for the original page (RWX, original PFN).
    orig_pte: EptEntry,
    /// Default runtime view: original PFN, RW, no execute.
    installed_pte: EptEntry,
    /// Full PTE for the fake execute-only (or RX) hook view.
    hook_pte: EptEntry,
}

struct HookTable {
    entries: [Option<EptHookedPage>; MAX_HOOKS],
}

impl HookTable {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_HOOKS],
        }
    }

    fn find(&self, gpa_page_base: u64) -> Option<EptHookedPage> {
        self.entries
            .iter()
            .filter_map(|entry| *entry)
            .find(|hook| hook.gpa_page_base == gpa_page_base)
    }

    fn insert(&mut self, hook: EptHookedPage) -> Result<(), HookError> {
        if self.find(hook.gpa_page_base).is_some() {
            return Err(HookError::AlreadyHooked);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(HookError::TooManyHooks)?;
        *slot = Some(hook);
        Ok(())
    }

    fn remove(&mut self, gpa_page_base: u64) -> Result<EptHookedPage, HookError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| matches!(entry, Some(h) if h.gpa_page_base == gpa_page_base))
            .ok_or(HookError::NotFound)?;
        slot.take().ok_or(HookError::NotFound)
    }
}

static HOOKS: Mutex<HookTable> = Mutex::new(HookTable::new());

fn execute_only_supported() -> bool {
    rdmsr(IA32_VMX_EPT_VPID_CAP) & 1 != 0
}

fn decode_ept_violation(qualification: u64) -> (bool, bool, bool, bool, bool, bool) {
    let read_access = qualification & 1 != 0;
    let write_access = qualification & 2 != 0;
    let execute_access = qualification & 4 != 0;
    let ept_readable = qualification & 8 != 0;
    let ept_writable = qualification & 16 != 0;
    let ept_executable = qualification & 32 != 0;
    (
        read_access,
        write_access,
        execute_access,
        ept_readable,
        ept_writable,
        ept_executable,
    )
}

pub(crate) fn install(
    ept: &mut EptState,
    gpa_page_base: u64,
    fake_page_hpa: u64,
) -> Result<(), HookError> {
    if gpa_page_base & 0xFFF != 0 || fake_page_hpa & 0xFFF != 0 {
        return Err(HookError::InvalidParameter);
    }
    if gpa_page_base >= SIZE_512_GB {
        return Err(HookError::OutOfRange);
    }

    {
        let hooks = HOOKS.lock();
        if hooks.find(gpa_page_base).is_some() {
            return Err(HookError::AlreadyHooked);
        }
        if hooks.entries.iter().all(|entry| entry.is_some()) {
            return Err(HookError::TooManyHooks);
        }
    }

    ept.split_2mb_to_4kb(gpa_page_base).map_err(|_| HookError::EptError)?;

    let entry = ept
        .pml1_entry_mut(gpa_page_base)
        .map_err(|_| HookError::EptError)?;
    let orig_pte = *entry;

    let execute_only = execute_only_supported();
    let mut hook_pte = orig_pte;
    hook_pte.hook_install_execute_view(fake_page_hpa >> 12, execute_only);
    let mut installed_pte = orig_pte;
    installed_pte.hook_install_no_execute();
    let hook_entry = EptHookedPage {
        gpa_page_base,
        orig_pte,
        installed_pte,
        hook_pte,
    };

    HOOKS.lock().insert(hook_entry)?;

    entry.restore_pte(hook_entry.installed_pte);
    invept_single_context(ept.eptp());
    Ok(())
}

/// Restores the default hook view (original PFN, execute blocked) after a syscall completes.
pub(crate) fn restore_installed_view(ept: &mut EptState, gpa_page_base: u64) -> bool {
    let page_base = gpa_page_base & !(BASE_PAGE_SIZE as u64 - 1);
    let hook = match HOOKS.lock().find(page_base) {
        Some(hook) => hook,
        None => return false,
    };

    let Ok(entry) = ept.pml1_entry_mut(page_base) else {
        return false;
    };

    if entry.raw_value() == hook.installed_pte.raw_value() {
        return true;
    }

    entry.restore_pte(hook.installed_pte);
    invept_single_context(ept.eptp());
    true
}

pub(crate) fn uninstall(ept: &mut EptState, gpa_page_base: u64) -> Result<(), HookError> {
    let page_base = gpa_page_base & !(BASE_PAGE_SIZE as u64 - 1);

    let hook = HOOKS.lock().remove(page_base)?;

    let entry = ept
        .pml1_entry_mut(page_base)
        .map_err(|_| HookError::EptError)?;

    entry.restore_pte(hook.orig_pte);
    invept_single_context(ept.eptp());
    Ok(())
}

pub(crate) fn handle_ept_violation(
    _vcpu_id: usize,
    qualification: u64,
    guest_phys_addr: u64,
) -> bool {
    let page_base = guest_phys_addr & !(BASE_PAGE_SIZE as u64 - 1);
    let (read_access, write_access, execute_access, _, _, ept_executable) =
        decode_ept_violation(qualification);

    let mut ept = super::guest::ept_state().lock();
    let hook = match HOOKS.lock().find(page_base) {
        Some(hook) => hook,
        None => return false,
    };

    let Ok(entry) = ept.pml1_entry_mut(page_base) else {
        return false;
    };

    let eptp = if ept_executable && (read_access || write_access) {
        entry.restore_pte(hook.orig_pte);
        ept.eptp()
    } else if !ept_executable && execute_access {
        entry.restore_pte(hook.hook_pte);
        ept.eptp()
    } else {
        return false;
    };

    invept_single_context(eptp);
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookError {
    InvalidParameter,
    OutOfRange,
    AlreadyHooked,
    NotFound,
    TooManyHooks,
    EptError,
}

impl HookError {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidParameter => "invalid_parameter",
            Self::OutOfRange => "out_of_range",
            Self::AlreadyHooked => "already_hooked",
            Self::NotFound => "not_found",
            Self::TooManyHooks => "too_many_hooks",
            Self::EptError => "ept_error",
        }
    }
}

impl From<EptError> for HookError {
    fn from(err: EptError) -> Self {
        match err {
            EptError::NoSplitSlots => HookError::TooManyHooks,
            _ => HookError::EptError,
        }
    }
}
