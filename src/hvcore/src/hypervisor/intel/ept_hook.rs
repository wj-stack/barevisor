//! EPT hook: hidden inline detour via split-view EPT permissions (HyperDbg Hook2).
//!
//! Install keeps the original PFN readable/writable but clears execute. Execute
//! violations swap in the fake execute-only page; read/write on the fake view
//! temporarily restores the original PTE and uses MTF to reinstall the hook.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use x86::bits64::paging::BASE_PAGE_SIZE;

use crate::hypervisor::x86_instructions::rdmsr;

use super::epts::{EptEntry, EptError, EptState, invept_single_context};

const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
const MAX_HOOKS: usize = super::epts::MAX_EPT_DYNAMIC_SPLITS;
const MAX_VCPUS: usize = 256;
const MTF_NONE: u64 = u64::MAX;
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

    fn count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
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
static MTF_PENDING: [AtomicU64; MAX_VCPUS] = [const { AtomicU64::new(MTF_NONE) }; MAX_VCPUS];

fn execute_only_supported() -> bool {
    rdmsr(IA32_VMX_EPT_VPID_CAP) & 1 != 0
}

fn set_mtf_pending(vcpu_id: usize, gpa_page_base: u64) {
    if vcpu_id < MAX_VCPUS {
        MTF_PENDING[vcpu_id].store(gpa_page_base, Ordering::Relaxed);
    }
}

fn take_mtf_pending(vcpu_id: usize) -> Option<u64> {
    if vcpu_id >= MAX_VCPUS {
        return None;
    }
    let gpa = MTF_PENDING[vcpu_id].swap(MTF_NONE, Ordering::Relaxed);
    (gpa != MTF_NONE).then_some(gpa)
}

fn clear_mtf_pending_for_page(gpa_page_base: u64) {
    for pending in &MTF_PENDING {
        if pending.load(Ordering::Relaxed) == gpa_page_base {
            pending.store(MTF_NONE, Ordering::Relaxed);
        }
    }
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

fn log_pte(label: &str, gpa: u64, pfn: u64, readable: bool, writable: bool, executable: bool) {
    crate::hv_dbg!(
        "ept_hook {label}: gpa={gpa:#x} pfn={pfn:#x} r={} w={} x={}",
        u8::from(readable),
        u8::from(writable),
        u8::from(executable)
    );
}

pub(crate) fn install(
    ept: &mut EptState,
    gpa_page_base: u64,
    fake_page_hpa: u64,
) -> Result<(), HookError> {
    crate::hv_dbg!(
        "ept_hook install begin: gpa={gpa_page_base:#x} fake_hpa={fake_page_hpa:#x} hooks={}",
        HOOKS.lock().count()
    );

    if gpa_page_base & 0xFFF != 0 || fake_page_hpa & 0xFFF != 0 {
        crate::hv_dbg!("ept_hook install fail: invalid_parameter alignment");
        return Err(HookError::InvalidParameter);
    }
    if gpa_page_base >= SIZE_512_GB {
        crate::hv_dbg!("ept_hook install fail: out_of_range gpa={gpa_page_base:#x}");
        return Err(HookError::OutOfRange);
    }

    {
        let hooks = HOOKS.lock();
        if hooks.find(gpa_page_base).is_some() {
            crate::hv_dbg!("ept_hook install fail: already_hooked gpa={gpa_page_base:#x}");
            return Err(HookError::AlreadyHooked);
        }
        if hooks.entries.iter().all(|entry| entry.is_some()) {
            crate::hv_dbg!("ept_hook install fail: too_many_hooks");
            return Err(HookError::TooManyHooks);
        }
    }

    if let Err(err) = ept.split_2mb_to_4kb(gpa_page_base) {
        crate::hv_dbg!("ept_hook install fail: split_2mb_to_4kb gpa={gpa_page_base:#x} err={err:?}");
        return Err(HookError::EptError);
    }

    let entry = ept.pml1_entry_mut(gpa_page_base).map_err(|err| {
        crate::hv_dbg!(
            "ept_hook install fail: pml1_entry_mut gpa={gpa_page_base:#x} err={err:?}"
        );
        HookError::EptError
    })?;
    let orig_pte = *entry;
    let (orig_pfn, orig_r, orig_w, orig_x) = orig_pte.access_summary();
    log_pte("pre_install", gpa_page_base, orig_pfn, orig_r, orig_w, orig_x);

    let execute_only = execute_only_supported();
    let mut hook_pte = orig_pte;
    hook_pte.hook_install_execute_view(fake_page_hpa >> 12, execute_only);
    let mut installed_pte = orig_pte;
    installed_pte.hook_install_no_execute();
    crate::hv_dbg!(
        "ept_hook install: execute_only_supported={} orig_pfn={:#x} hook_pfn={:#x}",
        u8::from(execute_only),
        orig_pte.page_pfn(),
        hook_pte.page_pfn()
    );
    let hook_entry = EptHookedPage {
        gpa_page_base,
        orig_pte,
        installed_pte,
        hook_pte,
    };

    {
        let mut hooks = HOOKS.lock();
        hooks.insert(hook_entry).map_err(|err| {
            crate::hv_dbg!("ept_hook install fail: hook_table insert err={err:?}");
            err
        })?;
    }

    // Keep the original PFN visible for data, block execute only.
    entry.restore_pte(hook_entry.installed_pte);
    let (pfn, r, w, x) = entry.access_summary();
    log_pte("post_install", gpa_page_base, pfn, r, w, x);
    crate::hv_dbg!("ept_hook install: invept begin eptp={:#x}", ept.eptp().0);
    invept_single_context(ept.eptp());
    crate::hv_dbg!("ept_hook install: invept done");
    crate::hv_dbg!(
        "ept_hook install ok: gpa={gpa_page_base:#x} orig_pfn={:#x} hook_pfn={:#x} eptp={:#x}",
        orig_pte.page_pfn(),
        hook_pte.page_pfn(),
        ept.eptp().0
    );
    Ok(())
}

pub(crate) fn uninstall(ept: &mut EptState, gpa_page_base: u64) -> Result<(), HookError> {
    let page_base = gpa_page_base & !(BASE_PAGE_SIZE as u64 - 1);
    crate::hv_dbg!("ept_hook uninstall begin: gpa={page_base:#x}");

    let hook = match HOOKS.lock().remove(page_base) {
        Ok(hook) => hook,
        Err(_) => {
            crate::hv_dbg!("ept_hook uninstall fail: not_found gpa={page_base:#x}");
            return Err(HookError::NotFound);
        }
    };

    let entry = ept.pml1_entry_mut(page_base).map_err(|err| {
        crate::hv_dbg!(
            "ept_hook uninstall fail: pml1_entry_mut gpa={page_base:#x} err={err:?}"
        );
        HookError::EptError
    })?;
    let (pfn, r, w, x) = entry.access_summary();
    log_pte("pre_uninstall", page_base, pfn, r, w, x);

    entry.restore_pte(hook.orig_pte);
    let (pfn, r, w, x) = entry.access_summary();
    log_pte("post_uninstall", page_base, pfn, r, w, x);
    clear_mtf_pending_for_page(page_base);
    invept_single_context(ept.eptp());
    crate::hv_dbg!(
        "ept_hook uninstall ok: gpa={page_base:#x} restored_pfn={:#x}",
        hook.orig_pte.page_pfn()
    );
    Ok(())
}

pub(crate) fn handle_ept_violation(
    vcpu_id: usize,
    qualification: u64,
    guest_phys_addr: u64,
) -> bool {
    let page_base = guest_phys_addr & !(BASE_PAGE_SIZE as u64 - 1);
    let (
        read_access,
        write_access,
        execute_access,
        ept_readable,
        ept_writable,
        ept_executable,
    ) = decode_ept_violation(qualification);

    let mut ept = super::guest::ept_state().lock();
    let hook = HOOKS.lock().find(page_base);
    let Some(hook) = hook else {
        crate::hv_dbg!(
            "ept_hook violation: no hook vcpu={vcpu_id} gpa={page_base:#x} qual={qualification:#x}"
        );
        return false;
    };

    let Ok(entry) = ept.pml1_entry_mut(page_base) else {
        crate::hv_dbg!(
            "ept_hook violation: pml1 lookup failed vcpu={vcpu_id} gpa={page_base:#x} qual={qualification:#x}"
        );
        return false;
    };

    let (pfn_before, r_before, w_before, x_before) = entry.access_summary();
    let handled = if !ept_executable && execute_access {
        // Execute on the no-execute original view -> show the fake hook page.
        entry.restore_pte(hook.hook_pte);
        "exec"
    } else if (!ept_readable && read_access) || (!ept_writable && write_access) {
        // Read/write on the execute-only hook view -> original for one instruction.
        entry.restore_pte(hook.orig_pte);
        set_mtf_pending(vcpu_id, page_base);
        if !super::guest::set_monitor_trap_flag(true) {
            crate::hv_dbg!("ept_hook violation: failed to enable MTF vcpu={vcpu_id}");
            clear_mtf_pending_for_page(page_base);
            return false;
        }
        "data"
    } else {
        crate::hv_dbg!(
            "ept_hook violation: unexpected vcpu={vcpu_id} gpa={page_base:#x} qual={qualification:#x} ept(rwx)={}{}{} access(rwx)={}{}{}",
            u8::from(ept_readable),
            u8::from(ept_writable),
            u8::from(ept_executable),
            u8::from(read_access),
            u8::from(write_access),
            u8::from(execute_access)
        );
        return false;
    };

    let (pfn_after, r_after, w_after, x_after) = entry.access_summary();
    invept_single_context(ept.eptp());

    crate::hv_dbg!(
        "ept_hook violation: kind={handled} vcpu={vcpu_id} gpa={page_base:#x} qual={qualification:#x} guest={guest_phys_addr:#x}"
    );
    crate::hv_dbg!(
        "ept_hook violation: pte pfn={pfn_before:#x} rwx={}{}{} -> pfn={pfn_after:#x} rwx={}{}{}",
        u8::from(r_before),
        u8::from(w_before),
        u8::from(x_before),
        u8::from(r_after),
        u8::from(w_after),
        u8::from(x_after)
    );

    true
}

/// Restores the execute-only hook view after a temporary data-access window.
pub(crate) fn handle_mtf(vcpu_id: usize) -> bool {
    let Some(page_base) = take_mtf_pending(vcpu_id) else {
        return false;
    };

    let mut ept = super::guest::ept_state().lock();
    let hook = HOOKS.lock().find(page_base);
    let Some(hook) = hook else {
        crate::hv_dbg!("ept_hook mtf: hook missing vcpu={vcpu_id} gpa={page_base:#x}");
        super::guest::set_monitor_trap_flag(false);
        return false;
    };

    let Ok(entry) = ept.pml1_entry_mut(page_base) else {
        crate::hv_dbg!("ept_hook mtf: pml1 lookup failed vcpu={vcpu_id} gpa={page_base:#x}");
        super::guest::set_monitor_trap_flag(false);
        return false;
    };

    entry.restore_pte(hook.installed_pte);
    invept_single_context(ept.eptp());
    super::guest::set_monitor_trap_flag(false);
    crate::hv_dbg!("ept_hook mtf: restored installed view vcpu={vcpu_id} gpa={page_base:#x}");
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
