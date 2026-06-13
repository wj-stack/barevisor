use core::ptr::addr_of;
use core::sync::atomic::Ordering;

use alloc::boxed::Box;
use x86::bits64::paging::{
    BASE_PAGE_SHIFT, BASE_PAGE_SIZE, HUGE_PAGE_SIZE, LARGE_PAGE_SIZE, PML4_SLOT_SIZE,
};

use crate::{hypervisor::intel::mtrr::MemoryType, hypervisor::platform_ops, hypervisor::support::zeroed_box};

use super::mtrr::Mtrr;

/// Maximum 2 MB → 4 KB splits (runtime hooks + MTRR-crossing regions at init).
pub(crate) const MAX_EPT_DYNAMIC_SPLITS: usize = 32;

/// Identity-mapped EPT state with pre-allocated runtime 2 MB → 4 KB splits.
pub(crate) struct EptState {
    pub tables: Box<Epts>,
    /// Pre-allocated 4 KB page tables (HyperDbg `VMM_EPT_DYNAMIC_SPLIT.PML1` pool).
    /// Heap-backed via `zeroed_box` so `EptState::new` does not touch the ~64 KiB host stack.
    split_pages: Box<[EptPageTable; MAX_EPT_DYNAMIC_SPLITS]>,
    split_pde_keys: [Option<(usize, usize)>; MAX_EPT_DYNAMIC_SPLITS],
    free_splits: [bool; MAX_EPT_DYNAMIC_SPLITS],
}

impl EptState {
    pub(crate) fn new() -> Self {
        let mut tables = zeroed_box::<Epts>();
        tables.build_identity();
        let mut state = Self {
            tables,
            split_pages: zeroed_box(),
            split_pde_keys: [None; MAX_EPT_DYNAMIC_SPLITS],
            free_splits: [true; MAX_EPT_DYNAMIC_SPLITS],
        };
        state.pre_split_mtrr_crossing_regions();
        state
    }

    /// Splits 2 MB regions that straddle MTRR boundaries at hypervisor init.
    ///
    /// Identity map uses 2 MB large pages where valid; Intel requires 4 KB leaf
    /// entries with per-page memory types when a 2 MB window crosses an MTRR.
    /// Runtime split during IOCTL hook install races other vCPUs and causes
    /// EPT misconfiguration storms (e.g. gpa=0x2ed7000).
    fn pre_split_mtrr_crossing_regions(&mut self) {
        let mtrr = Mtrr::new();
        let mut pa = LARGE_PAGE_SIZE as u64;
        let end = PML4_SLOT_SIZE as u64;

        while pa < end {
            if !mtrr.region_valid_for_large_page(pa) {
                let _ = self.split_2mb_to_4kb(pa);
            }
            pa += LARGE_PAGE_SIZE as u64;
        }
    }

    pub(crate) fn eptp(&self) -> EptPointer {
        self.tables.eptp()
    }

    /// Splits the 2 MB EPT mapping covering `gpa` into 512 × 4 KB entries.
    pub(crate) fn split_2mb_to_4kb(&mut self, gpa: u64) -> Result<(), EptError> {
        const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;
        if gpa >= SIZE_512_GB {
            return Err(EptError::OutOfRange);
        }

        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pde = &mut self.tables.pd[pdpt_index].entries[pd_index];

        if !pde.readable() && !pde.writable() && !pde.executable() {
            return Err(EptError::InvalidAddress);
        }

        if !pde.large() {
            return Ok(());
        }

        let split_index = self
            .free_splits
            .iter()
            .position(|free| *free)
            .ok_or(EptError::NoSplitSlots)?;

        let readable = pde.readable();
        let writable = pde.writable();
        let executable = pde.executable();

        // Identity-map each 4 KB slot in this 2 MB region. Do not use pfn_2mb + i:
        // large-page PFN encoding is not linear in the low 9 bits.
        let region_base = gpa & !(LARGE_PAGE_SIZE as u64 - 1);
        let mtrr = Mtrr::new();
        let page_table = &mut self.split_pages[split_index];
        for (i, pte) in page_table.entries.iter_mut().enumerate() {
            let page_pa = region_base + (i as u64) * BASE_PAGE_SIZE as u64;
            let page_pfn = page_pa >> BASE_PAGE_SHIFT;
            let page_memory_type =
                safe_leaf_memory_type(mtrr.ept_memory_type_for_page(page_pa) as u64);
            pte.set_readable(readable);
            pte.set_writable(writable);
            pte.set_executable(executable);
            pte.set_large(false);
            pte.set_memory_type(page_memory_type);
            pte.set_pfn(page_pfn);
        }
        self.split_pde_keys[split_index] = Some((pdpt_index, pd_index));
        self.free_splits[split_index] = false;

        let pt_pa = platform_ops::get().pa(addr_of!(*page_table) as *const _);

        // Publish PTE writes before switching the PDE away from the 2 MB mapping.
        core::sync::atomic::fence(Ordering::SeqCst);

        pde.set_large(false);
        // HyperDbg leaves the non-leaf memory type as UC (0) when pointing at a PT.
        pde.set_memory_type(MemoryType::Uncachable as u64);
        pde.set_readable(true);
        pde.set_writable(true);
        pde.set_executable(true);
        pde.set_pfn(pt_pa >> BASE_PAGE_SHIFT);
        invept_single_context(self.eptp());
        Ok(())
    }

    pub(crate) fn pml1_entry_mut(&mut self, gpa: u64) -> Result<&mut EptEntry, EptError> {
        const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;
        if gpa >= SIZE_512_GB {
            return Err(EptError::OutOfRange);
        }

        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pt_index = ((gpa >> 12) & 0x1FF) as usize;

        let pde = &self.tables.pd[pdpt_index].entries[pd_index];
        if pde.large() {
            return Err(EptError::NotSplit);
        }

        let pt_pa = pde.pfn() << 12;
        let static_pt_pa = platform_ops::get().pa(addr_of!(self.tables.pt) as *const _);
        if pt_pa == static_pt_pa {
            return Ok(&mut self.tables.pt.entries[pt_index]);
        }

        for (index, key) in self.split_pde_keys.iter().enumerate() {
            if *key == Some((pdpt_index, pd_index)) {
                return Ok(&mut self.split_pages[index].entries[pt_index]);
            }
        }

        Err(EptError::InvalidAddress)
    }

    pub(crate) fn pde_entry(&self, gpa: u64) -> Result<EptEntry, EptError> {
        const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;
        if gpa >= SIZE_512_GB {
            return Err(EptError::OutOfRange);
        }
        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        Ok(self.tables.pd[pdpt_index].entries[pd_index])
    }

    pub(crate) fn pml1_entry(&self, gpa: u64) -> Result<EptEntry, EptError> {
        const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;
        if gpa >= SIZE_512_GB {
            return Err(EptError::OutOfRange);
        }

        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pt_index = ((gpa >> 12) & 0x1FF) as usize;

        let pde = &self.tables.pd[pdpt_index].entries[pd_index];
        if pde.large() {
            return Err(EptError::NotSplit);
        }

        let pt_pa = pde.pfn() << 12;
        let static_pt_pa = platform_ops::get().pa(addr_of!(self.tables.pt) as *const _);
        if pt_pa == static_pt_pa {
            return Ok(self.tables.pt.entries[pt_index]);
        }

        for (index, key) in self.split_pde_keys.iter().enumerate() {
            if *key == Some((pdpt_index, pd_index)) {
                return Ok(self.split_pages[index].entries[pt_index]);
            }
        }

        Err(EptError::InvalidAddress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EptError {
    OutOfRange,
    InvalidAddress,
    NotSplit,
    NoSplitSlots,
}

#[repr(C, align(4096))]
pub(crate) struct Epts {
    pml4: Pml4,
    pdpt: [Pdpt; 512],
    pd: [Pd; 512],
    pt: EptPageTable,
}

impl Epts {
    pub(crate) fn build_identity(&mut self) {
        let mtrr = Mtrr::new();
        log::trace!("{mtrr:#x?}");
        log::trace!("Initializing EPTs");

        let ops = platform_ops::get();

        let mut pa = 0u64;

        self.pml4.entries[0].set_readable(true);
        self.pml4.entries[0].set_writable(true);
        self.pml4.entries[0].set_executable(true);
        self.pml4.entries[0].set_pfn(ops.pa(addr_of!(self.pdpt[0]) as _) >> BASE_PAGE_SHIFT);
        for (i, pdpte) in self.pdpt[0].entries.iter_mut().enumerate() {
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(ops.pa(addr_of!(self.pd[i]) as _) >> BASE_PAGE_SHIFT);

            for pde in &mut self.pd[i].entries {
                if pa == 0 {
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_pfn(ops.pa(addr_of!(self.pt) as _) >> BASE_PAGE_SHIFT);

                    for pte in &mut self.pt.entries {
                        let memory_type = mtrr
                            .find(pa..pa + BASE_PAGE_SIZE as u64)
                            .unwrap_or_else(|| panic!("Could not resolve a memory type for {pa:#x?}"));
                        pte.set_readable(true);
                        pte.set_writable(true);
                        pte.set_executable(true);
                        pte.set_memory_type(memory_type as u64);
                        pte.set_pfn(pa >> BASE_PAGE_SHIFT);
                        pa += BASE_PAGE_SIZE as u64;
                    }
                } else {
                    let memory_type = mtrr
                        .find(pa..pa + LARGE_PAGE_SIZE as u64)
                        .unwrap_or_else(|| {
                            log::warn!("Could not resolve a memory type for {pa:#x?}");
                            MemoryType::Uncachable
                        });
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_memory_type(memory_type as u64);
                    pde.set_large(true);
                    pde.set_pfn(pa >> BASE_PAGE_SHIFT);
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }

        assert!(pa == PML4_SLOT_SIZE as u64);
        for (pml4_index, pml4e) in self.pml4.entries.iter_mut().enumerate().skip(1) {
            pml4e.set_readable(true);
            pml4e.set_writable(true);
            pml4e.set_executable(true);
            pml4e.set_pfn(ops.pa(addr_of!(self.pdpt[pml4_index]) as _) >> BASE_PAGE_SHIFT);

            for pdpte in &mut self.pdpt[pml4_index].entries {
                let memory_type = mtrr
                    .find(pa..pa + PML4_SLOT_SIZE as u64)
                    .unwrap_or_else(|| panic!("Could not resolve a memory type for {pa:#x?}"));
                pdpte.set_readable(true);
                pdpte.set_writable(true);
                pdpte.set_executable(true);
                pdpte.set_memory_type(memory_type as u64);
                pdpte.set_large(true);
                pdpte.set_pfn(pa >> BASE_PAGE_SHIFT);
                pa += HUGE_PAGE_SIZE as u64;
            }
        }
    }

    pub(crate) fn eptp(&self) -> EptPointer {
        let mut eptp = EptPointer::default();
        let ept_pml4_pa = platform_ops::get().pa(addr_of!(*self) as *const _);
        eptp.set_pfn(ept_pml4_pa >> BASE_PAGE_SHIFT);
        eptp.set_memory_type(MemoryType::WriteBack as _);
        eptp.set_page_levels_minus_one(3);
        eptp
    }
}

/// Invalidates cached EPT-derived guest physical address translations for this EPTP.
///
/// Single-context INVEPT invalidates mappings on all logical processors that use
/// this EPT pointer (Intel SDM). Do not call `run_on_all_processors` from VMX
/// root: affinity migration corrupts per-CPU VMCS state.
pub(crate) fn invept_single_context(eptp: EptPointer) {
    let descriptor = [eptp.0, 0u64];
    unsafe {
        // MSVC/LLVM integrated assembler uses Intel syntax but rejects `oword ptr`.
        #[cfg(target_env = "msvc")]
        core::arch::asm!(
            "invept rcx, [{desc}]",
            desc = in(reg) descriptor.as_ptr(),
            in("rcx") 1u64,
            options(nostack),
        );

        #[cfg(not(target_env = "msvc"))]
        core::arch::asm!(
            "invept ({desc}), {ty}",
            desc = in(reg) descriptor.as_ptr(),
            ty = in(reg) 1u64,
            options(nostack),
        );
    }
}

bitfield::bitfield! {
    #[derive(Clone, Copy, Default)]
    pub struct EptPointer(u64);
    impl Debug;
    memory_type, set_memory_type: 2, 0;
    page_levels_minus_one, set_page_levels_minus_one: 5, 3;
    enable_access_dirty, set_enable_access_dirty: 6;
    enable_sss, set_enable_sss: 7;
    pfn, set_pfn: 51, 12;
}

bitfield::bitfield! {
    #[derive(Clone, Copy, Default)]
    pub struct EptEntry(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    memory_type, set_memory_type: 5, 3;
    large, set_large: 7;
    pfn, set_pfn: 51, 12;
}

impl EptEntry {
    pub(crate) fn page_pfn(self) -> u64 {
        self.pfn()
    }

    pub(crate) fn is_executable(self) -> bool {
        self.executable()
    }

    pub(crate) fn access_summary(self) -> (u64, bool, bool, bool) {
        (
            self.page_pfn(),
            self.readable(),
            self.writable(),
            self.executable(),
        )
    }

    pub(crate) fn is_large(self) -> bool {
        self.large()
    }

    pub(crate) fn memory_type_value(self) -> u64 {
        self.memory_type()
    }

    pub(crate) fn raw_value(self) -> u64 {
        self.0
    }

    /// Install: keep the original PFN for data, block instruction fetch.
    pub(crate) fn hook_install_no_execute(&mut self) {
        self.set_executable(false);
        self.set_large(false);
    }

    pub(crate) fn restore_pte(&mut self, pte: EptEntry) {
        *self = pte;
    }

    /// Hook view: map the fake page execute-only (R=0, W=0, X=1).
    /// Falls back to RX (R=1, W=0, X=1) when execute-only is unsupported.
    pub(crate) fn hook_install_execute_view(&mut self, exec_pfn: u64, execute_only: bool) {
        if execute_only {
            self.set_readable(false);
            self.set_writable(false);
        } else {
            self.set_readable(true);
            self.set_writable(false);
        }
        self.set_executable(true);
        self.set_large(false);
        self.set_pfn(exec_pfn);
    }
}

#[derive(Debug, Clone, Copy)]
struct Pml4 {
    entries: [EptEntry; 512],
}

#[derive(Debug, Clone, Copy)]
struct Pdpt {
    entries: [EptEntry; 512],
}

#[derive(Debug, Clone, Copy)]
struct Pd {
    entries: [EptEntry; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct EptPageTable {
    entries: [EptEntry; 512],
}

/// Leaf PTE memory type safe for R=1/W=1 mappings.
fn safe_leaf_memory_type(memory_type: u64) -> u64 {
    // Intel SDM: EPT memory type WP (5) with writable=1 is a misconfiguration.
    if memory_type == MemoryType::WriteProtected as u64 {
        MemoryType::WriteBack as u64
    } else {
        memory_type
    }
}
