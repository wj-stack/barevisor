use core::ptr::addr_of;

use alloc::boxed::Box;
use alloc::vec::Vec;
use x86::bits64::paging::{
    BASE_PAGE_SHIFT, BASE_PAGE_SIZE, HUGE_PAGE_SIZE, LARGE_PAGE_SIZE, PML4_SLOT_SIZE,
};

use crate::{hypervisor::intel::mtrr::MemoryType, hypervisor::platform_ops, hypervisor::support::zeroed_box};

use super::mtrr::Mtrr;

/// Identity-mapped EPT state with optional runtime 2 MB → 4 KB splits.
pub(crate) struct EptState {
    pub tables: Box<Epts>,
    dynamic_pts: Vec<Box<EptPageTable>>,
}

impl EptState {
    pub(crate) fn new() -> Self {
        let mut tables = zeroed_box::<Epts>();
        tables.build_identity();
        Self {
            tables,
            dynamic_pts: Vec::new(),
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

        let base_pa = pde.pfn() << 12;
        let memory_type = pde.memory_type();
        let readable = pde.readable();
        let writable = pde.writable();
        let executable = pde.executable();

        let mut new_pt = EptPageTable::zeroed();
        for (i, pte) in new_pt.entries.iter_mut().enumerate() {
            let page_pa = base_pa + (i as u64) * BASE_PAGE_SIZE as u64;
            pte.set_readable(readable);
            pte.set_writable(writable);
            pte.set_executable(executable);
            pte.set_memory_type(memory_type);
            pte.set_pfn(page_pa >> BASE_PAGE_SHIFT);
        }

        let pt_pa = platform_ops::get().pa(addr_of!(new_pt) as *const _);
        self.dynamic_pts.push(Box::new(new_pt));

        pde.set_large(false);
        pde.set_memory_type(memory_type);
        pde.set_readable(readable);
        pde.set_writable(writable);
        pde.set_executable(executable);
        pde.set_pfn(pt_pa >> BASE_PAGE_SHIFT);
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

        for pt in &mut self.dynamic_pts {
            if platform_ops::get().pa(addr_of!(*pt) as *const _) == pt_pa {
                return Ok(&mut pt.entries[pt_index]);
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
    pub(crate) fn as_execute_only_fake(original: Self, fake_page_hpa: u64) -> Self {
        let mut entry = original;
        entry.set_readable(false);
        entry.set_writable(false);
        entry.set_executable(true);
        entry.set_pfn(fake_page_hpa >> BASE_PAGE_SHIFT);
        entry
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

impl EptPageTable {
    fn zeroed() -> Self {
        Self {
            entries: [EptEntry::default(); 512],
        }
    }
}
