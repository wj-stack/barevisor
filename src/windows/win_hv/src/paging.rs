//! Guest virtual/physical address translation for the Windows driver.

use core::ffi::c_void;
use core::mem::size_of;

use shared_contract::{
    TRANSLATE_FAIL_INVALID, TRANSLATE_FAIL_MMGPA, TRANSLATE_FAIL_PD, TRANSLATE_FAIL_PML4,
    TRANSLATE_FAIL_PDPT, TRANSLATE_FAIL_PTE,
};
use wdk_sys::{
    NTSTATUS, NT_SUCCESS, PHYSICAL_ADDRESS,
    ntddk::MmGetPhysicalAddress,
};

const PAGE_SIZE: usize = 4096;
/// `MmNonCached` in `MEMORY_CACHING_TYPE`.
const MM_NON_CACHED: u32 = 0;

const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_LARGE: u64 = 1 << 7;
const PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Page size used to resolve the final GPA.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalkLevel {
    Page4K = 4,
    Page2M = 3,
    Page1G = 2,
}

/// Result of a guest page table walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GvaWalk {
    pub pml4e_pa: u64,
    pub pdpe_pa: u64,
    pub pde_pa: u64,
    pub pte_pa: u64,
    pub gpa: u64,
    pub level: WalkLevel,
}

/// Partial walk state returned when translation fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WalkFailure {
    pub status: NTSTATUS,
    pub stage: u8,
    pub pml4e_pa: u64,
    pub pdpe_pa: u64,
    pub pde_pa: u64,
    pub pte_pa: u64,
}

#[repr(C)]
union MmCopyAddress {
    physical_address: i64,
}

const MM_COPY_MEMORY_PHYSICAL: u32 = 0x1;

unsafe extern "system" {
    fn MmCopyMemory(
        target_address: *mut c_void,
        source_address: MmCopyAddress,
        number_of_bytes: usize,
        flags: u32,
        number_of_bytes_transferred: *mut usize,
    ) -> NTSTATUS;
    fn MmMapIoSpace(
        physical_address: PHYSICAL_ADDRESS,
        number_of_bytes: usize,
        cache_type: u32,
    ) -> *mut c_void;
    fn MmUnmapIoSpace(base_address: *mut c_void, number_of_bytes: usize);
}

/// Translates `gva` by switching to `kernel_cr3` and calling `MmGetPhysicalAddress`.
///
/// HyperDbg path 1 (`VirtualAddressToPhysicalAddressByProcessCr3`).
pub(crate) fn gva_to_gpa_cr3_switch(kernel_cr3: u64, gva: u64) -> Result<u64, NTSTATUS> {
    if !is_canonical_va(gva) {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }
    if kernel_cr3 & PAGE_MASK == 0 {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }

    let saved_cr3 = crate::process::read_cr3();
    crate::process::write_cr3(kernel_cr3);
    #[expect(clippy::cast_sign_loss)]
    let gpa = unsafe { MmGetPhysicalAddress(gva as *mut c_void).QuadPart as u64 };
    crate::process::write_cr3(saved_cr3);

    if gpa == 0 {
        return Err(wdk_sys::STATUS_NOT_FOUND);
    }
    Ok(gpa)
}

/// Maps a CR3-switch failure to walk failure metadata for IOCTL responses.
pub(crate) fn cr3_switch_failure(status: NTSTATUS) -> WalkFailure {
    WalkFailure {
        status,
        stage: if status == wdk_sys::STATUS_NOT_FOUND {
            TRANSLATE_FAIL_MMGPA
        } else {
            TRANSLATE_FAIL_INVALID
        },
        ..WalkFailure::default()
    }
}

/// Translates `gva` and returns the full walk details.
pub(crate) fn gva_to_gpa_walk(cr3: u64, gva: u64) -> Result<GvaWalk, WalkFailure> {
    if !is_canonical_va(gva) {
        return Err(WalkFailure {
            status: wdk_sys::STATUS_INVALID_PARAMETER,
            stage: TRANSLATE_FAIL_INVALID,
            ..WalkFailure::default()
        });
    }

    let root = cr3 & PAGE_MASK;
    if root == 0 {
        return Err(WalkFailure {
            status: wdk_sys::STATUS_INVALID_PARAMETER,
            stage: TRANSLATE_FAIL_INVALID,
            ..WalkFailure::default()
        });
    }

    let pml4_index = ((gva >> 39) & 0x1FF) as u64;
    let pdpt_index = ((gva >> 30) & 0x1FF) as u64;
    let pd_index = ((gva >> 21) & 0x1FF) as u64;
    let pt_index = ((gva >> 12) & 0x1FF) as u64;

    let pml4e_pa = root + pml4_index * 8;
    let pml4e = match read_phys_u64(pml4e_pa) {
        Ok(entry) => entry,
        Err(status) => {
            return Err(WalkFailure {
                status,
                stage: TRANSLATE_FAIL_PML4,
                pml4e_pa,
                ..WalkFailure::default()
            });
        }
    };
    if !entry_present(pml4e) {
        return Err(WalkFailure {
            status: wdk_sys::STATUS_NOT_FOUND,
            stage: TRANSLATE_FAIL_PML4,
            pml4e_pa,
            ..WalkFailure::default()
        });
    }

    let pdpt_pa = entry_pfn(pml4e);
    let pdpe_pa = pdpt_pa + pdpt_index * 8;
    let pdpte = match read_phys_u64(pdpe_pa) {
        Ok(entry) => entry,
        Err(status) => {
            return Err(WalkFailure {
                status,
                stage: TRANSLATE_FAIL_PDPT,
                pml4e_pa,
                pdpe_pa,
                ..WalkFailure::default()
            });
        }
    };
    if !entry_present(pdpte) {
        return Err(WalkFailure {
            status: wdk_sys::STATUS_NOT_FOUND,
            stage: TRANSLATE_FAIL_PDPT,
            pml4e_pa,
            pdpe_pa,
            ..WalkFailure::default()
        });
    }
    if entry_large(pdpte) {
        return Ok(GvaWalk {
            pml4e_pa,
            pdpe_pa,
            pde_pa: 0,
            pte_pa: 0,
            gpa: entry_pfn(pdpte) + (gva & 0x3FFF_FFFF),
            level: WalkLevel::Page1G,
        });
    }

    let pd_pa = entry_pfn(pdpte);
    let pde_pa = pd_pa + pd_index * 8;
    let pde = match read_phys_u64(pde_pa) {
        Ok(entry) => entry,
        Err(status) => {
            return Err(WalkFailure {
                status,
                stage: TRANSLATE_FAIL_PD,
                pml4e_pa,
                pdpe_pa,
                pde_pa,
                ..WalkFailure::default()
            });
        }
    };
    if !entry_present(pde) {
        return Err(WalkFailure {
            status: wdk_sys::STATUS_NOT_FOUND,
            stage: TRANSLATE_FAIL_PD,
            pml4e_pa,
            pdpe_pa,
            pde_pa,
            ..WalkFailure::default()
        });
    }
    if entry_large(pde) {
        return Ok(GvaWalk {
            pml4e_pa,
            pdpe_pa,
            pde_pa,
            pte_pa: 0,
            gpa: entry_pfn(pde) + (gva & 0x1F_FFFF),
            level: WalkLevel::Page2M,
        });
    }

    let pt_pa = entry_pfn(pde);
    let pte_pa = pt_pa + pt_index * 8;
    let pte = match read_phys_u64(pte_pa) {
        Ok(entry) => entry,
        Err(status) => {
            return Err(WalkFailure {
                status,
                stage: TRANSLATE_FAIL_PTE,
                pml4e_pa,
                pdpe_pa,
                pde_pa,
                pte_pa,
            });
        }
    };
    if !entry_present(pte) {
        return Err(WalkFailure {
            status: wdk_sys::STATUS_NOT_FOUND,
            stage: TRANSLATE_FAIL_PTE,
            pml4e_pa,
            pdpe_pa,
            pde_pa,
            pte_pa,
        });
    }

    Ok(GvaWalk {
        pml4e_pa,
        pdpe_pa,
        pde_pa,
        pte_pa,
        gpa: entry_pfn(pte) + (gva & 0xFFF),
        level: WalkLevel::Page4K,
    })
}

/// Maps guest physical address to host physical address.
///
/// Barevisor builds identity EPT/NPT, so GPA and HPA are equal.
pub(crate) fn gpa_to_hpa(gpa: u64) -> u64 {
    gpa
}

/// Reads `size` bytes starting at `hpa` into `buffer`.
pub(crate) fn read_hpa(hpa: u64, buffer: *mut u8, size: usize) -> Result<(), NTSTATUS> {
    if buffer.is_null() || size == 0 {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }

    let mut transferred = 0usize;
    let source = MmCopyAddress {
        physical_address: hpa as i64,
    };
    let status = unsafe {
        MmCopyMemory(
            buffer.cast(),
            source,
            size,
            MM_COPY_MEMORY_PHYSICAL,
            &mut transferred,
        )
    };
    if !NT_SUCCESS(status) || transferred != size {
        return Err(if NT_SUCCESS(status) {
            wdk_sys::STATUS_UNSUCCESSFUL
        } else {
            status
        });
    }

    Ok(())
}

/// Writes `size` bytes from `buffer` to host physical address `hpa`.
pub(crate) fn write_hpa(hpa: u64, buffer: *const u8, size: usize) -> Result<(), NTSTATUS> {
    if buffer.is_null() || size == 0 {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }

    let mut remaining = size;
    let mut current_pa = hpa;
    let mut current_buf = buffer;

    while remaining > 0 {
        let page_offset = (current_pa & 0xFFF) as usize;
        let chunk = remaining.min(PAGE_SIZE - page_offset);
        write_hpa_page_chunk(current_pa, unsafe {
            core::slice::from_raw_parts(current_buf, chunk)
        })?;
        remaining -= chunk;
        current_pa += chunk as u64;
        current_buf = unsafe { current_buf.add(chunk) };
    }

    Ok(())
}

fn write_hpa_page_chunk(hpa: u64, data: &[u8]) -> Result<(), NTSTATUS> {
    let page_base = hpa & PAGE_MASK;
    let page_offset = (hpa & 0xFFF) as usize;
    let map_size = ((page_offset + data.len() + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    let physical_address = PHYSICAL_ADDRESS {
        QuadPart: page_base as i64,
    };
    let mapped = unsafe { MmMapIoSpace(physical_address, map_size, MM_NON_CACHED) };
    if mapped.is_null() {
        return Err(wdk_sys::STATUS_UNSUCCESSFUL);
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            mapped.cast::<u8>().add(page_offset),
            data.len(),
        );
        MmUnmapIoSpace(mapped, map_size);
    }

    Ok(())
}

fn read_phys_u64(pa: u64) -> Result<u64, NTSTATUS> {
    let mut value = 0u64;
    read_hpa(pa, (&raw mut value).cast(), size_of::<u64>())?;
    Ok(value)
}

fn entry_present(entry: u64) -> bool {
    entry & PAGE_PRESENT != 0
}

fn entry_large(entry: u64) -> bool {
    entry & PAGE_LARGE != 0
}

fn entry_pfn(entry: u64) -> u64 {
    entry & PAGE_MASK
}

fn is_canonical_va(address: u64) -> bool {
    address <= 0x0000_7FFF_FFFF_FFFF || address >= 0xFFFF_8000_0000_0000
}
