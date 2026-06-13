//! Guest virtual/physical address translation for the Windows driver.

use core::ffi::c_void;

use wdk_sys::NTSTATUS;

const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_LARGE: u64 = 1 << 7;
const PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[repr(C)]
union PhysicalAddress {
    quad_part: i64,
}

unsafe extern "system" {
    fn MmGetVirtualForPhysical(physical_address: PhysicalAddress) -> *mut c_void;
}

/// Translates `gva` through the guest page tables rooted at `cr3`.
pub(crate) fn gva_to_gpa(cr3: u64, gva: u64) -> Result<u64, NTSTATUS> {
    if !is_canonical_va(gva) {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }

    let root = cr3 & PAGE_MASK;
    if root == 0 {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }

    let pml4_index = ((gva >> 39) & 0x1FF) as usize;
    let pdpt_index = ((gva >> 30) & 0x1FF) as usize;
    let pd_index = ((gva >> 21) & 0x1FF) as usize;
    let pt_index = ((gva >> 12) & 0x1FF) as usize;

    let pml4e = read_phys_u64(root + pml4_index as u64 * 8)?;
    if !entry_present(pml4e) {
        return Err(wdk_sys::STATUS_NOT_FOUND);
    }

    let pdpt_pa = entry_pfn(pml4e);
    let pdpte = read_phys_u64(pdpt_pa + pdpt_index as u64 * 8)?;
    if !entry_present(pdpte) {
        return Err(wdk_sys::STATUS_NOT_FOUND);
    }
    if entry_large(pdpte) {
        return Ok(entry_pfn(pdpte) + (gva & 0x3FFF_FFFF));
    }

    let pd_pa = entry_pfn(pdpte);
    let pde = read_phys_u64(pd_pa + pd_index as u64 * 8)?;
    if !entry_present(pde) {
        return Err(wdk_sys::STATUS_NOT_FOUND);
    }
    if entry_large(pde) {
        return Ok(entry_pfn(pde) + (gva & 0x1F_FFFF));
    }

    let pt_pa = entry_pfn(pde);
    let pte = read_phys_u64(pt_pa + pt_index as u64 * 8)?;
    if !entry_present(pte) {
        return Err(wdk_sys::STATUS_NOT_FOUND);
    }

    Ok(entry_pfn(pte) + (gva & 0xFFF))
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

    let mut remaining = size;
    let mut written = 0usize;
    while remaining > 0 {
        let current = hpa + written as u64;
        let page_offset = (current & 0xFFF) as usize;
        let chunk = core::cmp::min(remaining, 0x1000 - page_offset);

        let va = map_phys(current & PAGE_MASK)?;
        let src = unsafe { va.cast::<u8>().add(page_offset) };
        unsafe {
            core::ptr::copy_nonoverlapping(src, buffer.add(written), chunk);
        }

        written += chunk;
        remaining -= chunk;
    }

    Ok(())
}

fn read_phys_u64(pa: u64) -> Result<u64, NTSTATUS> {
    let va = map_phys(pa & PAGE_MASK)?;
    let offset = (pa & 0xFFF) as usize;
    Ok(unsafe { va.cast::<u8>().add(offset).cast::<u64>().read_unaligned() })
}

fn map_phys(page_pa: u64) -> Result<*mut c_void, NTSTATUS> {
    let physical = PhysicalAddress {
        quad_part: page_pa as i64,
    };
    let va = unsafe { MmGetVirtualForPhysical(physical) };
    if va.is_null() {
        return Err(wdk_sys::STATUS_UNSUCCESSFUL);
    }
    Ok(va)
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
