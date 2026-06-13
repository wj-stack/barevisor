//! EPT Hook2 install helpers for the Windows driver.

use core::mem::size_of;

use hv::platform_ops::PlatformOps;
use iced_x86::{Decoder, DecoderOptions};
use shared_contract::{
    EPT_HOOK2_ERR_ALLOC, EPT_HOOK2_ERR_CR3, EPT_HOOK2_ERR_DISASM, EPT_HOOK2_ERR_GPA_RANGE,
    EPT_HOOK2_ERR_HYPERVISOR, EPT_HOOK2_ERR_INVALID, EPT_HOOK2_ERR_NO_EXEC_ONLY,
    EPT_HOOK2_ERR_NOT_FOUND, EPT_HOOK2_ERR_PAGE_BOUNDARY, EPT_HOOK2_ERR_TRANSLATE,
    EptHook2Response, EptUnhookRequest,
};
use spin::Mutex;
use wdk_sys::{
    POOL_FLAG_NON_PAGED,
    ntddk::{ExAllocatePool2, ExFreePoolWithTag},
};

use crate::ops::WindowsOps;
use crate::paging::{cr3_switch_failure, gpa_to_hpa, gva_to_gpa_cr3_switch, read_hpa};

const PAGE_SIZE: usize = 4096;
const HOOK_JUMP_LEN: usize = 19;
const TRAMPOLINE_JUMP_LEN: usize = 14;
const MIN_PATCH_LEN: usize = 19;
const SIZE_512_GB: u64 = 512 * 1024 * 1024 * 1024;
const POOL_TAG: u32 = u32::from_ne_bytes(*b"EptH");

struct HookAllocation {
    gpa_page_base: u64,
    fake_page: usize,
    trampoline: usize,
}

static HOOK_ALLOCS: Mutex<alloc::vec::Vec<HookAllocation>> = Mutex::new(alloc::vec::Vec::new());

/// Installs an EPT Hook2 detour and returns the IOCTL response payload.
pub(crate) fn install(
    process_id: u32,
    target_gva: u64,
    hook_gva: u64,
) -> EptHook2Response {
    if target_gva == 0 || hook_gva == 0 {
        return fail(EPT_HOOK2_ERR_INVALID);
    }
    if !ept_execute_only_supported() {
        return fail(EPT_HOOK2_ERR_NO_EXEC_ONLY);
    }

    let cr3 = if process_id != 0 {
        match crate::process::get_kernel_cr3(process_id) {
            Ok(cr3) => cr3,
            Err(_) => return fail(EPT_HOOK2_ERR_CR3),
        }
    } else {
        crate::process::read_cr3()
    };

    let page_gva = target_gva & !(PAGE_SIZE as u64 - 1);
    let page_offset = (target_gva & (PAGE_SIZE as u64 - 1)) as usize;
    if page_offset + HOOK_JUMP_LEN > PAGE_SIZE {
        return fail(EPT_HOOK2_ERR_PAGE_BOUNDARY);
    }

    let gpa_page_base = match gva_to_gpa_cr3_switch(cr3, page_gva) {
        Ok(gpa) => gpa & !(PAGE_SIZE as u64 - 1),
        Err(status) => {
            let _ = cr3_switch_failure(status);
            return fail(EPT_HOOK2_ERR_TRANSLATE);
        }
    };
    if gpa_page_base >= SIZE_512_GB {
        return fail(EPT_HOOK2_ERR_GPA_RANGE);
    }

    let hpa = gpa_to_hpa(gpa_page_base);
    let mut page = [0u8; PAGE_SIZE];
    if read_hpa(hpa, page.as_mut_ptr(), PAGE_SIZE).is_err() {
        return fail(EPT_HOOK2_ERR_TRANSLATE);
    }

    let patched_len = match compute_patch_length(&page, page_offset) {
        Some(len) => len,
        None => return fail(EPT_HOOK2_ERR_DISASM),
    };

    let fake_page = match alloc_page() {
        Some(ptr) => ptr,
        None => return fail(EPT_HOOK2_ERR_ALLOC),
    };
    let trampoline = match alloc_page() {
        Some(ptr) => ptr,
        None => {
            unsafe { free_page(fake_page) };
            return fail(EPT_HOOK2_ERR_ALLOC);
        }
    };

    unsafe {
        core::ptr::copy_nonoverlapping(page.as_ptr(), fake_page, PAGE_SIZE);
        write_absolute_jump(
            core::slice::from_raw_parts_mut(fake_page.add(page_offset), HOOK_JUMP_LEN),
            hook_gva,
        );
        core::ptr::copy_nonoverlapping(
            page.as_ptr().add(page_offset),
            trampoline,
            patched_len,
        );
        write_absolute_jump2(
            core::slice::from_raw_parts_mut(
                trampoline.add(patched_len),
                TRAMPOLINE_JUMP_LEN,
            ),
            target_gva + patched_len as u64,
        );
    }

    let fake_hpa = WindowsOps.pa(fake_page.cast());
    if !hv::hypercall::install_ept_hook2(gpa_page_base, fake_hpa) {
        unsafe {
            free_page(fake_page);
            free_page(trampoline);
        }
        return fail(EPT_HOOK2_ERR_HYPERVISOR);
    }

    HOOK_ALLOCS.lock().push(HookAllocation {
        gpa_page_base,
        fake_page: fake_page as usize,
        trampoline: trampoline as usize,
    });

    EptHook2Response {
        success: 1,
        error_code: 0,
        patched_len: patched_len as u8,
        _padding: 0,
        trampoline_gva: trampoline as u64,
        target_gpa: gpa_page_base,
    }
}

/// Removes a previously installed hook and frees driver allocations.
pub(crate) fn uninstall(request: EptUnhookRequest) -> u8 {
    if request.target_gva == 0 {
        return EPT_HOOK2_ERR_INVALID;
    }

    let cr3 = if request.process_id != 0 {
        match crate::process::get_kernel_cr3(request.process_id) {
            Ok(cr3) => cr3,
            Err(_) => return EPT_HOOK2_ERR_CR3,
        }
    } else {
        crate::process::read_cr3()
    };

    let page_gva = request.target_gva & !(PAGE_SIZE as u64 - 1);
    let gpa_page_base = match gva_to_gpa_cr3_switch(cr3, page_gva) {
        Ok(gpa) => gpa & !(PAGE_SIZE as u64 - 1),
        Err(_) => return EPT_HOOK2_ERR_TRANSLATE,
    };

    if !hv::hypercall::uninstall_ept_hook2(gpa_page_base) {
        return EPT_HOOK2_ERR_HYPERVISOR;
    }

    let mut allocs = HOOK_ALLOCS.lock();
    let Some(index) = allocs
        .iter()
        .position(|entry| entry.gpa_page_base == gpa_page_base)
    else {
        return EPT_HOOK2_ERR_NOT_FOUND;
    };
    let entry = allocs.remove(index);
    unsafe {
        free_page(entry.fake_page as *mut u8);
        free_page(entry.trampoline as *mut u8);
    }
    0
}

/// Frees all hook allocations during driver unload.
pub(crate) fn uninstall_all() {
    let mut allocs = HOOK_ALLOCS.lock();
    for entry in allocs.drain(..) {
        let _ = hv::hypercall::uninstall_ept_hook2(entry.gpa_page_base);
        unsafe {
            free_page(entry.fake_page as *mut u8);
            free_page(entry.trampoline as *mut u8);
        }
    }
}

fn fail(error_code: u8) -> EptHook2Response {
    EptHook2Response {
        success: 0,
        error_code,
        ..EptHook2Response::default()
    }
}

fn compute_patch_length(page: &[u8], offset: usize) -> Option<usize> {
    let mut decoder = Decoder::with_ip(64, &page[offset..], 0, DecoderOptions::NONE);
    let mut total = 0usize;
    while total < MIN_PATCH_LEN {
        if !decoder.can_decode() {
            return None;
        }
        let instruction = decoder.decode();
        let len = instruction.len();
        if len == 0 {
            return None;
        }
        total += len;
    }
    Some(total)
}

fn write_absolute_jump(buffer: &mut [u8], target: u64) {
    assert!(buffer.len() >= HOOK_JUMP_LEN);
    buffer[0] = 0xE8;
    buffer[1..5].copy_from_slice(&0u32.to_le_bytes());
    buffer[5] = 0x68;
    buffer[6..10].copy_from_slice(&(target as u32).to_le_bytes());
    buffer[10] = 0xC7;
    buffer[11] = 0x44;
    buffer[12] = 0x24;
    buffer[13] = 0x04;
    buffer[14..18].copy_from_slice(&((target >> 32) as u32).to_le_bytes());
    buffer[18] = 0xC3;
}

fn write_absolute_jump2(buffer: &mut [u8], target: u64) {
    assert!(buffer.len() >= TRAMPOLINE_JUMP_LEN);
    buffer[0] = 0x68;
    buffer[1..5].copy_from_slice(&(target as u32).to_le_bytes());
    buffer[5] = 0xC7;
    buffer[6] = 0x44;
    buffer[7] = 0x24;
    buffer[8] = 0x04;
    buffer[9..13].copy_from_slice(&((target >> 32) as u32).to_le_bytes());
    buffer[13] = 0xC3;
}

fn alloc_page() -> Option<*mut u8> {
    let ptr = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE as _, POOL_TAG) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr.cast())
    }
}

unsafe fn free_page(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { ExFreePoolWithTag(ptr.cast(), POOL_TAG) };
    }
}

fn ept_execute_only_supported() -> bool {
    const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
    let (low, _high): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") IA32_VMX_EPT_VPID_CAP,
            out("eax") low,
            out("edx") _high,
            options(nomem, nostack, preserves_flags),
        );
    }
    low & 1 != 0
}

const _: () = assert!(size_of::<EptHook2Response>() == 24);
