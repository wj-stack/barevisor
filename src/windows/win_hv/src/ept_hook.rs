//! EPT Hook2 install helpers for the Windows driver.

use core::mem::size_of;

use hv::platform_ops::PlatformOps;
use shared_contract::{
    EPT_HOOK2_ERR_ALLOC, EPT_HOOK2_ERR_CR3, EPT_HOOK2_ERR_DISASM, EPT_HOOK2_ERR_GPA_RANGE,
    EPT_HOOK2_ERR_HYPERVISOR, EPT_HOOK2_ERR_INVALID, EPT_HOOK2_ERR_NOT_FOUND,
    EPT_HOOK2_ERR_PAGE_BOUNDARY, EPT_HOOK2_ERR_TRANSLATE, EptHook2Response, EptUnhookRequest,
};
use spin::Mutex;
use wdk_sys::{
    POOL_FLAG_NON_PAGED, POOL_FLAG_NON_PAGED_EXECUTE,
    ntddk::{ExAllocatePool2, ExFreePoolWithTag},
};

use crate::hook_log::ept_hook_err_name;
use crate::ops::WindowsOps;
use crate::paging::{cr3_switch_failure, gpa_to_hpa, gva_to_gpa_cr3_switch, read_hpa};

const PAGE_SIZE: usize = 4096;
const HOOK_JUMP_LEN: usize = 12;
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
    syscall_number: u32,
    target_gva: u64,
    hook_gva: u64,
) -> EptHook2Response {
    if target_gva == 0 || hook_gva == 0 {
        return fail_logged(EPT_HOOK2_ERR_INVALID, "bad_target_or_hook");
    }
    let cr3 = if process_id != 0 {
        match crate::process::get_kernel_cr3(process_id) {
            Ok(cr3) => cr3,
            Err(_) => return fail_logged(EPT_HOOK2_ERR_CR3, "pid_cr3"),
        }
    } else {
        crate::process::read_cr3()
    };
    let page_gva = target_gva & !(PAGE_SIZE as u64 - 1);
    let page_offset = (target_gva & (PAGE_SIZE as u64 - 1)) as usize;
    if page_offset + HOOK_JUMP_LEN > PAGE_SIZE {
        return fail_logged(EPT_HOOK2_ERR_PAGE_BOUNDARY, "hook_jump_oob");
    }

    let gpa_page_base = match gva_to_gpa_cr3_switch(cr3, page_gva) {
        Ok(gpa) => gpa & !(PAGE_SIZE as u64 - 1),
        Err(status) => {
            let _ = cr3_switch_failure(status);
            return fail_logged(EPT_HOOK2_ERR_TRANSLATE, "gva_to_gpa");
        }
    };
    if gpa_page_base >= SIZE_512_GB {
        return fail_logged(EPT_HOOK2_ERR_GPA_RANGE, "gpa_limit");
    }

    let hpa = gpa_to_hpa(gpa_page_base);

    let mut page = [0u8; PAGE_SIZE];
    if read_hpa(hpa, page.as_mut_ptr(), PAGE_SIZE).is_err() {
        return fail_logged(EPT_HOOK2_ERR_TRANSLATE, "read_hpa");
    }

    let hook_plan = match plan_hook(&page, page_offset, syscall_number) {
        Some(plan) => plan,
        None => return fail_logged(EPT_HOOK2_ERR_DISASM, "plan_hook"),
    };
    let patched_len = hook_plan.patched_len;
    if page_offset + patched_len > PAGE_SIZE {
        return fail_logged(EPT_HOOK2_ERR_PAGE_BOUNDARY, "patched_len_oob");
    }
    let fake_page = match alloc_page() {
        Some(ptr) => ptr,
        None => return fail_logged(EPT_HOOK2_ERR_ALLOC, "fake_page"),
    };
    let trampoline = match alloc_executable_page() {
        Some(ptr) => ptr,
        None => {
            unsafe { free_page(fake_page) };
            return fail_logged(EPT_HOOK2_ERR_ALLOC, "trampoline_page");
        }
    };

    unsafe {
        core::ptr::copy_nonoverlapping(page.as_ptr(), fake_page, PAGE_SIZE);
        core::ptr::write_bytes(fake_page.add(page_offset), 0x90, patched_len);
        write_absolute_jump(
            core::slice::from_raw_parts_mut(fake_page.add(page_offset), HOOK_JUMP_LEN),
            hook_gva,
        );
        let original_bytes = &page[page_offset..page_offset + patched_len];
        let resume_gva = target_gva + patched_len as u64;
        write_resume_trampoline(trampoline, original_bytes, resume_gva);
    }

    let fake_hpa = WindowsOps.pa(fake_page.cast());
    let (status, _, _, _) = hv::hypercall::issue(
        hv::hypercall::HV_HYPERCALL_INSTALL_EPT_HOOK2,
        gpa_page_base,
        fake_hpa,
        0,
        0,
    );
    if status != hv::hypercall::HV_HYPERCALL_SUCCESS {
        unsafe {
            free_page(fake_page);
            free_page(trampoline);
        }
        return fail_logged(EPT_HOOK2_ERR_HYPERVISOR, "hypercall_install");
    }

    HOOK_ALLOCS.lock().push(HookAllocation {
        gpa_page_base,
        fake_page: fake_page as usize,
        trampoline: trampoline as usize,
    });

    EptHook2Response {
        success: 1,
        error_code: 0,
        patched_len: patched_len.min(u8::MAX as usize) as u8,
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

fn fail_logged(error_code: u8, step: &str) -> EptHook2Response {
    crate::eprintln!(
        "ept_hook install failed at {step}: err={error_code} ({})",
        ept_hook_err_name(error_code)
    );
    fail(error_code)
}

fn fail(error_code: u8) -> EptHook2Response {
    EptHook2Response {
        success: 0,
        error_code,
        ..EptHook2Response::default()
    }
}

struct HookPlan {
    patched_len: usize,
    syscall_number: u32,
}

/// Plans fake-page overwrite length for `page[offset..]`.
fn plan_hook(page: &[u8], offset: usize, syscall_number: u32) -> Option<HookPlan> {
    let patched_len = crate::x86_insn::patch_len_at_least(page, offset, HOOK_JUMP_LEN)?;

    if syscall_number != 0 {
        return Some(HookPlan {
            patched_len,
            syscall_number,
        });
    }

    if let Some(stub) = parse_syscall_stub(page, offset) {
        let stub_len = core::cmp::max(stub.stub_len, patched_len);
        return Some(HookPlan {
            patched_len: stub_len,
            syscall_number: stub.syscall_number,
        });
    }

    if let Some(stub) = scan_syscall_stub(page, offset) {
        return Some(HookPlan {
            patched_len,
            syscall_number: stub.syscall_number,
        });
    }

    None
}

struct ScannedSyscallStub {
    offset: usize,
    syscall_number: u32,
}

/// Scans `page[offset..]` for an `Nt*` syscall stub pattern.
fn scan_syscall_stub(page: &[u8], offset: usize) -> Option<ScannedSyscallStub> {
    const SCAN_LIMIT: usize = 256;
    let end = core::cmp::min(page.len(), offset.saturating_add(SCAN_LIMIT));
    let mut scan_offset = offset;
    while scan_offset < end {
        if let Some(stub) = parse_syscall_stub(page, scan_offset) {
            return Some(ScannedSyscallStub {
                offset: scan_offset.saturating_sub(offset),
                syscall_number: stub.syscall_number,
            });
        }
        scan_offset += 1;
    }
    None
}

struct ParsedSyscallStub {
    stub_len: usize,
    syscall_number: u32,
}

/// Recognizes ntoskrnl `Nt*` stubs: `mov r10, rcx; mov eax, imm32; ...; syscall; ret`.
fn parse_syscall_stub(page: &[u8], offset: usize) -> Option<ParsedSyscallStub> {
    let bytes = page.get(offset..)?;
    if bytes.len() < 11 {
        return None;
    }
    if bytes[0..3] != [0x4C, 0x8B, 0xD1] || bytes[3] != 0xB8 {
        return None;
    }

    let syscall_number = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    for index in 8..bytes.len().saturating_sub(2) {
        if bytes[index] == 0x0F && bytes[index + 1] == 0x05 && bytes.get(index + 2) == Some(&0xC3)
        {
            return Some(ParsedSyscallStub {
                stub_len: index + 3,
                syscall_number,
            });
        }
    }
    None
}

/// Trampoline: saved original bytes at the hook site, then branch to `resume_gva`.
///
/// `resume_gva` is `target_gva + patched_len`. Execution continues on the hooked
/// page via the fake EPT view (full page copy), not by re-issuing `syscall`.
unsafe fn write_resume_trampoline(
    trampoline: *mut u8,
    original: &[u8],
    resume_gva: u64,
) -> usize {
    unsafe {
        let len = original.len();
        core::ptr::copy_nonoverlapping(original.as_ptr(), trampoline, len);
        write_absolute_branch(
            core::slice::from_raw_parts_mut(trampoline.add(len), BRANCH_LEN),
            resume_gva,
        );
        len + BRANCH_LEN
    }
}

const BRANCH_LEN: usize = 12;

/// `mov rax, imm64; jmp rax` — position-independent branch to `target`.
fn write_absolute_branch(buffer: &mut [u8], target: u64) {
    assert!(buffer.len() >= BRANCH_LEN);
    buffer[0] = 0x48;
    buffer[1] = 0xB8;
    buffer[2..10].copy_from_slice(&target.to_le_bytes());
    buffer[10] = 0xFF;
    buffer[11] = 0xE0;
}

/// TinyVT: `mov rax, imm64; push rax; ret` — no RIP-relative memory read on the fake page.
fn write_absolute_jump(buffer: &mut [u8], target: u64) {
    assert!(buffer.len() >= HOOK_JUMP_LEN);
    buffer[0] = 0x48;
    buffer[1] = 0xB8;
    buffer[2..10].copy_from_slice(&target.to_le_bytes());
    buffer[10] = 0x50;
    buffer[11] = 0xC3;
}

fn alloc_page() -> Option<*mut u8> {
    let ptr = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE as _, POOL_TAG) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr.cast())
    }
}

fn alloc_executable_page() -> Option<*mut u8> {
    let ptr = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE as _, POOL_TAG) };
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

const _: () = assert!(size_of::<EptHook2Response>() == 24);
