//! EPT Hook2 install helpers for the Windows driver.

use core::mem::size_of;

use hv::platform_ops::PlatformOps;
use shared_contract::{
    EPT_HOOK2_ERR_ALLOC, EPT_HOOK2_ERR_CR3, EPT_HOOK2_ERR_DISASM, EPT_HOOK2_ERR_GPA_RANGE,
    EPT_HOOK2_ERR_HYPERVISOR, EPT_HOOK2_ERR_INVALID, EPT_HOOK2_ERR_NO_EXEC_ONLY,
    EPT_HOOK2_ERR_NOT_FOUND, EPT_HOOK2_ERR_PAGE_BOUNDARY, EPT_HOOK2_ERR_TRANSLATE,
    EptHook2Response, EptUnhookRequest,
};
use spin::Mutex;
use wdk_sys::{
    POOL_FLAG_NON_PAGED, POOL_FLAG_NON_PAGED_EXECUTE,
    ntddk::{ExAllocatePool2, ExFreePoolWithTag},
};

use crate::hook_log::{ept_hook_err_name, log_hex};
use crate::ops::WindowsOps;
use crate::paging::{cr3_switch_failure, gpa_to_hpa, gva_to_gpa_cr3_switch, read_hpa};

const PAGE_SIZE: usize = 4096;
const HOOK_JUMP_LEN: usize = 19;
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
    crate::eprintln!(
        "ept_hook install begin: pid={process_id} syscall={syscall_number} target={target_gva:#x} hook={hook_gva:#x}"
    );

    if target_gva == 0 || hook_gva == 0 {
        return fail_logged(EPT_HOOK2_ERR_INVALID, "bad_target_or_hook");
    }
    if !ept_execute_only_supported() {
        return fail_logged(EPT_HOOK2_ERR_NO_EXEC_ONLY, "ept_execute_only");
    }
    crate::eprintln!("ept_hook: EPT execute-only supported");

    let cr3 = if process_id != 0 {
        match crate::process::get_kernel_cr3(process_id) {
            Ok(cr3) => cr3,
            Err(_) => return fail_logged(EPT_HOOK2_ERR_CR3, "pid_cr3"),
        }
    } else {
        crate::process::read_cr3()
    };
    crate::eprintln!("ept_hook: cr3={cr3:#x}");

    let page_gva = target_gva & !(PAGE_SIZE as u64 - 1);
    let page_offset = (target_gva & (PAGE_SIZE as u64 - 1)) as usize;
    crate::eprintln!("ept_hook: page_gva={page_gva:#x} page_offset={page_offset:#x}");
    if page_offset + HOOK_JUMP_LEN > PAGE_SIZE {
        return fail_logged(EPT_HOOK2_ERR_PAGE_BOUNDARY, "hook_jump_oob");
    }

    let gpa_page_base = match gva_to_gpa_cr3_switch(cr3, page_gva) {
        Ok(gpa) => gpa & !(PAGE_SIZE as u64 - 1),
        Err(status) => {
            let _ = cr3_switch_failure(status);
            crate::eprintln!("ept_hook: gva->gpa failed status={status}");
            return fail_logged(EPT_HOOK2_ERR_TRANSLATE, "gva_to_gpa");
        }
    };
    if gpa_page_base >= SIZE_512_GB {
        return fail_logged(EPT_HOOK2_ERR_GPA_RANGE, "gpa_limit");
    }

    let hpa = gpa_to_hpa(gpa_page_base);
    crate::eprintln!("ept_hook: gpa_page={gpa_page_base:#x} hpa={hpa:#x}");

    let mut page = [0u8; PAGE_SIZE];
    if read_hpa(hpa, page.as_mut_ptr(), PAGE_SIZE).is_err() {
        return fail_logged(EPT_HOOK2_ERR_TRANSLATE, "read_hpa");
    }

    let prologue_end = core::cmp::min(page.len(), page_offset + 64);
    log_hex("ept_hook target", &page[page_offset..prologue_end], 64);

    let hook_plan = match plan_hook(&page, page_offset, syscall_number) {
        Some(plan) => plan,
        None => {
            crate::eprintln!(
                "ept_hook: plan_hook failed (pass syscall_number for instrumented Nt* wrappers)"
            );
            return fail_logged(EPT_HOOK2_ERR_DISASM, "plan_hook");
        }
    };
    let patched_len = hook_plan.patched_len;
    crate::eprintln!(
        "ept_hook plan: syscall={} fake_overwrite={HOOK_JUMP_LEN} patched_len={patched_len}",
        hook_plan.syscall_number
    );

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
    crate::eprintln!(
        "ept_hook pools: fake_page={fake_page:p} trampoline={trampoline:p}"
    );

    let trampoline_dump_len;
    unsafe {
        core::ptr::copy_nonoverlapping(page.as_ptr(), fake_page, PAGE_SIZE);
        write_absolute_jump(
            core::slice::from_raw_parts_mut(fake_page.add(page_offset), HOOK_JUMP_LEN),
            hook_gva,
        );
        write_syscall_trampoline(trampoline, hook_plan.syscall_number);
        trampoline_dump_len = 11usize;
    }

    let fake_hpa = WindowsOps.pa(fake_page.cast());
    crate::eprintln!("ept_hook: fake_hpa={fake_hpa:#x}");
    log_hex(
        "ept_hook fake@offset",
        unsafe { core::slice::from_raw_parts(fake_page.add(page_offset), HOOK_JUMP_LEN) },
        HOOK_JUMP_LEN,
    );
    log_hex(
        "ept_hook trampoline",
        unsafe { core::slice::from_raw_parts(trampoline, trampoline_dump_len) },
        48,
    );

    crate::eprintln!("ept_hook: hypercall install_ept_hook2 gpa={gpa_page_base:#x}");
    let hypercall_ok = hv::hypercall::install_ept_hook2(gpa_page_base, fake_hpa);
    crate::eprintln!("ept_hook: hypercall install_ept_hook2 returned ok={hypercall_ok}");
    if !hypercall_ok {
        crate::eprintln!("ept_hook: hypercall install_ept_hook2 failed");
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

    crate::eprintln!(
        "ept_hook install ok: patched_len={patched_len} trampoline_gva={:#x} target_gpa={gpa_page_base:#x}",
        trampoline as u64
    );

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
    crate::eprintln!(
        "ept_hook uninstall: pid={} target={:#x}",
        request.process_id,
        request.target_gva
    );

    if request.target_gva == 0 {
        crate::eprintln!("ept_hook uninstall failed: invalid target");
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
        Err(status) => {
            crate::eprintln!("ept_hook uninstall: translate failed status={status}");
            return EPT_HOOK2_ERR_TRANSLATE;
        }
    };
    crate::eprintln!("ept_hook uninstall: gpa_page={gpa_page_base:#x}");

    if !hv::hypercall::uninstall_ept_hook2(gpa_page_base) {
        crate::eprintln!("ept_hook uninstall: hypercall failed");
        return EPT_HOOK2_ERR_HYPERVISOR;
    }

    let mut allocs = HOOK_ALLOCS.lock();
    let Some(index) = allocs
        .iter()
        .position(|entry| entry.gpa_page_base == gpa_page_base)
    else {
        crate::eprintln!("ept_hook uninstall: allocation not found");
        return EPT_HOOK2_ERR_NOT_FOUND;
    };
    let entry = allocs.remove(index);
    unsafe {
        free_page(entry.fake_page as *mut u8);
        free_page(entry.trampoline as *mut u8);
    }
    crate::eprintln!("ept_hook uninstall ok");
    0
}

/// Frees all hook allocations during driver unload.
pub(crate) fn uninstall_all() {
    let mut allocs = HOOK_ALLOCS.lock();
    let count = allocs.len();
    crate::eprintln!("ept_hook uninstall_all: count={count}");
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

/// Plans fake-page overwrite and syscall trampoline for `page[offset..]`.
fn plan_hook(page: &[u8], offset: usize, syscall_number: u32) -> Option<HookPlan> {
    if syscall_number != 0 {
        crate::eprintln!("ept_hook plan_hook: forced syscall={syscall_number}");
        return Some(HookPlan {
            patched_len: HOOK_JUMP_LEN,
            syscall_number,
        });
    }

    if let Some(stub) = parse_syscall_stub(page, offset) {
        crate::eprintln!(
            "ept_hook plan_hook: syscall stub at target len={} syscall={}",
            stub.stub_len,
            stub.syscall_number
        );
        return Some(HookPlan {
            patched_len: stub.stub_len,
            syscall_number: stub.syscall_number,
        });
    }

    if let Some(stub) = scan_syscall_stub(page, offset) {
        crate::eprintln!(
            "ept_hook plan_hook: syscall stub scan hit +{} syscall={}",
            stub.offset,
            stub.syscall_number
        );
        return Some(HookPlan {
            patched_len: HOOK_JUMP_LEN,
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

/// Writes a position-independent `Nt*` syscall stub into `trampoline`.
unsafe fn write_syscall_trampoline(trampoline: *mut u8, syscall_number: u32) {
    unsafe {
        let mut cursor = trampoline;
        *cursor = 0x4C;
        cursor = cursor.add(1);
        *cursor = 0x8B;
        cursor = cursor.add(1);
        *cursor = 0xD1;
        cursor = cursor.add(1);
        *cursor = 0xB8;
        cursor = cursor.add(1);
        core::ptr::copy_nonoverlapping(
            syscall_number.to_le_bytes().as_ptr(),
            cursor,
            4,
        );
        cursor = cursor.add(4);
        *cursor = 0x0F;
        cursor = cursor.add(1);
        *cursor = 0x05;
        cursor = cursor.add(1);
        *cursor = 0xC3;
    }
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
