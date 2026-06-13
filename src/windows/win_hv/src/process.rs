//! Process CR3 helpers backed by `ntoskrnl` exports.

use core::ffi::c_void;

use wdk_sys::{HANDLE, NTSTATUS, NT_SUCCESS, STATUS_NOT_FOUND};

type PEPROCESS = *mut c_void;
type PRKPROCESS = *mut c_void;
type PRKAPC_STATE = *mut KAPC_STATE;

/// `KPROCESS.DirectoryTableBase` on x64 Windows 10+.
const DIRECTORY_TABLE_BASE_OFFSET: usize = 0x28;
/// `KPROCESS.UserDirectoryTableBase` on x64 Windows 10 1803+ (KVA shadow).
const USER_DIRECTORY_TABLE_BASE_OFFSET: usize = 0x388;

#[repr(C)]
struct KAPC_STATE {
    _storage: [u8; 0x40],
}

pub(crate) struct ProcessCr3 {
    pub kernel: u64,
    pub user: u64,
}

unsafe extern "system" {
    fn PsLookupProcessByProcessId(process_id: HANDLE, process: *mut PEPROCESS) -> NTSTATUS;
    fn ObDereferenceObject(object: *mut c_void);
    fn KeStackAttachProcess(process: PRKPROCESS, apc_state: PRKAPC_STATE);
    fn KeUnstackDetachProcess(apc_state: PRKAPC_STATE);
}

/// Returns kernel and user CR3 values for `process_id`.
pub(crate) fn get_process_cr3(process_id: u32) -> Result<ProcessCr3, NTSTATUS> {
    let process = lookup_process(process_id)?;
    let kernel = read_u64_at(process, DIRECTORY_TABLE_BASE_OFFSET);
    let mut user = read_u64_at(process, USER_DIRECTORY_TABLE_BASE_OFFSET);
    if user == 0 {
        user = read_attached_cr3(process);
    }
    let cr3 = ProcessCr3 { kernel, user };
    unsafe { ObDereferenceObject(process.cast()) };
    Ok(cr3)
}

/// Picks the page table root for `gva`.
pub(crate) fn resolve_cr3_for_gva(process_id: u32, cr3: u64, gva: u64) -> Result<u64, NTSTATUS> {
    if process_id != 0 {
        let process = lookup_process(process_id)?;
        let cr3 = resolve_cr3_for_process(process, gva)?;
        unsafe { ObDereferenceObject(process.cast()) };
        return Ok(cr3);
    }
    Ok(cr3)
}

fn resolve_cr3_for_process(process: PEPROCESS, gva: u64) -> Result<u64, NTSTATUS> {
    if crate::paging::is_user_gva(gva) {
        let user = read_u64_at(process, USER_DIRECTORY_TABLE_BASE_OFFSET);
        if user != 0 {
            return Ok(user);
        }
        return Ok(read_attached_cr3(process));
    }
    Ok(read_u64_at(process, DIRECTORY_TABLE_BASE_OFFSET))
}

fn read_attached_cr3(process: PEPROCESS) -> u64 {
    let mut apc_state = KAPC_STATE {
        _storage: [0; 0x40],
    };
    unsafe {
        KeStackAttachProcess(process.cast(), &raw mut apc_state);
        let cr3 = read_cr3();
        KeUnstackDetachProcess(&raw mut apc_state);
        cr3
    }
}

fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

fn lookup_process(process_id: u32) -> Result<PEPROCESS, NTSTATUS> {
    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = unsafe { PsLookupProcessByProcessId(process_id as HANDLE, &raw mut process) };
    if !NT_SUCCESS(status) {
        return Err(if status == STATUS_NOT_FOUND {
            STATUS_NOT_FOUND
        } else {
            status
        });
    }
    Ok(process)
}

fn read_u64_at(process: PEPROCESS, offset: usize) -> u64 {
    unsafe { process.cast::<u8>().add(offset).cast::<u64>().read_unaligned() }
}
