//! Process kernel CR3 helpers backed by `ntoskrnl` exports.

use core::ffi::c_void;

use wdk_sys::{HANDLE, NTSTATUS, NT_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND};

type PEPROCESS = *mut c_void;

/// `KPROCESS.DirectoryTableBase` on x64 Windows 10+.
const DIRECTORY_TABLE_BASE_OFFSET: usize = 0x28;

unsafe extern "system" {
    fn PsLookupProcessByProcessId(process_id: HANDLE, process: *mut PEPROCESS) -> NTSTATUS;
    fn ObDereferenceObject(object: *mut c_void);
}

/// Returns kernel CR3 (`DirectoryTableBase`) for `process_id`.
pub(crate) fn get_kernel_cr3(process_id: u32) -> Result<u64, NTSTATUS> {
    crate::eprintln!("process: get_kernel_cr3 pid={process_id}");
    let process = lookup_process(process_id)?;
    let cr3 = read_u64_at(process, DIRECTORY_TABLE_BASE_OFFSET);
    unsafe { ObDereferenceObject(process.cast()) };
    crate::eprintln!("process: pid={process_id} cr3={cr3:#x}");
    Ok(cr3)
}

/// Resolves the kernel page table root from `process_id` or `cr3`.
pub(crate) fn resolve_kernel_cr3(process_id: u32, cr3: u64) -> Result<u64, NTSTATUS> {
    if process_id != 0 {
        return get_kernel_cr3(process_id);
    }
    if cr3 & 0x000F_FFFF_FFFF_F000 == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(cr3)
}

/// Reads the current CPU CR3.
pub(crate) fn read_cr3() -> u64 {
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

/// Writes the current CPU CR3.
pub(crate) fn write_cr3(cr3: u64) {
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) cr3,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn lookup_process(process_id: u32) -> Result<PEPROCESS, NTSTATUS> {
    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = unsafe { PsLookupProcessByProcessId(process_id as HANDLE, &raw mut process) };
    if !NT_SUCCESS(status) {
        crate::eprintln!(
            "process: PsLookupProcessByProcessId pid={process_id} failed status={status:#010x}"
        );
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
