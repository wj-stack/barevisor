//! Process CR3 helpers backed by `ntoskrnl` exports.

use core::ffi::c_void;

use wdk_sys::{HANDLE, NTSTATUS, NT_SUCCESS, STATUS_NOT_FOUND};

type PEPROCESS = *mut c_void;

/// `KPROCESS` prefix of `EPROCESS` on x64 Windows 10+.
#[repr(C)]
struct KPROCESS {
    _header: [u8; 0x28],
    directory_table_base: u64,
}

unsafe extern "system" {
    fn PsLookupProcessByProcessId(process_id: HANDLE, process: *mut PEPROCESS) -> NTSTATUS;
    fn ObDereferenceObject(object: *mut c_void);
}

/// Returns the target process CR3 (`DirectoryTableBase`), if the PID exists.
pub(crate) fn get_cr3_by_process_id(process_id: u32) -> Result<u64, NTSTATUS> {
    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = unsafe { PsLookupProcessByProcessId(process_id as HANDLE, &raw mut process) };
    if !NT_SUCCESS(status) {
        return Err(if status == STATUS_NOT_FOUND {
            STATUS_NOT_FOUND
        } else {
            status
        });
    }

    let cr3 = cr3_from_eprocess(process);
    unsafe { ObDereferenceObject(process.cast()) };
    Ok(cr3)
}

fn cr3_from_eprocess(process: PEPROCESS) -> u64 {
    unsafe { (*(process.cast::<KPROCESS>())).directory_table_base }
}
