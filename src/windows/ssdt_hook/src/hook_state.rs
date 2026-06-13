//! SSDT hook example state and EPT install helpers.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use shared_contract::{
    EptHook2Request, EptHook2Response, EptUnhookRequest, SsdtHookInfoResponse,
    EPT_HOOK2_ERR_ALLOC, EPT_HOOK2_ERR_CR3, EPT_HOOK2_ERR_DISASM, EPT_HOOK2_ERR_GPA_RANGE,
    EPT_HOOK2_ERR_HYPERVISOR, EPT_HOOK2_ERR_INVALID, EPT_HOOK2_ERR_NO_EXEC_ONLY,
    EPT_HOOK2_ERR_NOT_FOUND, EPT_HOOK2_ERR_PAGE_BOUNDARY, EPT_HOOK2_ERR_TRANSLATE,
    SSDT_HOOK_EXPORT_NAME_LEN, IOCTL_EPT_HOOK2, IOCTL_EPT_UNHOOK,
};
use spin::Mutex;
use wdk_sys::{
    HANDLE, IO_STATUS_BLOCK, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_NOT_FOUND, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

use crate::{ClientId, NtOpenProcessFn};

const HOOK_EXPORT: &str = "NtOpenProcess";

struct HookState {
    target_gva: u64,
    hook_gva: u64,
    syscall_number: u32,
    trampoline: Option<NtOpenProcessFn>,
}

static HOOK_STATE: Mutex<HookState> = Mutex::new(HookState {
    target_gva: 0,
    hook_gva: 0,
    syscall_number: 0,
    trampoline: None,
});
static TRAMPOLINE_GVA: AtomicU64 = AtomicU64::new(0);
static TARGET_GPA: AtomicU64 = AtomicU64::new(0);

pub(crate) fn init_target() -> Result<(), NTSTATUS> {
    let resolved = kernel_ssdt::resolve_ssdt_function(HOOK_EXPORT)?;
    let hook_gva = crate::hooked_nt_open_process as *const () as u64;
    let mut state = HOOK_STATE.lock();
    state.target_gva = resolved.address as u64;
    state.hook_gva = hook_gva;
    state.syscall_number = resolved.syscall_number;
    state.trampoline = None;
    Ok(())
}

pub(crate) fn info_response() -> SsdtHookInfoResponse {
    let state = HOOK_STATE.lock();
    let mut export_name = [0u8; SSDT_HOOK_EXPORT_NAME_LEN];
    let bytes = HOOK_EXPORT.as_bytes();
    let copy_len = core::cmp::min(bytes.len(), SSDT_HOOK_EXPORT_NAME_LEN - 1);
    export_name[..copy_len].copy_from_slice(&bytes[..copy_len]);

    SsdtHookInfoResponse {
        ready: u8::from(state.target_gva != 0),
        installed: u8::from(TRAMPOLINE_GVA.load(Ordering::Acquire) != 0),
        _padding: [0; 6],
        target_gva: state.target_gva,
        hook_gva: state.hook_gva,
        export_name,
        trampoline_gva: TRAMPOLINE_GVA.load(Ordering::Acquire),
    }
}

pub(crate) fn install_hook() -> Result<EptHook2Response, NTSTATUS> {
    let (target_gva, hook_gva, syscall_number) = {
        let state = HOOK_STATE.lock();
        if state.target_gva == 0 {
            return Err(STATUS_NOT_FOUND);
        }
        (state.target_gva, state.hook_gva, state.syscall_number)
    };

    let response = install_ept_hook(target_gva, hook_gva, syscall_number)?;
    TRAMPOLINE_GVA.store(response.trampoline_gva, Ordering::Release);
    TARGET_GPA.store(response.target_gpa, Ordering::Release);
    let trampoline = unsafe {
        core::mem::transmute::<u64, NtOpenProcessFn>(response.trampoline_gva)
    };
    {
        let mut state = HOOK_STATE.lock();
        state.trampoline = Some(trampoline);
    }

    Ok(response)
}

pub(crate) fn uninstall_hook() -> Result<(), NTSTATUS> {
    let target_gva = HOOK_STATE.lock().target_gva;
    if target_gva == 0 {
        return Ok(());
    }
    uninstall_ept_hook(target_gva)?;
    TRAMPOLINE_GVA.store(0, Ordering::Release);
    TARGET_GPA.store(0, Ordering::Release);
    let mut state = HOOK_STATE.lock();
    state.trampoline = None;
    Ok(())
}

pub(crate) fn on_hook_hit(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut ClientId,
) -> NTSTATUS {
    let trampoline = TRAMPOLINE_GVA.load(Ordering::Acquire);
    if trampoline == 0 {
        return STATUS_UNSUCCESSFUL;
    }
    let original: NtOpenProcessFn = unsafe { core::mem::transmute(trampoline) };
    let status =
        unsafe { original(process_handle, desired_access, object_attributes, client_id) };
    let target_gpa = TARGET_GPA.load(Ordering::Acquire);
    if target_gpa != 0 {
        let _ = hv::hypercall::restore_ept_hook2(target_gpa);
    }
    status
}

unsafe extern "system" {
    fn ZwCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> NTSTATUS;
    fn ZwDeviceIoControlFile(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        io_control_code: u32,
        input_buffer: *mut c_void,
        input_buffer_length: u32,
        output_buffer: *mut c_void,
        output_buffer_length: u32,
    ) -> NTSTATUS;
    fn ZwClose(handle: HANDLE) -> NTSTATUS;
    fn RtlInitUnicodeString(destination: *mut UNICODE_STRING, source: *const u16);
}

const FILE_GENERIC_READ: u32 = 0x8000_0000;
const FILE_GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

fn device_io_control(
    handle: HANDLE,
    ioctl: u32,
    input: *mut c_void,
    input_len: u32,
    output: *mut c_void,
    output_len: u32,
) -> NTSTATUS {
    let mut io_status = IO_STATUS_BLOCK::default();
    unsafe {
        ZwDeviceIoControlFile(
            handle,
            HANDLE::default(),
            null_mut(),
            null_mut(),
            &raw mut io_status,
            ioctl,
            input,
            input_len,
            output,
            output_len,
        )
    }
}

fn install_ept_hook(
    target_gva: u64,
    hook_gva: u64,
    syscall_number: u32,
) -> Result<EptHook2Response, NTSTATUS> {
    let handle = open_barevisor_device()?;
    let request = EptHook2Request {
        process_id: 0,
        syscall_number,
        target_gva,
        hook_gva,
    };
    let mut response = EptHook2Response::default();
    let status = device_io_control(
        handle,
        IOCTL_EPT_HOOK2,
        (&raw const request).cast_mut().cast(),
        size_of::<EptHook2Request>() as u32,
        (&raw mut response).cast(),
        size_of::<EptHook2Response>() as u32,
    );
    unsafe { ZwClose(handle) };
    if response.success == 0 {
        crate::eprintln!(
            "IOCTL_EPT_HOOK2 rejected: ioctl_status={:#010x} error_code={} ({})",
            status as u32,
            response.error_code,
            ept_hook_err_name(response.error_code)
        );
        return Err(if NT_SUCCESS(status) {
            STATUS_UNSUCCESSFUL
        } else {
            status
        });
    }
    if !NT_SUCCESS(status) {
        return Err(status);
    }
    Ok(response)
}

fn uninstall_ept_hook(target_gva: u64) -> Result<(), NTSTATUS> {
    let handle = open_barevisor_device()?;
    let request = EptUnhookRequest {
        target_gva,
        process_id: 0,
        _padding: 0,
    };
    let mut error_code = 0u8;
    let status = device_io_control(
        handle,
        IOCTL_EPT_UNHOOK,
        (&raw const request).cast_mut().cast(),
        size_of::<EptUnhookRequest>() as u32,
        (&raw mut error_code).cast(),
        size_of::<u8>() as u32,
    );
    unsafe { ZwClose(handle) };
    if !NT_SUCCESS(status) || error_code != 0 {
        crate::eprintln!(
            "IOCTL_EPT_UNHOOK failed: status={status:#010x} error_code={error_code} ({})",
            ept_hook_err_name(error_code)
        );
        return Err(STATUS_UNSUCCESSFUL);
    }
    Ok(())
}

fn open_barevisor_device() -> Result<HANDLE, NTSTATUS> {
    let mut path = UNICODE_STRING::default();
    let mut wide = [0u16; 32];
    encode_wide("\\??\\BarevisorHv", &mut wide);
    unsafe { RtlInitUnicodeString(&raw mut path, wide.as_ptr()) };

    let mut object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &raw mut path,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };

    let mut handle = HANDLE::default();
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        ZwCreateFile(
            &raw mut handle,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            &raw mut object_attributes,
            &raw mut io_status,
            null_mut(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        )
    };
    if !NT_SUCCESS(status) {
        crate::eprintln!("ssdt_hook: open BarevisorHv failed status={status:#010x}");
        return Err(if status == STATUS_NOT_FOUND {
            STATUS_INSUFFICIENT_RESOURCES
        } else {
            status
        });
    }
    Ok(handle)
}

fn ept_hook_err_name(code: u8) -> &'static str {
    match code {
        EPT_HOOK2_ERR_INVALID => "invalid",
        EPT_HOOK2_ERR_CR3 => "cr3",
        EPT_HOOK2_ERR_TRANSLATE => "translate",
        EPT_HOOK2_ERR_GPA_RANGE => "gpa_range",
        EPT_HOOK2_ERR_DISASM => "disasm",
        EPT_HOOK2_ERR_ALLOC => "alloc",
        EPT_HOOK2_ERR_HYPERVISOR => "hypervisor",
        EPT_HOOK2_ERR_NO_EXEC_ONLY => "no_exec_only",
        EPT_HOOK2_ERR_NOT_FOUND => "not_found",
        EPT_HOOK2_ERR_PAGE_BOUNDARY => "page_boundary",
        _ => "unknown",
    }
}

fn encode_wide(input: &str, out: &mut [u16]) {
    let mut index = 0;
    for unit in input.encode_utf16() {
        if index + 1 >= out.len() {
            break;
        }
        out[index] = unit;
        index += 1;
    }
    if index < out.len() {
        out[index] = 0;
    }
}
