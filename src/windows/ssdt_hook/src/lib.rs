#![doc = "EPT Hook2 example driver: hooks SSDT `NtOpenProcess` via `win_hv`."]
#![no_std]

mod eprintln;
mod ssdt;

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use shared_contract::{
    EptHook2Request, EptHook2Response, EptUnhookRequest, IOCTL_EPT_HOOK2, IOCTL_EPT_UNHOOK,
};
use spin::Mutex;
use wdk_sys::{
    DRIVER_OBJECT, HANDLE, IO_STATUS_BLOCK, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES,
    PCUNICODE_STRING, STATUS_INSUFFICIENT_RESOURCES, STATUS_NOT_FOUND, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

type NtOpenProcessFn = unsafe extern "system" fn(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut ClientId,
) -> NTSTATUS;

#[repr(C)]
struct ClientId {
    unique_process: HANDLE,
    unique_thread: HANDLE,
}

struct HookState {
    target_gva: u64,
    trampoline: Option<NtOpenProcessFn>,
}

static HOOK_STATE: Mutex<HookState> = Mutex::new(HookState {
    target_gva: 0,
    trampoline: None,
});
static HOOK_HITS: AtomicU64 = AtomicU64::new(0);

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
    fn RtlInitUnicodeString(destination: *mut UNICODE_STRING, source: PCWSTR);
}

type PCWSTR = *const u16;

const FILE_GENERIC_READ: u32 = 0x8000_0000;
const FILE_GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

#[unsafe(link_section = "INIT")]
#[unsafe(export_name = "DriverEntry")]
extern "C" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    driver.DriverUnload = Some(driver_unload);
    eprintln!("Loading ssdt_hook.sys");

    let target_gva = match ssdt::kernel_routine_address("NtOpenProcess") {
        Some(address) => {
            eprintln!("NtOpenProcess via MmGetSystemRoutineAddress = {address:#x}");
            address as u64
        }
        None => {
            eprintln!("NtOpenProcess resolve failed");
            return STATUS_NOT_FOUND;
        }
    };

    let response = match install_ept_hook(target_gva, hooked_nt_open_process as *const () as u64) {
        Ok(response) => response,
        Err(status) => {
            eprintln!("EPT hook install failed: status={:#010x}", status as u32);
            return status;
        }
    };

    let trampoline = unsafe {
        core::mem::transmute::<u64, NtOpenProcessFn>(response.trampoline_gva)
    };
    *HOOK_STATE.lock() = HookState {
        target_gva,
        trampoline: Some(trampoline),
    };

    eprintln!(
        "NtOpenProcess EPT hook installed: trampoline={:#x} patched_len={}",
        response.trampoline_gva, response.patched_len
    );
    STATUS_SUCCESS
}

unsafe extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    let target_gva = HOOK_STATE.lock().target_gva;
    if target_gva != 0 {
        if let Err(status) = uninstall_ept_hook(target_gva) {
            eprintln!("EPT unhook failed during unload: {status}");
        } else {
            eprintln!("NtOpenProcess EPT hook removed");
        }
    }
    *HOOK_STATE.lock() = HookState {
        target_gva: 0,
        trampoline: None,
    };
    eprintln!("Unloaded ssdt_hook.sys");
}

unsafe extern "system" fn hooked_nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut ClientId,
) -> NTSTATUS {
    let hits = HOOK_HITS.fetch_add(1, Ordering::Relaxed) + 1;
    let pid = if client_id.is_null() {
        0
    } else {
        unsafe { (*client_id).unique_process as u32 }
    };
    eprintln!("hooked NtOpenProcess hit #{hits} pid={pid} access={desired_access:#x}");

    let original = HOOK_STATE.lock().trampoline;
    let Some(original) = original else {
        return STATUS_UNSUCCESSFUL;
    };
    unsafe { original(process_handle, desired_access, object_attributes, client_id) }
}

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

fn install_ept_hook(target_gva: u64, hook_gva: u64) -> Result<EptHook2Response, NTSTATUS> {
    let handle = open_barevisor_device()?;
    let request = EptHook2Request {
        process_id: 0,
        _padding: 0,
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
        eprintln!(
            "IOCTL_EPT_HOOK2 rejected: ioctl_status={:#010x} error_code={}",
            status as u32, response.error_code
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
        return Err(if status == STATUS_NOT_FOUND {
            STATUS_INSUFFICIENT_RESOURCES
        } else {
            status
        });
    }
    Ok(handle)
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

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    if let Some(text) = info.message().as_str() {
        panic_print(text);
    }
    if let Some(location) = info.location() {
        panic_print(location.file());
        panic_print(":");
        panic_print_u32(location.line());
    }
    if unsafe { *wdk_sys::KdDebuggerNotPresent } == 0 {
        wdk::dbg_break();
    }
    loop {}
}

fn panic_print(text: &str) {
    let mut buffer = [0u8; 128];
    let length = core::cmp::min(buffer.len() - 1, text.len());
    buffer[..length].copy_from_slice(&text.as_bytes()[..length]);
    let msg_ptr = buffer.as_mut_ptr().cast::<i8>();
    let _ = unsafe {
        wdk_sys::ntddk::DbgPrintEx(
            wdk_sys::_DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID as _,
            wdk_sys::DPFLTR_ERROR_LEVEL,
            c"ssdt_hook panic: %s".as_ptr(),
            msg_ptr,
        )
    };
}

fn panic_print_u32(value: u32) {
    let mut buffer = [0u8; 16];
    let mut n = value;
    let mut index = buffer.len();
    if n == 0 {
        index -= 1;
        buffer[index] = b'0';
    } else {
        while n > 0 && index > 0 {
            index -= 1;
            buffer[index] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    let msg_ptr = buffer[index..].as_mut_ptr().cast::<i8>();
    let _ = unsafe {
        wdk_sys::ntddk::DbgPrintEx(
            wdk_sys::_DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID as _,
            wdk_sys::DPFLTR_ERROR_LEVEL,
            c"%s".as_ptr(),
            msg_ptr,
        )
    };
}
