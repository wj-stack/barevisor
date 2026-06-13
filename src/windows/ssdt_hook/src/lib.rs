#![doc = "EPT Hook2 example driver: manual SSDT `NtOpenProcess` detour via `win_hv`."]
#![no_std]

mod device;
mod eprintln;
mod hook_state;

use wdk_sys::{
    DRIVER_OBJECT, HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, PCUNICODE_STRING, STATUS_NOT_FOUND,
    STATUS_SUCCESS,
};

type NtOpenProcessFn = unsafe extern "system" fn(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut ClientId,
) -> NTSTATUS;

#[repr(C)]
pub(crate) struct ClientId {
    unique_process: HANDLE,
    unique_thread: HANDLE,
}

#[unsafe(link_section = "INIT")]
#[unsafe(export_name = "DriverEntry")]
extern "C" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    driver.DriverUnload = Some(driver_unload);
    eprintln!("Loading ssdt_hook.sys (manual hook mode)");

    let status = device::create_device(driver);
    if !wdk::nt_success(status) {
        eprintln!("Device creation failed: {status}");
        return status;
    }

    if let Err(status) = hook_state::init_target() {
        eprintln!("NtOpenProcess SSDT resolve failed: {status}");
        return STATUS_NOT_FOUND;
    }

    eprintln!("Ready. Use win_hv_client ssdt-hook info / install");
    STATUS_SUCCESS
}

unsafe extern "C" fn driver_unload(driver: *mut DRIVER_OBJECT) {
    let _ = hook_state::uninstall_hook();
    device::delete_device(driver);
    eprintln!("Unloaded ssdt_hook.sys");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn hooked_nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut ClientId,
) -> NTSTATUS {
    hook_state::on_hook_hit(process_handle, desired_access, object_attributes, client_id)
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
