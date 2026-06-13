//! IOCTL device for manual `ssdt_hook` example control.

use core::mem::size_of;

use shared_contract::{
    EptHook2Response, IOCTL_SSDT_HOOK_GET_INFO, IOCTL_SSDT_HOOK_INSTALL,
    IOCTL_SSDT_HOOK_SET_BLOCK_PID, IOCTL_SSDT_HOOK_UNINSTALL, SsdtHookInfoResponse,
    SsdtHookSetBlockPidRequest,
};
use wdk_sys::{
    CCHAR, DEVICE_OBJECT, DRIVER_OBJECT, IO_NO_INCREMENT, IRP, NTSTATUS,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    UNICODE_STRING,
};

const IRP_MJ_CREATE_INDEX: usize = 0x00;
const IRP_MJ_CLOSE_INDEX: usize = 0x02;
const IRP_MJ_DEVICE_CONTROL_INDEX: usize = 0x0e;

const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;
const DO_BUFFERED_IO: u32 = 0x0000_0004;

const DEVICE_NAME: &str = "\\Device\\SsdtHook";
const SYMLINK_NAME: &str = "\\DosDevices\\SsdtHook";

fn encode_utf16z(input: &str, out: &mut [u16]) -> Option<usize> {
    let mut idx = 0;
    for code_unit in input.encode_utf16() {
        if idx + 1 >= out.len() {
            return None;
        }
        out[idx] = code_unit;
        idx += 1;
    }
    out[idx] = 0;
    Some(idx + 1)
}

fn to_unicode_string(buffer: &mut [u16], used_with_nul: usize) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: ((used_with_nul - 1) * size_of::<u16>()) as u16,
        MaximumLength: (used_with_nul * size_of::<u16>()) as u16,
        Buffer: buffer.as_mut_ptr(),
    }
}

unsafe fn complete_request(irp: *mut IRP, status: NTSTATUS, info: usize) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = info as u64;
        wdk_sys::ntddk::IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
    }
    status
}

unsafe extern "C" fn dispatch_create_close(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    unsafe { complete_request(irp, STATUS_SUCCESS, 0) }
}

unsafe extern "C" fn dispatch_device_control(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let stack_location = unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    if stack_location.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let device_io_control = unsafe { (*stack_location).Parameters.DeviceIoControl };
    let ioctl_code = device_io_control.IoControlCode;
    let input_len = device_io_control.InputBufferLength as usize;
    let output_len = device_io_control.OutputBufferLength as usize;
    let system_buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer.cast::<u8>() };

    match ioctl_code {
        IOCTL_SSDT_HOOK_GET_INFO => handle_ioctl_get_info(irp, output_len, system_buffer),
        IOCTL_SSDT_HOOK_INSTALL => handle_ioctl_install(irp, output_len, system_buffer),
        IOCTL_SSDT_HOOK_UNINSTALL => handle_ioctl_uninstall(irp),
        IOCTL_SSDT_HOOK_SET_BLOCK_PID => {
            handle_ioctl_set_block_pid(irp, input_len, system_buffer)
        }
        _ => unsafe { complete_request(irp, STATUS_INVALID_DEVICE_REQUEST, 0) },
    }
}

fn handle_ioctl_get_info(
    irp: *mut IRP,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if output_len < size_of::<SsdtHookInfoResponse>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let response = crate::hook_state::info_response();
    unsafe {
        system_buffer
            .cast::<SsdtHookInfoResponse>()
            .write_unaligned(response);
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<SsdtHookInfoResponse>()) }
}

fn handle_ioctl_install(
    irp: *mut IRP,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if output_len < size_of::<EptHook2Response>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let response = match crate::hook_state::install_hook() {
        Ok(response) => response,
        Err(status) => {
            crate::eprintln!("IOCTL_SSDT_HOOK_INSTALL failed: status={status:#010x}");
            let failed = EptHook2Response {
                success: 0,
                error_code: 0,
                patched_len: 0,
                _padding: 0,
                trampoline_gva: 0,
                target_gpa: 0,
            };
            unsafe {
                system_buffer
                    .cast::<EptHook2Response>()
                    .write_unaligned(failed);
            }
            return unsafe { complete_request(irp, status, size_of::<EptHook2Response>()) };
        }
    };

    unsafe {
        system_buffer
            .cast::<EptHook2Response>()
            .write_unaligned(response);
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<EptHook2Response>()) }
}

fn handle_ioctl_uninstall(irp: *mut IRP) -> NTSTATUS {
    match crate::hook_state::uninstall_hook() {
        Ok(()) => unsafe { complete_request(irp, STATUS_SUCCESS, 0) },
        Err(status) => {
            crate::eprintln!("IOCTL_SSDT_HOOK_UNINSTALL failed: status={status:#010x}");
            unsafe { complete_request(irp, status, 0) }
        }
    }
}

fn handle_ioctl_set_block_pid(
    irp: *mut IRP,
    input_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<SsdtHookSetBlockPidRequest>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe {
        system_buffer
            .cast::<SsdtHookSetBlockPidRequest>()
            .read_unaligned()
    };
    crate::hook_state::set_block_pid(request.pid);
    unsafe { complete_request(irp, STATUS_SUCCESS, 0) }
}

pub(crate) fn create_device(driver: &mut DRIVER_OBJECT) -> NTSTATUS {
    driver.MajorFunction[IRP_MJ_CREATE_INDEX] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE_INDEX] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL_INDEX] = Some(dispatch_device_control);

    let mut device_name_buf = [0u16; 64];
    let Some(device_used) = encode_utf16z(DEVICE_NAME, &mut device_name_buf) else {
        return STATUS_UNSUCCESSFUL;
    };
    let mut device_name = to_unicode_string(&mut device_name_buf, device_used);

    let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
    let status = unsafe {
        wdk_sys::ntddk::IoCreateDevice(
            driver,
            0,
            &raw mut device_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &raw mut device_object,
        )
    };
    if !wdk::nt_success(status) {
        return status;
    }

    unsafe {
        (*device_object).Flags |= DO_BUFFERED_IO;
    }

    let mut symlink_buf = [0u16; 64];
    let Some(symlink_used) = encode_utf16z(SYMLINK_NAME, &mut symlink_buf) else {
        unsafe {
            wdk_sys::ntddk::IoDeleteDevice(device_object);
        }
        return STATUS_UNSUCCESSFUL;
    };
    let mut symlink_name = to_unicode_string(&mut symlink_buf, symlink_used);

    let status =
        unsafe { wdk_sys::ntddk::IoCreateSymbolicLink(&raw mut symlink_name, &raw mut device_name) };
    if !wdk::nt_success(status) {
        unsafe {
            wdk_sys::ntddk::IoDeleteDevice(device_object);
        }
        return status;
    }

    crate::eprintln!("Device ready: {DEVICE_NAME} -> {SYMLINK_NAME}");
    STATUS_SUCCESS
}

pub(crate) fn delete_device(driver: *mut DRIVER_OBJECT) {
    let mut symlink_buf = [0u16; 64];
    let Some(symlink_used) = encode_utf16z(SYMLINK_NAME, &mut symlink_buf) else {
        return;
    };
    let mut symlink = to_unicode_string(&mut symlink_buf, symlink_used);

    unsafe {
        let _ = wdk_sys::ntddk::IoDeleteSymbolicLink(&raw mut symlink);
    }

    unsafe {
        if !(*driver).DeviceObject.is_null() {
            wdk_sys::ntddk::IoDeleteDevice((*driver).DeviceObject);
        }
    }
}
