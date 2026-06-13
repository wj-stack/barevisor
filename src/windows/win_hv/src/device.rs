//! Device object, symbolic link, and IOCTL dispatch for `win_hv`.

use core::mem::size_of;

use shared_contract::{
    GetCr3ByPidRequest, GetCr3ByPidResponse, IOCTL_GET_CR3_BY_PID, IOCTL_PING,
    IOCTL_READ_GVA, IOCTL_READ_MEMORY, IOCTL_TRANSLATE_GVA, IOCTL_WRITE_MEMORY, MEM_IO_MAX_LEN,
    MemIoRequest, PING_RESPONSE_U32, ReadGvaRequest, TranslateGvaRequest, TranslateGvaResponse,
    TRANSLATE_FAIL_CR3,
};
use wdk_sys::{
    CCHAR, DEVICE_OBJECT, DRIVER_OBJECT, IO_NO_INCREMENT, IRP, NTSTATUS,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

use crate::eprintln;

const IRP_MJ_CREATE_INDEX: usize = 0x00;
const IRP_MJ_CLOSE_INDEX: usize = 0x02;
const IRP_MJ_DEVICE_CONTROL_INDEX: usize = 0x0e;

const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;
const DO_BUFFERED_IO: u32 = 0x0000_0004;

const DEVICE_NAME: &str = "\\Device\\BarevisorHv";
const SYMLINK_NAME: &str = "\\DosDevices\\BarevisorHv";

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
        IOCTL_PING => handle_ioctl_ping(irp, output_len, system_buffer),
        IOCTL_READ_MEMORY => handle_ioctl_read_memory(irp, input_len, output_len, system_buffer),
        IOCTL_WRITE_MEMORY => handle_ioctl_write_memory(irp, input_len, system_buffer),
        IOCTL_GET_CR3_BY_PID => {
            handle_ioctl_get_cr3_by_pid(irp, input_len, output_len, system_buffer)
        }
        IOCTL_TRANSLATE_GVA => {
            handle_ioctl_translate_gva(irp, input_len, output_len, system_buffer)
        }
        IOCTL_READ_GVA => handle_ioctl_read_gva(irp, input_len, output_len, system_buffer),
        _ => unsafe { complete_request(irp, STATUS_INVALID_DEVICE_REQUEST, 0) },
    }
}

fn handle_ioctl_ping(irp: *mut IRP, output_len: usize, system_buffer: *mut u8) -> NTSTATUS {
    if output_len < size_of::<u32>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    if hv::hypercall::ping() {
        unsafe {
            system_buffer
                .cast::<u32>()
                .write_unaligned(PING_RESPONSE_U32);
        }
        unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<u32>()) }
    } else {
        unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) }
    }
}

fn handle_ioctl_read_memory(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<MemIoRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe { system_buffer.cast::<MemIoRequest>().read_unaligned() };
    let size = request.size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }

    if !hv::hypercall::read_memory(request.address, system_buffer, size) {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    unsafe { complete_request(irp, STATUS_SUCCESS, size) }
}

fn handle_ioctl_write_memory(
    irp: *mut IRP,
    input_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<MemIoRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe { system_buffer.cast::<MemIoRequest>().read_unaligned() };
    let size = request.size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if input_len < size_of::<MemIoRequest>() + size {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }

    let data = unsafe { system_buffer.add(size_of::<MemIoRequest>()) };
    if !hv::hypercall::write_memory(request.address, data, size) {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    unsafe { complete_request(irp, STATUS_SUCCESS, 0) }
}

fn handle_ioctl_get_cr3_by_pid(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<GetCr3ByPidRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size_of::<GetCr3ByPidResponse>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe {
        system_buffer
            .cast::<GetCr3ByPidRequest>()
            .read_unaligned()
    };
    let response = match crate::process::get_process_cr3(request.process_id) {
        Ok(cr3) => GetCr3ByPidResponse {
            found: 1,
            _padding: [0; 7],
            cr3: cr3.kernel,
            user_cr3: cr3.user,
        },
        Err(_) => GetCr3ByPidResponse {
            found: 0,
            _padding: [0; 7],
            cr3: 0,
            user_cr3: 0,
        },
    };

    unsafe {
        system_buffer
            .cast::<GetCr3ByPidResponse>()
            .write_unaligned(response);
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<GetCr3ByPidResponse>()) }
}

fn translate_gva(process_id: u32, cr3: u64, gva: u64) -> TranslateGvaResponse {
    let cr3 = match crate::process::resolve_cr3_for_gva(process_id, cr3, gva) {
        Ok(cr3) => cr3,
        Err(status) => {
            eprintln!(
                "translate_gva: cr3 resolve failed pid={process_id} gva={gva:#x} status={status}"
            );
            return translate_gva_failed(0, status, TRANSLATE_FAIL_CR3, &crate::paging::WalkFailure::default());
        }
    };

    match crate::paging::gva_to_gpa_walk(cr3, gva) {
        Ok(walk) => {
            let gpa = walk.gpa;
            TranslateGvaResponse {
                success: 1,
                walk_level: walk.level as u8,
                fail_stage: 0,
                _padding: 0,
                status: 0,
                used_cr3: cr3,
                pml4e_pa: walk.pml4e_pa,
                pdpe_pa: walk.pdpe_pa,
                pde_pa: walk.pde_pa,
                pte_pa: walk.pte_pa,
                gpa,
                hpa: crate::paging::gpa_to_hpa(gpa),
            }
        }
        Err(failure) => {
            eprintln!(
                "translate_gva: walk failed pid={process_id} gva={gva:#x} cr3={cr3:#x} stage={} status={}",
                failure.stage,
                failure.status
            );
            translate_gva_failed(cr3, failure.status, failure.stage, &failure)
        }
    }
}

fn translate_gva_failed(
    used_cr3: u64,
    status: NTSTATUS,
    fail_stage: u8,
    failure: &crate::paging::WalkFailure,
) -> TranslateGvaResponse {
    TranslateGvaResponse {
        success: 0,
        walk_level: 0,
        fail_stage,
        _padding: 0,
        status,
        used_cr3,
        pml4e_pa: failure.pml4e_pa,
        pdpe_pa: failure.pdpe_pa,
        pde_pa: failure.pde_pa,
        pte_pa: failure.pte_pa,
        gpa: 0,
        hpa: 0,
    }
}

fn handle_ioctl_translate_gva(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<TranslateGvaRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size_of::<TranslateGvaResponse>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe {
        system_buffer
            .cast::<TranslateGvaRequest>()
            .read_unaligned()
    };
    let response = translate_gva(request.process_id, request.cr3, request.gva);
    unsafe {
        system_buffer
            .cast::<TranslateGvaResponse>()
            .write_unaligned(response);
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<TranslateGvaResponse>()) }
}

fn handle_ioctl_read_gva(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<ReadGvaRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe { system_buffer.cast::<ReadGvaRequest>().read_unaligned() };
    let size = request.size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }

    let translation = translate_gva(request.process_id, request.cr3, request.gva);
    if translation.success == 0 {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    if crate::paging::read_hpa(translation.hpa, system_buffer, size).is_err() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    unsafe { complete_request(irp, STATUS_SUCCESS, size) }
}

extern "C" fn driver_unload(driver: *mut DRIVER_OBJECT) {
    let mut symlink_buf = [0u16; 96];
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
    eprintln!("Unloaded win_hv.sys");
}

pub(crate) fn create_device(driver: &mut DRIVER_OBJECT) -> NTSTATUS {
    driver.DriverUnload = Some(driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE_INDEX] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE_INDEX] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL_INDEX] = Some(dispatch_device_control);

    let mut device_name_buf = [0u16; 96];
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

    let mut symlink_buf = [0u16; 96];
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

    eprintln!("Device ready: {DEVICE_NAME} -> {SYMLINK_NAME}");
    STATUS_SUCCESS
}
