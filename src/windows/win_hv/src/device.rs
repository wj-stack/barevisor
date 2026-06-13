//! Device object, symbolic link, and IOCTL dispatch for `win_hv`.

use core::mem::size_of;

use shared_contract::{
    EptHook2Request, EptHook2Response, EptUnhookRequest, GetCr3ByPidRequest, GetCr3ByPidResponse,
    GetSsdtFunctionRequest, GetSsdtFunctionResponse, GetSsdtResponse, IOCTL_EPT_HOOK2,
    IOCTL_EPT_UNHOOK, IOCTL_GET_CR3_BY_PID, IOCTL_GET_SSDT, IOCTL_GET_SSDT_FUNCTION, IOCTL_PING,
    IOCTL_READ_GVA, IOCTL_READ_MEMORY, IOCTL_TRANSLATE_GVA, IOCTL_WRITE_MEMORY,
    IOCTL_WRITE_PHYSICAL, MEM_IO_MAX_LEN, MemIoRequest, PhysMemIoRequest, PING_RESPONSE_U32,
    ReadGvaRequest, TranslateGvaRequest, TranslateGvaResponse, TRANSLATE_FAIL_CR3,
    TRANSLATE_METHOD_CR3_SWITCH, TRANSLATE_METHOD_PAGE_WALK,
};
use wdk_sys::{
    CCHAR, DEVICE_OBJECT, DRIVER_OBJECT, IO_NO_INCREMENT, IRP, NTSTATUS,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

use crate::eprintln;
use crate::hook_log::{ept_hook_err_name, ioctl_name, ssdt_err_name, translate_fail_stage};

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

fn c_str_preview(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("<invalid>")
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

    eprintln!(
        "IOCTL {} ({:#x}) in={} out={}",
        ioctl_name(ioctl_code),
        ioctl_code,
        input_len,
        output_len
    );

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
        IOCTL_WRITE_PHYSICAL => handle_ioctl_write_physical(irp, input_len, system_buffer),
        IOCTL_EPT_HOOK2 => handle_ioctl_ept_hook2(irp, input_len, output_len, system_buffer),
        IOCTL_EPT_UNHOOK => handle_ioctl_ept_unhook(irp, input_len, output_len, system_buffer),
        IOCTL_GET_SSDT => handle_ioctl_get_ssdt(irp, output_len, system_buffer),
        IOCTL_GET_SSDT_FUNCTION => {
            handle_ioctl_get_ssdt_function(irp, input_len, output_len, system_buffer)
        }
        _ => {
            eprintln!("IOCTL unknown: {ioctl_code:#x}");
            unsafe { complete_request(irp, STATUS_INVALID_DEVICE_REQUEST, 0) }
        }
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
        eprintln!("IOCTL_PING ok");
        unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<u32>()) }
    } else {
        eprintln!("IOCTL_PING failed: hypervisor ping");
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
        eprintln!("IOCTL_READ_MEMORY: invalid size={size}");
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }

    if !hv::hypercall::read_memory(request.address, system_buffer, size) {
        eprintln!(
            "IOCTL_READ_MEMORY failed: addr={:#x} size={size}",
            request.address
        );
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    eprintln!("IOCTL_READ_MEMORY ok: addr={:#x} size={size}", request.address);

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
        eprintln!(
            "IOCTL_WRITE_MEMORY failed: addr={:#x} size={size}",
            request.address
        );
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    eprintln!("IOCTL_WRITE_MEMORY ok: addr={:#x} size={size}", request.address);

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
    eprintln!("IOCTL_GET_CR3_BY_PID: pid={}", request.process_id);
    let response = match crate::process::get_kernel_cr3(request.process_id) {
        Ok(cr3) => {
            eprintln!("IOCTL_GET_CR3_BY_PID ok: cr3={cr3:#x}");
            GetCr3ByPidResponse {
                found: 1,
                _padding: [0; 7],
                cr3,
            }
        }
        Err(status) => {
            eprintln!("IOCTL_GET_CR3_BY_PID failed: status={status:#010x}");
            GetCr3ByPidResponse {
                found: 0,
                _padding: [0; 7],
                cr3: 0,
            }
        }
    };

    unsafe {
        system_buffer
            .cast::<GetCr3ByPidResponse>()
            .write_unaligned(response);
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<GetCr3ByPidResponse>()) }
}

fn translate_gva(process_id: u32, method: u32, cr3: u64, gva: u64) -> TranslateGvaResponse {
    let method = if method == TRANSLATE_METHOD_CR3_SWITCH {
        TRANSLATE_METHOD_CR3_SWITCH
    } else {
        TRANSLATE_METHOD_PAGE_WALK
    };

    let cr3 = match crate::process::resolve_kernel_cr3(process_id, cr3) {
        Ok(cr3) => cr3,
        Err(status) => {
            eprintln!(
                "translate_gva: cr3 resolve failed pid={process_id} gva={gva:#x} status={status}"
            );
            return translate_gva_failed(
                method,
                0,
                status,
                TRANSLATE_FAIL_CR3,
                &crate::paging::WalkFailure::default(),
            );
        }
    };

    if method == TRANSLATE_METHOD_CR3_SWITCH {
        return translate_gva_cr3_switch(method, cr3, gva, process_id);
    }

    match crate::paging::gva_to_gpa_walk(cr3, gva) {
        Ok(walk) => {
            let gpa = walk.gpa;
            eprintln!(
                "translate_gva: walk ok pid={process_id} gva={gva:#x} gpa={gpa:#x} level={}",
                walk.level as u8
            );
            TranslateGvaResponse {
                success: 1,
                walk_level: walk.level as u8,
                fail_stage: 0,
                method: method as u8,
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
                "translate_gva: walk failed pid={process_id} gva={gva:#x} cr3={cr3:#x} stage={} ({}) status={:#010x}",
                failure.stage,
                translate_fail_stage(failure.stage),
                failure.status as u32
            );
            translate_gva_failed(method, cr3, failure.status, failure.stage, &failure)
        }
    }
}

fn translate_gva_cr3_switch(
    method: u32,
    cr3: u64,
    gva: u64,
    process_id: u32,
) -> TranslateGvaResponse {
    match crate::paging::gva_to_gpa_cr3_switch(cr3, gva) {
        Ok(gpa) => {
            eprintln!(
                "translate_gva: cr3-switch ok pid={process_id} gva={gva:#x} gpa={gpa:#x}"
            );
            TranslateGvaResponse {
                success: 1,
                walk_level: 0,
                fail_stage: 0,
                method: method as u8,
                status: 0,
                used_cr3: cr3,
                pml4e_pa: 0,
                pdpe_pa: 0,
                pde_pa: 0,
                pte_pa: 0,
                gpa,
                hpa: crate::paging::gpa_to_hpa(gpa),
            }
        }
        Err(status) => {
            eprintln!(
                "translate_gva: cr3-switch failed pid={process_id} gva={gva:#x} cr3={cr3:#x} status={status:#010x}"
            );
            let failure = crate::paging::cr3_switch_failure(status);
            translate_gva_failed(method, cr3, failure.status, failure.stage, &failure)
        }
    }
}

fn translate_gva_failed(
    method: u32,
    used_cr3: u64,
    status: NTSTATUS,
    fail_stage: u8,
    failure: &crate::paging::WalkFailure,
) -> TranslateGvaResponse {
    TranslateGvaResponse {
        success: 0,
        walk_level: 0,
        fail_stage,
        method: method as u8,
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
    eprintln!(
        "IOCTL_TRANSLATE_GVA: pid={} method={} cr3={:#x} gva={:#x}",
        request.process_id,
        request.method,
        request.cr3,
        request.gva
    );
    let response = translate_gva(request.process_id, request.method, request.cr3, request.gva);
    if response.success != 0 {
        eprintln!(
            "IOCTL_TRANSLATE_GVA ok: gpa={:#x} hpa={:#x}",
            response.gpa,
            response.hpa
        );
    } else {
        eprintln!(
            "IOCTL_TRANSLATE_GVA failed: stage={} ({}) status={:#010x}",
            response.fail_stage,
            translate_fail_stage(response.fail_stage),
            response.status as u32
        );
    }
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
    eprintln!(
        "IOCTL_READ_GVA: pid={} cr3={:#x} gva={:#x} size={size}",
        request.process_id,
        request.cr3,
        request.gva
    );
    if size == 0 || size > MEM_IO_MAX_LEN {
        eprintln!("IOCTL_READ_GVA: invalid size={size}");
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }

    let translation = translate_gva(
        request.process_id,
        TRANSLATE_METHOD_PAGE_WALK,
        request.cr3,
        request.gva,
    );
    if translation.success == 0 {
        eprintln!(
            "IOCTL_READ_GVA: translate failed stage={} ({})",
            translation.fail_stage,
            translate_fail_stage(translation.fail_stage)
        );
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    if crate::paging::read_hpa(translation.hpa, system_buffer, size).is_err() {
        eprintln!(
            "IOCTL_READ_GVA: read_hpa failed hpa={:#x} size={size}",
            translation.hpa
        );
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    eprintln!(
        "IOCTL_READ_GVA ok: hpa={:#x} size={size}",
        translation.hpa
    );

    unsafe { complete_request(irp, STATUS_SUCCESS, size) }
}

fn handle_ioctl_write_physical(
    irp: *mut IRP,
    input_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<PhysMemIoRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe {
        system_buffer
            .cast::<PhysMemIoRequest>()
            .read_unaligned()
    };
    let size = request.size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if input_len < size_of::<PhysMemIoRequest>() + size {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }

    let data = unsafe { system_buffer.add(size_of::<PhysMemIoRequest>()) };
    eprintln!(
        "IOCTL_WRITE_PHYSICAL: hpa={:#x} size={size}",
        request.address
    );
    if crate::paging::write_hpa(request.address, data, size).is_err() {
        eprintln!(
            "IOCTL_WRITE_PHYSICAL failed: hpa={:#x} size={size}",
            request.address
        );
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    eprintln!("IOCTL_WRITE_PHYSICAL ok");

    unsafe { complete_request(irp, STATUS_SUCCESS, 0) }
}

fn handle_ioctl_ept_hook2(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<EptHook2Request>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size_of::<EptHook2Response>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe { system_buffer.cast::<EptHook2Request>().read_unaligned() };
    eprintln!(
        "IOCTL_EPT_HOOK2: pid={} syscall={} target={:#x} hook={:#x}",
        request.process_id,
        request.syscall_number,
        request.target_gva,
        request.hook_gva
    );
    let response = crate::ept_hook::install(
        request.process_id,
        request.syscall_number,
        request.target_gva,
        request.hook_gva,
    );
    if response.success != 0 {
        eprintln!(
            "IOCTL_EPT_HOOK2 ok: patched_len={} trampoline={:#x} target_gpa={:#x}",
            response.patched_len,
            response.trampoline_gva,
            response.target_gpa
        );
    } else {
        eprintln!(
            "IOCTL_EPT_HOOK2 failed: err={} ({})",
            response.error_code,
            ept_hook_err_name(response.error_code)
        );
    }
    unsafe {
        system_buffer
            .cast::<EptHook2Response>()
            .write_unaligned(response);
    }

    if response.success == 0 {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, size_of::<EptHook2Response>()) };
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<EptHook2Response>()) }
}

fn handle_ioctl_get_ssdt(
    irp: *mut IRP,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if output_len < size_of::<GetSsdtResponse>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let response = crate::ssdt::get_ssdt_info();
    if response.success != 0 {
        eprintln!(
            "IOCTL_GET_SSDT ok: ntos={:#x} ksd={:#x} table={:#x} count={} shadow={:#x}",
            response.ntoskrnl_base,
            response.ke_service_descriptor_table,
            response.service_table_base,
            response.number_of_services,
            response.ke_service_descriptor_table_shadow
        );
    } else {
        eprintln!(
            "IOCTL_GET_SSDT failed: err={} ({})",
            response.error_code,
            ssdt_err_name(response.error_code)
        );
    }
    unsafe {
        system_buffer
            .cast::<GetSsdtResponse>()
            .write_unaligned(response);
    }
    if response.success == 0 {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, size_of::<GetSsdtResponse>()) };
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<GetSsdtResponse>()) }
}

fn handle_ioctl_get_ssdt_function(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<GetSsdtFunctionRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size_of::<GetSsdtFunctionResponse>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe {
        system_buffer
            .cast::<GetSsdtFunctionRequest>()
            .read_unaligned()
    };
    let name = c_str_preview(&request.name);
    eprintln!("IOCTL_GET_SSDT_FUNCTION: name={name}");
    let response = crate::ssdt::resolve_ssdt_function(&request.name);
    if response.success != 0 {
        eprintln!(
            "IOCTL_GET_SSDT_FUNCTION ok: export={:#x} fn={:#x} syscall={}",
            response.export_address,
            response.function_address,
            response.syscall_number
        );
    } else {
        eprintln!(
            "IOCTL_GET_SSDT_FUNCTION failed: err={} ({})",
            response.error_code,
            ssdt_err_name(response.error_code)
        );
    }
    unsafe {
        system_buffer
            .cast::<GetSsdtFunctionResponse>()
            .write_unaligned(response);
    }
    if response.success == 0 {
        return unsafe {
            complete_request(irp, STATUS_UNSUCCESSFUL, size_of::<GetSsdtFunctionResponse>())
        };
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<GetSsdtFunctionResponse>()) }
}

fn handle_ioctl_ept_unhook(
    irp: *mut IRP,
    input_len: usize,
    output_len: usize,
    system_buffer: *mut u8,
) -> NTSTATUS {
    if input_len < size_of::<EptUnhookRequest>() {
        return unsafe { complete_request(irp, STATUS_INVALID_PARAMETER, 0) };
    }
    if output_len < size_of::<u8>() {
        return unsafe { complete_request(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    if system_buffer.is_null() {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, 0) };
    }

    let request = unsafe { system_buffer.cast::<EptUnhookRequest>().read_unaligned() };
    eprintln!(
        "IOCTL_EPT_UNHOOK: pid={} target={:#x}",
        request.process_id,
        request.target_gva
    );
    let error_code = crate::ept_hook::uninstall(request);
    if error_code != 0 {
        eprintln!(
            "IOCTL_EPT_UNHOOK failed: err={error_code} ({})",
            ept_hook_err_name(error_code)
        );
    } else {
        eprintln!("IOCTL_EPT_UNHOOK ok");
    }
    unsafe {
        system_buffer.write_unaligned(error_code);
    }

    if error_code != 0 {
        return unsafe { complete_request(irp, STATUS_UNSUCCESSFUL, size_of::<u8>()) };
    }
    unsafe { complete_request(irp, STATUS_SUCCESS, size_of::<u8>()) }
}

extern "C" fn driver_unload(driver: *mut DRIVER_OBJECT) {
    eprintln!("win_hv unload: removing all EPT hooks");
    crate::ept_hook::uninstall_all();
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
