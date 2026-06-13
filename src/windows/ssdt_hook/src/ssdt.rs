//! SSDT resolution for ntoskrnl syscall handlers on x64 Windows.

use core::ffi::c_void;

use wdk_sys::{
    NTSTATUS, NT_SUCCESS, STATUS_NOT_FOUND, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

const SYSTEM_MODULE_INFORMATION: u32 = 11;
const POOL_TAG: u32 = u32::from_ne_bytes(*b"Ssdt");
/// Upper bound for `RTL_PROCESS_MODULES.NumberOfModules` sanity checks.
const MAX_MODULE_COUNT: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemModuleEntry {
    section: *mut c_void,
    mapped_base: *mut c_void,
    image_base: *mut c_void,
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    offset_to_file_name: u16,
    full_path_name: [u8; 256],
}

#[repr(C)]
struct ServiceDescriptorEntry {
    service_table_base: *const u32,
    counter_table_base: *const u32,
    number_of_services: u32,
    argument_table: *const u8,
}

unsafe extern "system" {
    fn ZwQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
    fn MmGetSystemRoutineAddress(system_routine_name: *mut UNICODE_STRING) -> *mut c_void;
    fn RtlInitUnicodeString(destination: *mut UNICODE_STRING, source: *const u16);
}

/// Returns the kernel VA for an exported routine (e.g. `NtOpenProcess`).
pub(crate) fn kernel_routine_address(export_name: &str) -> Option<usize> {
    kernel_export(export_name)
}

/// Resolves the kernel VA of an ntoskrnl SSDT handler by export name.
///
/// Uses `MmGetSystemRoutineAddress` as ground truth, then locates the matching
/// SSDT entry so the hook is tied to the syscall dispatch table.
pub(crate) fn resolve_ssdt_function(export_name: &str) -> Result<usize, NTSTATUS> {
    let expected = kernel_export(export_name).ok_or(STATUS_NOT_FOUND)?;
    let (ntoskrnl_base, ntoskrnl_size) = ntoskrnl_image()?;
    let sdt = find_service_descriptor_table(ntoskrnl_base, ntoskrnl_size)?;
    let entry = unsafe { sdt.read() };
    if entry.service_table_base.is_null() || entry.number_of_services == 0 {
        return Err(STATUS_NOT_FOUND);
    }

    for syscall_number in 0..entry.number_of_services {
        let Ok(address) = function_from_ssdt(sdt, syscall_number) else {
            continue;
        };
        if address == expected {
            crate::eprintln!(
                "SSDT match: {export_name} syscall={syscall_number} va={address:#x}"
            );
            return Ok(address);
        }
    }

    crate::eprintln!(
        "SSDT: no entry matched {export_name} at {expected:#x} (ntos {ntoskrnl_base:p} size {ntoskrnl_size:#x})"
    );
    Err(STATUS_NOT_FOUND)
}

fn kernel_export(name: &str) -> Option<usize> {
    let mut wide = [0u16; 64];
    encode_wide(name, &mut wide);
    let mut unicode = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&raw mut unicode, wide.as_ptr()) };
    let address = unsafe { MmGetSystemRoutineAddress(&raw mut unicode) };
    if address.is_null() {
        None
    } else {
        Some(address as usize)
    }
}

fn function_from_ssdt(sdt: *const ServiceDescriptorEntry, syscall_number: u32) -> Result<usize, NTSTATUS> {
    let entry = unsafe { sdt.read() };
    if syscall_number >= entry.number_of_services {
        return Err(STATUS_NOT_FOUND);
    }
    let table = entry.service_table_base;
    if table.is_null() {
        return Err(STATUS_NOT_FOUND);
    }
    let encoded = unsafe { table.add(syscall_number as usize).read() };
    let offset = (encoded as i32) >> 4;
    if offset == 0 {
        return Err(STATUS_NOT_FOUND);
    }
    Ok(table.cast::<u8>().wrapping_add(offset as usize) as usize)
}

fn ntoskrnl_image() -> Result<(*const u8, u32), NTSTATUS> {
    let buffer = query_module_list()?;
    let count = unsafe { buffer.cast::<u32>().read() } as usize;
    if count == 0 || count > MAX_MODULE_COUNT {
        pool_free(buffer);
        return Err(STATUS_NOT_FOUND);
    }
    // `RTL_PROCESS_MODULES.Modules[0]` is 8-byte aligned on x64.
    let entries = unsafe {
        core::slice::from_raw_parts(
            buffer.add(8).cast::<SystemModuleEntry>(),
            count,
        )
    };

    for module in entries {
        let name = module_file_name(module);
        if name.eq_ignore_ascii_case("ntoskrnl.exe") || name.starts_with("ntoskrnl") {
            let base = module.image_base as *const u8;
            pool_free(buffer);
            return Ok((base, module.image_size));
        }
    }

    pool_free(buffer);
    Err(STATUS_NOT_FOUND)
}

fn module_file_name(module: &SystemModuleEntry) -> &str {
    let offset = module.offset_to_file_name as usize;
    if offset >= module.full_path_name.len() {
        return "";
    }
    let bytes = &module.full_path_name[offset..];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

fn query_module_list() -> Result<*mut u8, NTSTATUS> {
    let mut needed = 0u32;
    let status = unsafe {
        ZwQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            core::ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    if needed == 0 {
        return Err(status);
    }

    let buffer = pool_alloc(needed as usize)?;
    let status = unsafe {
        ZwQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            buffer.cast(),
            needed,
            &raw mut needed,
        )
    };
    if !NT_SUCCESS(status) {
        pool_free(buffer);
        return Err(status);
    }
    Ok(buffer)
}

fn find_service_descriptor_table(
    base: *const u8,
    size: u32,
) -> Result<*const ServiceDescriptorEntry, NTSTATUS> {
    let end = size.saturating_sub(16) as usize;
    let mut offset = 0usize;
    while offset < end {
        if matches_ke_service_descriptor_table(base, offset) {
            let disp = i32::from_le_bytes([
                unsafe { *base.add(offset + 3) },
                unsafe { *base.add(offset + 4) },
                unsafe { *base.add(offset + 5) },
                unsafe { *base.add(offset + 6) },
            ]);
            let sdt_offset = offset.wrapping_add(7).wrapping_add(disp as usize);
            if sdt_offset < size as usize {
                let candidate = base.wrapping_add(sdt_offset) as *const ServiceDescriptorEntry;
                if validate_service_descriptor(candidate, base, size) {
                    return Ok(candidate);
                }
            }
        }
        offset += 1;
    }
    Err(STATUS_NOT_FOUND)
}

fn matches_ke_service_descriptor_table(base: *const u8, offset: usize) -> bool {
    unsafe {
        *base.add(offset) == 0x4C
            && *base.add(offset + 1) == 0x8D
            && *base.add(offset + 2) == 0x15
            && *base.add(offset + 7) == 0x4C
            && *base.add(offset + 8) == 0x8D
            && *base.add(offset + 9) == 0x1D
            && *base.add(offset + 10) == 0xF7
    }
}

fn validate_service_descriptor(
    sdt: *const ServiceDescriptorEntry,
    ntos_base: *const u8,
    ntos_size: u32,
) -> bool {
    let entry = unsafe { sdt.read() };
    let table = entry.service_table_base;
    if table.is_null() {
        return false;
    }
    let table_addr = table as usize;
    let ntos_start = ntos_base as usize;
    let ntos_end = ntos_start + ntos_size as usize;
    if table_addr < ntos_start || table_addr >= ntos_end {
        return false;
    }
    // ntoskrnl exports a few hundred system services.
    (0x80..0x3000).contains(&entry.number_of_services)
}

fn encode_wide(input: &str, out: &mut [u16]) {
    let mut index = 0usize;
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

fn pool_alloc(size: usize) -> Result<*mut u8, NTSTATUS> {
    let ptr = unsafe {
        wdk_sys::ntddk::ExAllocatePool2(wdk_sys::POOL_FLAG_NON_PAGED, size as _, POOL_TAG)
    };
    if ptr.is_null() {
        Err(STATUS_UNSUCCESSFUL)
    } else {
        Ok(ptr.cast())
    }
}

fn pool_free(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { wdk_sys::ntddk::ExFreePoolWithTag(ptr.cast(), POOL_TAG) };
    }
}
