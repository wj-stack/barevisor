//! SSDT resolution for ntoskrnl syscall handlers on x64 Windows.
//!
//! Locates `KeServiceDescriptorTable` / `KeServiceDescriptorTableShadow` by scanning
//! ntoskrnl `.text` for the `KiSystemServiceRepeat` instruction pattern (HyperDbg /
//! TitanHide approach).

use core::ffi::c_void;

use shared_contract::{
    GetSsdtFunctionResponse, GetSsdtResponse, SSDT_ERR_EXPORT, SSDT_ERR_NAME, SSDT_ERR_NO_MATCH,
    SSDT_ERR_NOT_FOUND, SSDT_FUNCTION_NAME_MAX,
};
use wdk_sys::{
    NTSTATUS, NT_SUCCESS, STATUS_NOT_FOUND, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

const SYSTEM_MODULE_INFORMATION: u32 = 11;
const POOL_TAG: u32 = u32::from_ne_bytes(*b"Ssdt");
const MAX_MODULE_COUNT: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct ServiceDescriptorEntry {
    service_table_base: *const u32,
    counter_table_base: *const u32,
    number_of_services: u32,
    argument_table: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SsdtTables {
    ke_service_descriptor_table: *const ServiceDescriptorEntry,
    ke_service_descriptor_table_shadow: *const ServiceDescriptorEntry,
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

/// Fills [`GetSsdtResponse`] with native and shadow SSDT table addresses.
pub(crate) fn get_ssdt_info() -> GetSsdtResponse {
    let mut response = GetSsdtResponse::default();
    let Ok((ntoskrnl_base, ntoskrnl_size)) = ntoskrnl_image() else {
        response.error_code = SSDT_ERR_NOT_FOUND;
        return response;
    };
    let Ok(tables) = find_ssdt_tables(ntoskrnl_base, ntoskrnl_size) else {
        response.error_code = SSDT_ERR_NOT_FOUND;
        response.ntoskrnl_base = ntoskrnl_base as u64;
        response.ntoskrnl_size = ntoskrnl_size;
        return response;
    };

    let native = unsafe { tables.ke_service_descriptor_table.read() };
    let shadow0 = unsafe { tables.ke_service_descriptor_table_shadow.read() };
    let shadow1 = unsafe { tables.ke_service_descriptor_table_shadow.add(1).read() };

    response.success = 1;
    response.ntoskrnl_base = ntoskrnl_base as u64;
    response.ntoskrnl_size = ntoskrnl_size;
    response.ke_service_descriptor_table = tables.ke_service_descriptor_table as u64;
    response.service_table_base = native.service_table_base as u64;
    response.number_of_services = native.number_of_services;
    response.ke_service_descriptor_table_shadow =
        tables.ke_service_descriptor_table_shadow as u64;
    response.shadow_service_table_base = shadow0.service_table_base as u64;
    response.shadow_number_of_services = shadow0.number_of_services;
    response.win32k_service_table_base = shadow1.service_table_base as u64;
    response.win32k_number_of_services = shadow1.number_of_services;
    response
}

/// Resolves an ntoskrnl SSDT handler by export name.
pub(crate) fn resolve_ssdt_function(name: &[u8]) -> GetSsdtFunctionResponse {
    let mut response = GetSsdtFunctionResponse::default();
    let Some(export_name) = c_str_to_str(name) else {
        response.error_code = SSDT_ERR_NAME;
        return response;
    };
    let Some(expected) = kernel_export(export_name) else {
        response.error_code = SSDT_ERR_EXPORT;
        return response;
    };
    response.export_address = expected as u64;

    let Ok((ntoskrnl_base, ntoskrnl_size)) = ntoskrnl_image() else {
        response.error_code = SSDT_ERR_NOT_FOUND;
        return response;
    };
    let Ok(tables) = find_ssdt_tables(ntoskrnl_base, ntoskrnl_size) else {
        response.error_code = SSDT_ERR_NOT_FOUND;
        return response;
    };

    let sdt = tables.ke_service_descriptor_table;
    let entry = unsafe { sdt.read() };
    if entry.service_table_base.is_null() || entry.number_of_services == 0 {
        response.error_code = SSDT_ERR_NOT_FOUND;
        return response;
    }

    for syscall_number in 0..entry.number_of_services {
        let Ok(address) = function_from_ssdt(sdt, syscall_number) else {
            continue;
        };
        if address == expected {
            response.success = 1;
            response.syscall_number = syscall_number;
            response.function_address = address as u64;
            return response;
        }
    }

    response.error_code = SSDT_ERR_NO_MATCH;
    response
}

fn c_str_to_str(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 || end > SSDT_FUNCTION_NAME_MAX {
        return None;
    }
    core::str::from_utf8(&bytes[..end]).ok()
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

fn function_from_ssdt(
    sdt: *const ServiceDescriptorEntry,
    syscall_number: u32,
) -> Result<usize, NTSTATUS> {
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
    let entries = unsafe {
        core::slice::from_raw_parts(buffer.add(8).cast::<SystemModuleEntry>(), count)
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

/// Returns `(text_va, text_size)` for the ntoskrnl `.text` section (TitanHide / HyperDbg).
fn ntoskrnl_text_range(base: *const u8, image_size: u32) -> Result<(*const u8, usize), NTSTATUS> {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
    const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
    const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;

    let image_size = image_size as usize;
    if image_size < 0x200 {
        return Err(STATUS_NOT_FOUND);
    }
    if read_u16(base, 0) != IMAGE_DOS_SIGNATURE {
        return Err(STATUS_NOT_FOUND);
    }
    let e_lfanew = read_u32(base, 0x3C) as usize;
    if e_lfanew >= image_size.saturating_sub(0x108) {
        return Err(STATUS_NOT_FOUND);
    }

    unsafe {
        let nt = base.add(e_lfanew);
        if read_u32(nt, 0) != IMAGE_NT_SIGNATURE {
            return Err(STATUS_NOT_FOUND);
        }

        let file_header = nt.add(4);
        let number_of_sections = read_u16(file_header, 2) as usize;
        if number_of_sections == 0 || number_of_sections > 96 {
            return Err(STATUS_NOT_FOUND);
        }
        let size_of_optional_header = read_u16(file_header, 16) as usize;
        let first_section = file_header.add(20 + size_of_optional_header);
        let sections_end = first_section.add(number_of_sections * IMAGE_SIZEOF_SECTION_HEADER);
        if sections_end > base.add(image_size) {
            return Err(STATUS_NOT_FOUND);
        }

        for index in 0..number_of_sections {
            let section = first_section.add(index * IMAGE_SIZEOF_SECTION_HEADER);
            if !section_name_eq(section, b".text\0\0\0") {
                continue;
            }
            let virtual_size = read_u32(section, 8) as usize;
            let virtual_address = read_u32(section, 12) as usize;
            if virtual_address >= image_size {
                return Err(STATUS_NOT_FOUND);
            }
            let available = image_size - virtual_address;
            let text_size = core::cmp::min(virtual_size, available);
            if text_size < 32 {
                return Err(STATUS_NOT_FOUND);
            }
            return Ok((base.add(virtual_address), text_size));
        }
    }

    Err(STATUS_NOT_FOUND)
}

fn section_name_eq(section: *const u8, expected: &[u8; 8]) -> bool {
    let mut name = [0u8; 8];
    for (index, byte) in name.iter_mut().enumerate() {
        *byte = unsafe { *section.add(index) };
    }
    name == *expected
}

fn read_u16(base: *const u8, offset: usize) -> u16 {
    u16::from_le_bytes([
        unsafe { *base.add(offset) },
        unsafe { *base.add(offset + 1) },
    ])
}

fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le_bytes([
        unsafe { *base.add(offset) },
        unsafe { *base.add(offset + 1) },
        unsafe { *base.add(offset + 2) },
        unsafe { *base.add(offset + 3) },
    ])
}

fn in_image_range(ntos_base: *const u8, image_size: u32, address: *const u8) -> bool {
    let start = ntos_base as usize;
    let end = start.saturating_add(image_size as usize);
    let addr = address as usize;
    (start..end).contains(&addr)
}

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

fn find_ssdt_tables(base: *const u8, size: u32) -> Result<SsdtTables, NTSTATUS> {
    let (text, text_size) = ntoskrnl_text_range(base, size)?;
    // `matches_ki_system_service_repeat` reads through offset + 13.
    let scan_limit = text_size.saturating_sub(14);
    let mut offset = 0usize;
    while offset < scan_limit {
        if matches_ki_system_service_repeat(text, offset, text_size) {
            let native_disp = read_i32(text, offset + 3, text_size)?;
            let native_rip = unsafe { text.add(offset + 7) };
            let native_sdt = unsafe { native_rip.offset(native_disp as isize) };
            if !in_image_range(base, size, native_sdt)
                || !validate_service_descriptor(
                    native_sdt.cast(),
                    base,
                    size,
                )
            {
                offset += 1;
                continue;
            }

            let shadow_disp = read_i32(text, offset + 10, text_size)?;
            let shadow_rip = unsafe { text.add(offset + 14) };
            let shadow_sdt = unsafe { shadow_rip.offset(shadow_disp as isize) };
            if !in_image_range(base, size, shadow_sdt)
                || !validate_service_descriptor(shadow_sdt.cast(), base, size)
            {
                offset += 1;
                continue;
            }

            return Ok(SsdtTables {
                ke_service_descriptor_table: native_sdt.cast(),
                ke_service_descriptor_table_shadow: shadow_sdt.cast(),
            });
        }
        offset += 1;
    }
    Err(STATUS_NOT_FOUND)
}

fn read_i32(base: *const u8, offset: usize, limit: usize) -> Result<i32, NTSTATUS> {
    if offset + 4 > limit {
        return Err(STATUS_NOT_FOUND);
    }
    Ok(i32::from_le_bytes([
        unsafe { *base.add(offset) },
        unsafe { *base.add(offset + 1) },
        unsafe { *base.add(offset + 2) },
        unsafe { *base.add(offset + 3) },
    ]))
}

fn matches_ki_system_service_repeat(base: *const u8, offset: usize, limit: usize) -> bool {
    if offset + 13 >= limit {
        return false;
    }
    unsafe {
        *base.add(offset) == 0x4C
            && *base.add(offset + 1) == 0x8D
            && *base.add(offset + 2) == 0x15
            && *base.add(offset + 7) == 0x4C
            && *base.add(offset + 8) == 0x8D
            && *base.add(offset + 9) == 0x1D
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
