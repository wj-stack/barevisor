#![no_std]

//! Clears kernel driver load/unload traces (PiDDB, MmUnloadedDrivers, CI hash cache).

use core::ffi::c_void;

use wdk_sys::{NTSTATUS, NT_SUCCESS, STATUS_NOT_FOUND, STATUS_UNSUCCESSFUL, UNICODE_STRING};

const SYSTEM_MODULE_INFORMATION: u32 = 11;
const POOL_TAG: u32 = u32::from_ne_bytes(*b"Trce");
const MAX_MODULE_COUNT: usize = 4096;
const MAX_UNLOADED_DRIVERS: u32 = 50;

/// Per-stage results from [`clear_driver_traces`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClearTraceResult {
    /// PiDDBCacheTable entry removed.
    pub piddb: bool,
    /// Matching MmUnloadedDrivers entry obfuscated.
    pub unloaded: bool,
    /// g_KernelHashBucketList entry removed.
    pub hash_bucket: bool,
    /// g_CiEaCacheLookasideList reinitialized.
    pub ci_ea_cache: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PiddbCacheEntry {
    list: ListEntry,
    name: UNICODE_STRING,
    stamp: u32,
    status: NTSTATUS,
    _padding: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnloaderInformation {
    name: UNICODE_STRING,
    module_start: *mut c_void,
    module_end: *mut c_void,
    unload_time: u64,
}

#[repr(C)]
struct HashBucketEntry {
    next: *mut HashBucketEntry,
    name: UNICODE_STRING,
    hash: [u32; 5],
}

#[repr(C)]
struct RtlAvlTable {
    _opaque: [u8; 0x68],
    delete_count: u32,
}

#[repr(C)]
struct LookasideListEx {
    _list: [u8; 0x10],
    size: u32,
    _rest: [u8; 0x20],
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

unsafe extern "system" {
    fn ZwQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
    fn ExAcquireResourceExclusiveLite(resource: *mut c_void, wait: u8) -> u8;
    fn ExReleaseResourceLite(resource: *mut c_void);
    fn RtlLookupElementGenericTableAvl(table: *mut c_void, buffer: *const c_void) -> *mut c_void;
    fn RtlEnumerateGenericTableAvl(table: *mut c_void, restart: u8) -> *mut c_void;
    fn RtlDeleteElementGenericTableAvl(table: *mut c_void, buffer: *const c_void) -> u8;
    fn RtlInitUnicodeString(destination: *mut UNICODE_STRING, source: *const u16);
    fn MmIsAddressValid(virtual_address: *const c_void) -> u8;
    fn ExDeleteLookasideListEx(lookaside: *mut c_void);
    fn ExInitializeLookasideListEx(
        lookaside: *mut c_void,
        allocate: *const c_void,
        free: *const c_void,
        pool_type: u32,
        flags: u32,
        size: u32,
        tag: u32,
        depth: u16,
    ) -> NTSTATUS;
    fn ExFreePoolWithTag(p: *mut c_void, tag: u32);
}

/// Clears PiDDB, unloaded-driver, CI hash-bucket, and CI EA cache traces for `driver_name`.
pub fn clear_driver_traces(driver_name: &str, stamp: u32) -> ClearTraceResult {
    let mut result = ClearTraceResult::default();
    result.piddb = clear_piddb_cache(driver_name, stamp);
    result.unloaded = clear_unloaded_driver(driver_name);
    result.hash_bucket = clear_hash_bucket_list(driver_name);
    result.ci_ea_cache = clear_ci_ea_cache_lookaside_list();
    result
}

/// Per-stage query results from [`query_driver_traces`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryTraceResult {
    /// PiDDB status ([`TRACE_ABSENT`], [`TRACE_PRESENT`], [`TRACE_SCAN_FAILED`]).
    pub piddb: u8,
    /// MmUnloadedDrivers status.
    pub unloaded: u8,
    /// g_KernelHashBucketList status.
    pub hash_bucket: u8,
    /// g_CiEaCacheLookasideList scan status.
    pub ci_ea: u8,
    /// PiDDB stamp when `piddb == TRACE_PRESENT`.
    pub piddb_stamp: u32,
    /// MmUnloadedDrivers slot when `unloaded == TRACE_PRESENT`.
    pub unloaded_slot: u32,
}

/// Status codes shared with [`shared_contract`].
pub const TRACE_ABSENT: u8 = 0;
/// Driver trace is present in the structure.
pub const TRACE_PRESENT: u8 = 1;
/// Structure scan failed (pattern/module not found on this OS build).
pub const TRACE_SCAN_FAILED: u8 = 2;

/// Queries PiDDB, unloaded-driver, CI hash-bucket, and CI EA cache for `driver_name`.
pub fn query_driver_traces(driver_name: &str, stamp: u32) -> QueryTraceResult {
    let (piddb, piddb_stamp) = query_piddb_cache(driver_name, stamp);
    let (unloaded, unloaded_slot) = query_unloaded_driver(driver_name);
    let hash_bucket = query_hash_bucket_list(driver_name);
    let ci_ea = query_ci_ea_cache_lookaside_list();
    QueryTraceResult {
        piddb,
        unloaded,
        hash_bucket,
        ci_ea,
        piddb_stamp,
        unloaded_slot,
    }
}

fn query_piddb_cache(driver_name: &str, stamp: u32) -> (u8, u32) {
    let Ok((ntos_base, ntos_size)) = module_image("ntoskrnl.exe") else {
        return (TRACE_SCAN_FAILED, 0);
    };

    let Some(piddb_lock_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x4C, 0x8B, 0x8C],
        b"xxx????x????xxx",
    ) else {
        return (TRACE_SCAN_FAILED, 0);
    };
    let piddb_lock = resolve_rip_relative(piddb_lock_match, 3, 7);
    if !in_image_range(ntos_base, ntos_size, piddb_lock) {
        return (TRACE_SCAN_FAILED, 0);
    }

    let Some(piddb_table_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D],
        b"xxxxxx",
    ) else {
        return (TRACE_SCAN_FAILED, 0);
    };
    let piddb_table = resolve_rip_relative(piddb_table_match.wrapping_add(3), 3, 7);
    if !in_image_range(ntos_base, ntos_size, piddb_table) {
        return (TRACE_SCAN_FAILED, 0);
    }

    let wide_name = driver_name_to_wide(driver_name);
    let mut found_stamp = 0u32;

    if unsafe { ExAcquireResourceExclusiveLite(piddb_lock, 1) == 0 } {
        return (TRACE_SCAN_FAILED, 0);
    }

    let status = if stamp != 0 {
        let mut lookup = PiddbCacheEntry {
            list: ListEntry {
                flink: core::ptr::null_mut(),
                blink: core::ptr::null_mut(),
            },
            name: UNICODE_STRING::default(),
            stamp,
            status: 0,
            _padding: [0; 16],
        };
        let mut wide = [0u16; 128];
        if !encode_wide(driver_name, &mut wide) {
            unsafe { ExReleaseResourceLite(piddb_lock) };
            return (TRACE_SCAN_FAILED, 0);
        }
        unsafe { RtlInitUnicodeString(&raw mut lookup.name, wide.as_ptr()) };
        let entry = unsafe {
            RtlLookupElementGenericTableAvl(piddb_table, (&raw const lookup).cast())
        };
        if entry.is_null() {
            TRACE_ABSENT
        } else {
            found_stamp = unsafe { entry.cast::<PiddbCacheEntry>().read().stamp };
            TRACE_PRESENT
        }
    } else {
        let mut restart = 1u8;
        let mut status = TRACE_ABSENT;
        loop {
            let entry = unsafe { RtlEnumerateGenericTableAvl(piddb_table, restart) };
            restart = 0;
            if entry.is_null() {
                break;
            }
            let entry = unsafe { entry.cast::<PiddbCacheEntry>().read() };
            if unicode_contains(entry.name.Buffer, entry.name.Length, &wide_name) {
                found_stamp = entry.stamp;
                status = TRACE_PRESENT;
                break;
            }
        }
        status
    };

    unsafe { ExReleaseResourceLite(piddb_lock) };
    (status, found_stamp)
}

fn query_unloaded_driver(driver_name: &str) -> (u8, u32) {
    let Ok((ntos_base, ntos_size)) = module_image("ntoskrnl.exe") else {
        return (TRACE_SCAN_FAILED, 0);
    };

    let Some(mm_unloaded_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x4C, 0x8B, 0x15, 0, 0, 0, 0, 0x4C, 0x8B, 0xC9],
        b"xxx????xxx",
    ) else {
        return (TRACE_SCAN_FAILED, 0);
    };
    let mm_unloaded = resolve_rip_relative(mm_unloaded_match, 3, 7);
    if !in_image_range(ntos_base, ntos_size, mm_unloaded) {
        return (TRACE_SCAN_FAILED, 0);
    }

    let Some(mm_last_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x8B, 0x05, 0, 0, 0, 0, 0x83, 0xF8, 0x32],
        b"xx????xxx",
    ) else {
        return (TRACE_SCAN_FAILED, 0);
    };
    let mm_last = resolve_rip_relative(mm_last_match, 2, 6);
    if !in_image_range(ntos_base, ntos_size, mm_last) {
        return (TRACE_SCAN_FAILED, 0);
    }

    let unloaders = unsafe { *(mm_unloaded as *const *mut UnloaderInformation) };
    let unloaders_count = unsafe { *(mm_last as *const u32) };
    if unloaders.is_null()
        || unsafe { MmIsAddressValid(unloaders.cast()) == 0 }
        || unsafe { MmIsAddressValid(mm_last) == 0 }
    {
        return (TRACE_SCAN_FAILED, 0);
    }

    let wide_name = driver_name_to_wide(driver_name);
    let limit = core::cmp::min(unloaders_count, MAX_UNLOADED_DRIVERS);
    for index in 0..limit {
        let entry = unsafe { unloaders.add(index as usize) };
        if unsafe { MmIsAddressValid(entry.cast()) == 0 } {
            continue;
        }
        let info = unsafe { *entry };
        if info.name.Buffer.is_null() || info.name.Length == 0 {
            continue;
        }
        if unicode_contains(info.name.Buffer, info.name.Length, &wide_name) {
            return (TRACE_PRESENT, index);
        }
    }
    (TRACE_ABSENT, 0)
}

fn query_hash_bucket_list(driver_name: &str) -> u8 {
    let Ok((ci_base, ci_size)) = module_image("CI.dll") else {
        return TRACE_SCAN_FAILED;
    };

    let Some(kernel_hash_match) = find_pattern_image(
        ci_base,
        ci_size,
        &[
            0x48, 0x8B, 0x1D, 0, 0, 0, 0, 0xEB, 0, 0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00,
        ],
        b"xxx????x?xxxxxxx",
    ) else {
        return TRACE_SCAN_FAILED;
    };
    let hash_cache_lock_match = kernel_hash_match.wrapping_sub(0x13);
    let kernel_hash_bucket_list = resolve_rip_relative(kernel_hash_match, 3, 7);
    let hash_cache_lock = resolve_rip_relative(hash_cache_lock_match, 3, 7);
    if !in_image_range(ci_base, ci_size, kernel_hash_bucket_list)
        || !in_image_range(ci_base, ci_size, hash_cache_lock)
    {
        return TRACE_SCAN_FAILED;
    }

    let wide_name = driver_name_to_wide(driver_name);
    if unsafe { ExAcquireResourceExclusiveLite(hash_cache_lock, 1) == 0 } {
        return TRACE_SCAN_FAILED;
    }

    let head = kernel_hash_bucket_list as *mut HashBucketEntry;
    let mut current = unsafe { (*head).next };
    let mut status = TRACE_ABSENT;
    while !current.is_null() {
        let name = unsafe { (*current).name };
        if !name.Buffer.is_null() && unicode_contains(name.Buffer, name.Length, &wide_name) {
            status = TRACE_PRESENT;
            break;
        }
        current = unsafe { (*current).next };
    }

    unsafe { ExReleaseResourceLite(hash_cache_lock) };
    status
}

fn query_ci_ea_cache_lookaside_list() -> u8 {
    let Ok((ci_base, ci_size)) = module_image("CI.dll") else {
        return TRACE_SCAN_FAILED;
    };

    let Some(ci_ea_match) = find_pattern_image(
        ci_base,
        ci_size,
        &[
            0x8B, 0x15, 0, 0, 0, 0, 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x44, 0x8B, 0x05, 0, 0, 0, 0,
            0x8B, 0x0D, 0, 0, 0, 0, 0xFF, 0x05, 0, 0, 0, 0, 0xFF, 0x15,
        ],
        b"xx????xxx????xxx????xx????xx????xx",
    ) else {
        return TRACE_SCAN_FAILED;
    };
    let ci_ea_list = resolve_rip_relative(ci_ea_match.wrapping_sub(0x1B), 3, 7);
    if !in_image_range(ci_base, ci_size, ci_ea_list) {
        return TRACE_SCAN_FAILED;
    }
    if unsafe { MmIsAddressValid(ci_ea_list) == 0 } {
        return TRACE_SCAN_FAILED;
    }
    TRACE_ABSENT
}

fn remove_piddb_entry(piddb_table: *mut c_void, entry: *mut PiddbCacheEntry) -> bool {
    let prev = unsafe { (*entry).list.blink };
    let next = unsafe { (*entry).list.flink };
    if !prev.is_null() && !next.is_null() {
        unsafe {
            (*prev).flink = next;
            (*next).blink = prev;
        }
    }
    if unsafe { RtlDeleteElementGenericTableAvl(piddb_table, entry.cast()) != 0 } {
        let avl = piddb_table.cast::<RtlAvlTable>();
        unsafe {
            if (*avl).delete_count > 0 {
                (*avl).delete_count -= 1;
            }
        }
        true
    } else {
        false
    }
}

fn clear_piddb_cache(driver_name: &str, stamp: u32) -> bool {
    let Ok((ntos_base, ntos_size)) = module_image("ntoskrnl.exe") else {
        return false;
    };

    let Some(piddb_lock_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x4C, 0x8B, 0x8C],
        b"xxx????x????xxx",
    ) else {
        return false;
    };
    let piddb_lock = resolve_rip_relative(piddb_lock_match, 3, 7);
    if !in_image_range(ntos_base, ntos_size, piddb_lock) {
        return false;
    }

    let Some(piddb_table_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D],
        b"xxxxxx",
    ) else {
        return false;
    };
    let piddb_table = resolve_rip_relative(piddb_table_match.wrapping_add(3), 3, 7);
    if !in_image_range(ntos_base, ntos_size, piddb_table) {
        return false;
    }

    let mut cleared = false;
    if unsafe { ExAcquireResourceExclusiveLite(piddb_lock, 1) != 0 } {
        if stamp != 0 {
            let mut wide = [0u16; 128];
            if !encode_wide(driver_name, &mut wide) {
                unsafe { ExReleaseResourceLite(piddb_lock) };
                return false;
            }
            let mut lookup = PiddbCacheEntry {
                list: ListEntry {
                    flink: core::ptr::null_mut(),
                    blink: core::ptr::null_mut(),
                },
                name: UNICODE_STRING::default(),
                stamp,
                status: 0,
                _padding: [0; 16],
            };
            unsafe { RtlInitUnicodeString(&raw mut lookup.name, wide.as_ptr()) };
            let entry = unsafe {
                RtlLookupElementGenericTableAvl(piddb_table, (&raw const lookup).cast())
            };
            if !entry.is_null() {
                cleared = remove_piddb_entry(piddb_table, entry.cast());
            }
        } else {
            let wide_name = driver_name_to_wide(driver_name);
            loop {
                let mut restart = 1u8;
                let mut found: *mut PiddbCacheEntry = core::ptr::null_mut();
                loop {
                    let entry = unsafe { RtlEnumerateGenericTableAvl(piddb_table, restart) };
                    restart = 0;
                    if entry.is_null() {
                        break;
                    }
                    let entry_ref = unsafe { entry.cast::<PiddbCacheEntry>().read() };
                    if unicode_contains(
                        entry_ref.name.Buffer,
                        entry_ref.name.Length,
                        &wide_name,
                    ) {
                        found = entry.cast();
                        break;
                    }
                }
                if found.is_null() {
                    break;
                }
                if !remove_piddb_entry(piddb_table, found) {
                    break;
                }
                cleared = true;
            }
        }
        unsafe { ExReleaseResourceLite(piddb_lock) };
    }
    cleared
}

fn clear_unloaded_driver(driver_name: &str) -> bool {
    let Ok((ntos_base, ntos_size)) = module_image("ntoskrnl.exe") else {
        return false;
    };

    let Some(mm_unloaded_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x4C, 0x8B, 0x15, 0, 0, 0, 0, 0x4C, 0x8B, 0xC9],
        b"xxx????xxx",
    ) else {
        return false;
    };
    let mm_unloaded = resolve_rip_relative(mm_unloaded_match, 3, 7);
    if !in_image_range(ntos_base, ntos_size, mm_unloaded) {
        return false;
    }

    let Some(mm_last_match) = find_pattern_image(
        ntos_base,
        ntos_size,
        &[0x8B, 0x05, 0, 0, 0, 0, 0x83, 0xF8, 0x32],
        b"xx????xxx",
    ) else {
        return false;
    };
    let mm_last = resolve_rip_relative(mm_last_match, 2, 6);
    if !in_image_range(ntos_base, ntos_size, mm_last) {
        return false;
    }

    let unloaders = unsafe { *(mm_unloaded as *const *mut UnloaderInformation) };
    let unloaders_count = unsafe { *(mm_last as *const u32) };
    if unloaders.is_null()
        || unsafe { MmIsAddressValid(unloaders.cast()) == 0 }
        || unsafe { MmIsAddressValid(mm_last) == 0 }
    {
        return false;
    }

    let wide_name = driver_name_to_wide(driver_name);
    let mut cleared = false;
    let limit = core::cmp::min(unloaders_count, MAX_UNLOADED_DRIVERS);
    for index in 0..limit {
        let entry = unsafe { unloaders.add(index as usize) };
        if unsafe { MmIsAddressValid(entry.cast()) == 0 } {
            continue;
        }
        let info = unsafe { *entry };
        if info.name.Buffer.is_null() || info.name.Length == 0 {
            continue;
        }
        if !unicode_contains(info.name.Buffer, info.name.Length, &wide_name) {
            continue;
        }

        unsafe {
            (*entry).module_start =
                (info.module_start as usize).wrapping_add(0x1234) as *mut c_void;
            (*entry).module_end =
                (info.module_end as usize).wrapping_sub(0x123) as *mut c_void;
            (*entry).unload_time = info.unload_time.wrapping_add(0x20);
            randomize_unicode_buffer(
                (*entry).name.Buffer,
                (*entry).name.Length as usize / 2,
            );
        }
        cleared = true;
    }
    cleared
}

fn clear_hash_bucket_list(driver_name: &str) -> bool {
    let Ok((ci_base, ci_size)) = module_image("CI.dll") else {
        return false;
    };

    let Some(kernel_hash_match) = find_pattern_image(
        ci_base,
        ci_size,
        &[
            0x48, 0x8B, 0x1D, 0, 0, 0, 0, 0xEB, 0, 0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00,
        ],
        b"xxx????x?xxxxxxx",
    ) else {
        return false;
    };
    let hash_cache_lock_match = kernel_hash_match.wrapping_sub(0x13);
    let kernel_hash_bucket_list = resolve_rip_relative(kernel_hash_match, 3, 7);
    let hash_cache_lock = resolve_rip_relative(hash_cache_lock_match, 3, 7);
    if !in_image_range(ci_base, ci_size, kernel_hash_bucket_list)
        || !in_image_range(ci_base, ci_size, hash_cache_lock)
    {
        return false;
    }

    let wide_name = driver_name_to_wide(driver_name);
    let mut cleared = false;
    if unsafe { ExAcquireResourceExclusiveLite(hash_cache_lock, 1) != 0 } {
        let head = kernel_hash_bucket_list as *mut HashBucketEntry;
        let mut prev = head;
        let mut current = unsafe { (*head).next };
        while !current.is_null() {
            let name = unsafe { (*current).name };
            if !name.Buffer.is_null()
                && unicode_contains(name.Buffer, name.Length, &wide_name)
            {
                unsafe {
                    (*prev).next = (*current).next;
                    (*current).hash = [1; 5];
                    randomize_unicode_buffer(name.Buffer, name.Length as usize / 2);
                    ExFreePoolWithTag(current.cast(), 0);
                }
                cleared = true;
                break;
            }
            prev = current;
            current = unsafe { (*current).next };
        }
        unsafe { ExReleaseResourceLite(hash_cache_lock) };
    }
    cleared
}

fn clear_ci_ea_cache_lookaside_list() -> bool {
    let Ok((ci_base, ci_size)) = module_image("CI.dll") else {
        return false;
    };

    let Some(ci_ea_match) = find_pattern_image(
        ci_base,
        ci_size,
        &[
            0x8B, 0x15, 0, 0, 0, 0, 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x44, 0x8B, 0x05, 0, 0, 0, 0,
            0x8B, 0x0D, 0, 0, 0, 0, 0xFF, 0x05, 0, 0, 0, 0, 0xFF, 0x15,
        ],
        b"xx????xxx????xxx????xx????xx????xx",
    ) else {
        return false;
    };
    let ci_ea_list = resolve_rip_relative(ci_ea_match.wrapping_sub(0x1B), 3, 7);
    if !in_image_range(ci_base, ci_size, ci_ea_list) {
        return false;
    }
    let lookaside = ci_ea_list as *mut LookasideListEx;
    let size = unsafe { (*lookaside).size };
    unsafe { ExDeleteLookasideListEx(lookaside.cast()) };
    // PagedPool = 1, tag 'csIC'
    let status = unsafe {
        ExInitializeLookasideListEx(
            lookaside.cast(),
            core::ptr::null(),
            core::ptr::null(),
            1,
            0,
            size,
            u32::from_ne_bytes(*b"csIC"),
            0,
        )
    };
    NT_SUCCESS(status)
}

fn module_image(name: &str) -> Result<(*const u8, u32), NTSTATUS> {
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
        let file_name = module_file_name(module);
        if file_name.eq_ignore_ascii_case(name) || file_name.starts_with(name.trim_end_matches(".exe")) {
            let base = module.image_base as *const u8;
            pool_free(buffer);
            return Ok((base, module.image_size));
        }
    }
    pool_free(buffer);
    Err(STATUS_NOT_FOUND)
}

fn find_pattern_image(
    base: *const u8,
    image_size: u32,
    pattern: &[u8],
    mask: &[u8],
) -> Option<usize> {
    let sections = image_sections(base, image_size)?;
    for (section_base, section_size) in sections {
        if let Some(offset) = find_pattern(section_base, section_size, pattern, mask) {
            return Some(offset);
        }
    }
    None
}

fn image_sections(base: *const u8, image_size: u32) -> Option<[(usize, usize); 2]> {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
    const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
    const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;

    let image_size = image_size as usize;
    if image_size < 0x200 || read_u16(base, 0) != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let e_lfanew = read_u32(base, 0x3C) as usize;
    if e_lfanew >= image_size.saturating_sub(0x108) {
        return None;
    }
    unsafe {
        let nt = base.add(e_lfanew);
        if read_u32(nt, 0) != IMAGE_NT_SIGNATURE {
            return None;
        }
        let file_header = nt.add(4);
        let number_of_sections = read_u16(file_header, 2) as usize;
        if number_of_sections == 0 || number_of_sections > 96 {
            return None;
        }
        let size_of_optional_header = read_u16(file_header, 16) as usize;
        let first_section = file_header.add(20 + size_of_optional_header);
        let sections_end = first_section.add(number_of_sections * IMAGE_SIZEOF_SECTION_HEADER);
        if sections_end > base.add(image_size) {
            return None;
        }

        let mut out = [(0usize, 0usize); 2];
        let mut count = 0usize;
        for index in 0..number_of_sections {
            let section = first_section.add(index * IMAGE_SIZEOF_SECTION_HEADER);
            let name = {
                let mut bytes = [0u8; 8];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = *section.add(i);
                }
                bytes
            };
            if name.starts_with(b".text") || name.starts_with(b"PAGE") {
                let virtual_size = read_u32(section, 8) as usize;
                let virtual_address = read_u32(section, 12) as usize;
                if virtual_address < image_size {
                    let available = image_size - virtual_address;
                    let size = core::cmp::min(virtual_size, available);
                    if size >= 32 {
                        out[count] = (base.add(virtual_address) as usize, size);
                        count += 1;
                        if count == 2 {
                            break;
                        }
                    }
                }
            }
        }
        if count == 0 {
            None
        } else {
            Some(out)
        }
    }
}

fn find_pattern(base: usize, size: usize, pattern: &[u8], mask: &[u8]) -> Option<usize> {
    if pattern.len() != mask.len() || size <= mask.len() {
        return None;
    }
    let limit = size - mask.len();
    for offset in 0..=limit {
        let addr = base.wrapping_add(offset);
        if pattern_matches(addr, pattern, mask) {
            return Some(addr);
        }
    }
    None
}

fn pattern_matches(base: usize, pattern: &[u8], mask: &[u8]) -> bool {
    for (index, mask_byte) in mask.iter().enumerate() {
        let expected = pattern[index];
        let actual = unsafe { *(base as *const u8).add(index) };
        if *mask_byte == b'?' || actual == expected {
            continue;
        }
        return false;
    }
    true
}

fn resolve_rip_relative(match_addr: usize, disp_offset: usize, instr_size: usize) -> *mut c_void {
    let disp = read_i32(match_addr as *const u8, disp_offset);
    unsafe {
        (match_addr as *const u8)
            .add(instr_size)
            .offset(disp as isize)
            .cast::<c_void>()
            .cast_mut()
    }
}

fn in_image_range(base: *const u8, size: u32, addr: *const c_void) -> bool {
    let start = base as usize;
    let end = start.saturating_add(size as usize);
    let target = addr as usize;
    (start..end).contains(&target)
}

fn read_i32(base: *const u8, offset: usize) -> i32 {
    i32::from_le_bytes([
        unsafe { *base.add(offset) },
        unsafe { *base.add(offset + 1) },
        unsafe { *base.add(offset + 2) },
        unsafe { *base.add(offset + 3) },
    ])
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

fn driver_name_to_wide(driver_name: &str) -> [u16; 128] {
    let mut wide = [0u16; 128];
    let _ = encode_wide(driver_name, &mut wide);
    wide
}

fn unicode_contains(haystack: *const u16, haystack_bytes: u16, needle: &[u16; 128]) -> bool {
    let haystack_len = haystack_bytes as usize / 2;
    if haystack.is_null() || haystack_len == 0 {
        return false;
    }
    let needle_len = needle.iter().position(|&c| c == 0).unwrap_or(needle.len());
    if needle_len == 0 || needle_len > haystack_len {
        return false;
    }
    for start in 0..=(haystack_len - needle_len) {
        let mut matched = true;
        for (index, &unit) in needle[..needle_len].iter().enumerate() {
            let hay = unsafe { *haystack.add(start + index) };
            if hay != unit {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn randomize_unicode_buffer(buffer: *mut u16, char_count: usize) {
    if buffer.is_null() || char_count <= 4 {
        return;
    }
    let mut seed = buffer as usize as u32 ^ 0xA5A5_1234;
    #[cfg(target_arch = "x86_64")]
    {
        seed ^= unsafe { core::arch::x86_64::_rdtsc() as u32 };
    }
    const MAP: [u16; 61] = [
        b'1' as u16, b'2' as u16, b'3' as u16, b'4' as u16, b'5' as u16, b'6' as u16,
        b'7' as u16, b'8' as u16, b'9' as u16, b'Z' as u16, b'X' as u16, b'C' as u16,
        b'V' as u16, b'B' as u16, b'N' as u16, b'M' as u16, b'A' as u16, b'S' as u16,
        b'D' as u16, b'F' as u16, b'G' as u16, b'H' as u16, b'J' as u16, b'K' as u16,
        b'L' as u16, b'Q' as u16, b'W' as u16, b'E' as u16, b'R' as u16, b'T' as u16,
        b'Y' as u16, b'U' as u16, b'I' as u16, b'O' as u16, b'P' as u16, b'z' as u16,
        b'x' as u16, b'c' as u16, b'v' as u16, b'b' as u16, b'n' as u16, b'm' as u16,
        b'a' as u16, b's' as u16, b'd' as u16, b'f' as u16, b'g' as u16, b'h' as u16,
        b'j' as u16, b'k' as u16, b'l' as u16, b'q' as u16, b'w' as u16, b'e' as u16,
        b'r' as u16, b't' as u16, b'y' as u16, b'u' as u16, b'i' as u16, b'o' as u16,
        b'p' as u16,
    ];
    let limit = char_count - 4;
    for index in 0..limit {
        seed ^= seed.wrapping_shl(13);
        seed ^= seed.wrapping_shr(17);
        seed ^= seed.wrapping_shl(5);
        let pick = (seed as usize).wrapping_add(index) % 60;
        unsafe { *buffer.add(index) = MAP[pick] };
    }
}
