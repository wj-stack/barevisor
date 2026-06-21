//! Orchestrates driver stealth: module unlink, device symlink, registry, traces.

use core::sync::atomic::{AtomicUsize, Ordering};

use shared_contract::{
    HideRequest, HideResponse, HIDE_FLAG_CLEAR_TRACES, HIDE_FLAG_DEVICE_SYMLINK,
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
