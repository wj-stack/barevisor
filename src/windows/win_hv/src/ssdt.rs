//! IOCTL wrappers around [`kernel_ssdt`] for `win_hv`.

use shared_contract::{
    GetSsdtFunctionResponse, GetSsdtResponse, SSDT_ERR_EXPORT, SSDT_ERR_NAME, SSDT_ERR_NO_MATCH,
    SSDT_ERR_NOT_FOUND, SSDT_FUNCTION_NAME_MAX,
};

use crate::hook_log::ssdt_err_name;

/// Fills [`GetSsdtResponse`] with native and shadow SSDT table addresses.
pub(crate) fn get_ssdt_info() -> GetSsdtResponse {
    crate::eprintln!("ssdt: locate_ssdt_tables begin");
    let mut response = GetSsdtResponse::default();
    let Ok(tables) = kernel_ssdt::locate_ssdt_tables() else {
        crate::eprintln!(
            "ssdt: locate_ssdt_tables failed ({})",
            ssdt_err_name(SSDT_ERR_NOT_FOUND)
        );
        response.error_code = SSDT_ERR_NOT_FOUND;
        return response;
    };

    crate::eprintln!(
        "ssdt: ntos={:#x} size={:#x} ksd={:#x} table={:#x} services={}",
        tables.ntoskrnl_base as u64,
        tables.ntoskrnl_size,
        tables.ke_service_descriptor_table as u64,
        tables.service_table_base as u64,
        tables.number_of_services
    );
    crate::eprintln!(
        "ssdt: shadow_ksd={:#x} shadow_table={:#x} shadow_services={} win32k_table={:#x} win32k_services={}",
        tables.ke_service_descriptor_table_shadow as u64,
        tables.shadow_service_table_base as u64,
        tables.shadow_number_of_services,
        tables.win32k_service_table_base as u64,
        tables.win32k_number_of_services
    );

    response.success = 1;
    response.ntoskrnl_base = tables.ntoskrnl_base as u64;
    response.ntoskrnl_size = tables.ntoskrnl_size;
    response.ke_service_descriptor_table = tables.ke_service_descriptor_table as u64;
    response.service_table_base = tables.service_table_base as u64;
    response.number_of_services = tables.number_of_services;
    response.ke_service_descriptor_table_shadow = tables.ke_service_descriptor_table_shadow as u64;
    response.shadow_service_table_base = tables.shadow_service_table_base as u64;
    response.shadow_number_of_services = tables.shadow_number_of_services;
    response.win32k_service_table_base = tables.win32k_service_table_base as u64;
    response.win32k_number_of_services = tables.win32k_number_of_services;
    response
}

/// Resolves an ntoskrnl SSDT handler by export name.
pub(crate) fn resolve_ssdt_function(name: &[u8]) -> GetSsdtFunctionResponse {
    let mut response = GetSsdtFunctionResponse::default();
    let Some(export_name) = c_str_to_str(name) else {
        crate::eprintln!("ssdt: resolve invalid name ({})", ssdt_err_name(SSDT_ERR_NAME));
        response.error_code = SSDT_ERR_NAME;
        return response;
    };
    crate::eprintln!("ssdt: resolve {export_name}");
    let Some(export_address) = kernel_ssdt::kernel_export(export_name) else {
        crate::eprintln!(
            "ssdt: kernel_export failed for {export_name} ({})",
            ssdt_err_name(SSDT_ERR_EXPORT)
        );
        response.error_code = SSDT_ERR_EXPORT;
        return response;
    };
    response.export_address = export_address as u64;
    crate::eprintln!("ssdt: export {export_name} = {:#x}", export_address as u64);

    if kernel_ssdt::locate_ssdt_tables().is_err() {
        crate::eprintln!(
            "ssdt: locate_ssdt_tables failed during resolve ({})",
            ssdt_err_name(SSDT_ERR_NOT_FOUND)
        );
        response.error_code = SSDT_ERR_NOT_FOUND;
        return response;
    }

    match kernel_ssdt::resolve_ssdt_function(export_name) {
        Ok(resolved) => {
            crate::eprintln!(
                "ssdt: {export_name} -> fn={:#x} syscall={}",
                resolved.address as u64,
                resolved.syscall_number
            );
            response.success = 1;
            response.syscall_number = resolved.syscall_number;
            response.function_address = resolved.address as u64;
        }
        Err(_) => {
            crate::eprintln!(
                "ssdt: no SSDT match for {export_name} ({})",
                ssdt_err_name(SSDT_ERR_NO_MATCH)
            );
            response.error_code = SSDT_ERR_NO_MATCH;
        }
    }
    response
}

fn c_str_to_str(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 || end > SSDT_FUNCTION_NAME_MAX {
        return None;
    }
    core::str::from_utf8(&bytes[..end]).ok()
}
