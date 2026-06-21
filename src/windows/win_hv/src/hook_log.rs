//! DbgPrint helpers for EPT hook / SSDT debug traces.

use shared_contract::{
    EPT_HOOK2_ERR_ALLOC, EPT_HOOK2_ERR_CR3, EPT_HOOK2_ERR_DISASM, EPT_HOOK2_ERR_GPA_RANGE,
    EPT_HOOK2_ERR_HYPERVISOR, EPT_HOOK2_ERR_INVALID, EPT_HOOK2_ERR_NO_EXEC_ONLY,
    EPT_HOOK2_ERR_NOT_FOUND, EPT_HOOK2_ERR_PAGE_BOUNDARY, EPT_HOOK2_ERR_TRANSLATE,
    IOCTL_EPT_HOOK2,     IOCTL_EPT_UNHOOK, IOCTL_GET_CR3_BY_PID, IOCTL_GET_SSDT,
    IOCTL_GET_SSDT_FUNCTION, IOCTL_CLEAR_TRACE, IOCTL_QUERY_TRACE, IOCTL_HIDE, IOCTL_PING, IOCTL_READ_GVA, IOCTL_READ_MEMORY,
    IOCTL_TRANSLATE_GVA, IOCTL_WRITE_MEMORY, IOCTL_WRITE_PHYSICAL, SSDT_ERR_EXPORT,
    SSDT_ERR_NAME, SSDT_ERR_NO_MATCH, SSDT_ERR_NOT_FOUND, TRANSLATE_FAIL_CR3,
    TRANSLATE_FAIL_INVALID, TRANSLATE_FAIL_MMGPA, TRANSLATE_FAIL_PD, TRANSLATE_FAIL_PML4,
    TRANSLATE_FAIL_PDPT, TRANSLATE_FAIL_PTE,
};

/// Maps [`EPT_HOOK2_ERR_*`] to a short label.
pub(crate) fn ept_hook_err_name(code: u8) -> &'static str {
    match code {
        EPT_HOOK2_ERR_INVALID => "invalid",
        EPT_HOOK2_ERR_CR3 => "cr3",
        EPT_HOOK2_ERR_TRANSLATE => "translate",
        EPT_HOOK2_ERR_GPA_RANGE => "gpa_range",
        EPT_HOOK2_ERR_DISASM => "disasm",
        EPT_HOOK2_ERR_ALLOC => "alloc",
        EPT_HOOK2_ERR_HYPERVISOR => "hypervisor",
        EPT_HOOK2_ERR_NO_EXEC_ONLY => "no_exec_only",
        EPT_HOOK2_ERR_NOT_FOUND => "not_found",
        EPT_HOOK2_ERR_PAGE_BOUNDARY => "page_boundary",
        _ => "unknown",
    }
}

/// Maps [`SSDT_ERR_*`] to a short label.
pub(crate) fn ssdt_err_name(code: u8) -> &'static str {
    match code {
        SSDT_ERR_NOT_FOUND => "not_found",
        SSDT_ERR_EXPORT => "export",
        SSDT_ERR_NO_MATCH => "no_match",
        SSDT_ERR_NAME => "name",
        _ => "unknown",
    }
}

/// Maps IOCTL codes handled by `win_hv` to a short label.
pub(crate) fn ioctl_name(code: u32) -> &'static str {
    match code {
        IOCTL_PING => "PING",
        IOCTL_READ_MEMORY => "READ_MEMORY",
        IOCTL_WRITE_MEMORY => "WRITE_MEMORY",
        IOCTL_GET_CR3_BY_PID => "GET_CR3_BY_PID",
        IOCTL_TRANSLATE_GVA => "TRANSLATE_GVA",
        IOCTL_READ_GVA => "READ_GVA",
        IOCTL_WRITE_PHYSICAL => "WRITE_PHYSICAL",
        IOCTL_EPT_HOOK2 => "EPT_HOOK2",
        IOCTL_EPT_UNHOOK => "EPT_UNHOOK",
        IOCTL_GET_SSDT => "GET_SSDT",
        IOCTL_GET_SSDT_FUNCTION => "GET_SSDT_FUNCTION",
        IOCTL_CLEAR_TRACE => "CLEAR_TRACE",
        IOCTL_QUERY_TRACE => "QUERY_TRACE",
        IOCTL_HIDE => "HIDE",
        _ => "UNKNOWN",
    }
}

/// Maps [`TRANSLATE_FAIL_*`] to a short label.
pub(crate) fn translate_fail_stage(stage: u8) -> &'static str {
    match stage {
        TRANSLATE_FAIL_CR3 => "cr3",
        TRANSLATE_FAIL_INVALID => "invalid",
        TRANSLATE_FAIL_PML4 => "pml4",
        TRANSLATE_FAIL_PDPT => "pdpt",
        TRANSLATE_FAIL_PD => "pd",
        TRANSLATE_FAIL_PTE => "pte",
        TRANSLATE_FAIL_MMGPA => "mmgpa",
        _ => "unknown",
    }
}

/// Prints `bytes` as hex, up to `max` bytes, 16 bytes per line (DbgPrint-safe ASCII).
pub(crate) fn log_hex(tag: &str, bytes: &[u8], max: usize) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let limit = core::cmp::min(bytes.len(), max);
    if limit == 0 {
        crate::eprintln!("{tag}: (empty)");
        return;
    }

    let mut offset = 0usize;
    while offset < limit {
        let row_end = core::cmp::min(offset + 16, limit);
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        for byte in &bytes[offset..row_end] {
            line[pos] = DIGITS[(byte >> 4) as usize];
            line[pos + 1] = DIGITS[(byte & 0x0f) as usize];
            line[pos + 2] = b' ';
            pos += 3;
        }
        line[pos] = 0;
        if let Ok(text) = core::str::from_utf8(&line[..pos]) {
            crate::eprintln!("{tag} +{offset:02x}: {text}");
        }
        offset = row_end;
    }
}
