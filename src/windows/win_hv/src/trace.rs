//! IOCTL wrapper around [`kernel_trace`] for driver load/unload trace cleanup.

use shared_contract::{
    ClearTraceResponse, QueryTraceResponse, CLEAR_TRACE_DRIVER_NAME_MAX,
};

/// Clears PiDDB, unloaded-driver, CI hash-bucket, and CI EA cache traces.
pub(crate) fn clear_traces(name: &[u8], stamp: u32) -> ClearTraceResponse {
    let Some(driver_name) = c_str_to_str(name) else {
        crate::eprintln!("trace: invalid driver name");
        return ClearTraceResponse::default();
    };

    crate::eprintln!("trace: clearing traces for {driver_name} stamp={stamp:#x}");
    let result = kernel_trace::clear_driver_traces(driver_name, stamp);
    crate::eprintln!(
        "trace: piddb={} unloaded={} hash={} ci_ea={}",
        u8::from(result.piddb),
        u8::from(result.unloaded),
        u8::from(result.hash_bucket),
        u8::from(result.ci_ea_cache)
    );

    let success = result.piddb
        || result.unloaded
        || result.hash_bucket
        || result.ci_ea_cache;

    ClearTraceResponse {
        success: u8::from(success),
        piddb: u8::from(result.piddb),
        unloaded: u8::from(result.unloaded),
        hash_bucket: u8::from(result.hash_bucket),
        ci_ea_cache: u8::from(result.ci_ea_cache),
        _padding: [0; 3],
    }
}

/// Queries PiDDB, unloaded-driver, CI hash-bucket, and CI EA cache traces.
pub(crate) fn query_traces(name: &[u8], stamp: u32) -> QueryTraceResponse {
    let Some(driver_name) = c_str_to_str(name) else {
        crate::eprintln!("trace: query invalid driver name");
        return QueryTraceResponse::default();
    };

    crate::eprintln!("trace: querying traces for {driver_name} stamp={stamp:#x}");
    let result = kernel_trace::query_driver_traces(driver_name, stamp);
    crate::eprintln!(
        "trace: query piddb={} unloaded={} hash={} ci_ea={} piddb_stamp={:#x} unloaded_slot={}",
        result.piddb,
        result.unloaded,
        result.hash_bucket,
        result.ci_ea,
        result.piddb_stamp,
        result.unloaded_slot
    );

    QueryTraceResponse {
        piddb: result.piddb,
        unloaded: result.unloaded,
        hash_bucket: result.hash_bucket,
        ci_ea: result.ci_ea,
        _padding: [0; 3],
        piddb_stamp: result.piddb_stamp,
        unloaded_slot: result.unloaded_slot,
    }
}

fn c_str_to_str(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 || end > CLEAR_TRACE_DRIVER_NAME_MAX {
        return None;
    }
    core::str::from_utf8(&bytes[..end]).ok()
}
