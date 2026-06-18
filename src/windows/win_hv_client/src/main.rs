//! User-mode IOCTL client for `win_hv` (ping / read / write via hypercalls).

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use shared_contract::{
    ClearTraceRequest, ClearTraceResponse, EptHook2Request, EptHook2Response, EptUnhookRequest,
    GetCr3ByPidRequest, GetCr3ByPidResponse, GetSsdtFunctionRequest, GetSsdtFunctionResponse,
    GetSsdtResponse, CLEAR_TRACE_DRIVER_NAME_MAX, IOCTL_CLEAR_TRACE, IOCTL_EPT_HOOK2,
    IOCTL_EPT_UNHOOK, IOCTL_GET_CR3_BY_PID, IOCTL_GET_SSDT, IOCTL_GET_SSDT_FUNCTION, IOCTL_PING,
    IOCTL_QUERY_TRACE, IOCTL_READ_GVA, IOCTL_READ_MEMORY, IOCTL_SSDT_HOOK_GET_INFO,
    IOCTL_SSDT_HOOK_INSTALL, IOCTL_SSDT_HOOK_SET_BLOCK_PID, IOCTL_SSDT_HOOK_UNINSTALL,
    IOCTL_TRANSLATE_GVA, IOCTL_WRITE_MEMORY, IOCTL_WRITE_PHYSICAL, MEM_IO_MAX_LEN, MemIoRequest,
    PhysMemIoRequest, PING_RESPONSE_U32, QueryTraceRequest, QueryTraceResponse, ReadGvaRequest,
    SSDT_ERR_EXPORT, SSDT_ERR_NAME, SSDT_ERR_NO_MATCH, SSDT_ERR_NOT_FOUND, SSDT_FUNCTION_NAME_MAX,
    SSDT_HOOK_USER_DEVICE_PATH, SsdtHookInfoResponse, SsdtHookSetBlockPidRequest,
    TRACE_ABSENT, TRACE_PRESENT, TRACE_SCAN_FAILED, TranslateGvaRequest, TranslateGvaResponse,
    TRANSLATE_FAIL_CR3, TRANSLATE_FAIL_INVALID, TRANSLATE_FAIL_MMGPA, TRANSLATE_FAIL_PD,
    TRANSLATE_FAIL_PML4, TRANSLATE_FAIL_PDPT, TRANSLATE_FAIL_PTE, TRANSLATE_METHOD_CR3_SWITCH,
    TRANSLATE_METHOD_PAGE_WALK, USER_DEVICE_PATH,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

fn to_wide(path: &str) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

fn open_device(path: &str) -> anyhow::Result<HANDLE> {
    let wide = to_wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("CreateFileW failed for {path}"))?;
    Ok(handle)
}

#[derive(Parser)]
#[command(name = "win_hv_client", version, about = "IOCTL client for win_hv")]
struct Cli {
    #[arg(long, short = 'd')]
    device: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Issue IOCTL_PING (hypercall ping under the hood).
    Ping,
    /// Read guest memory at `address` for `size` bytes.
    Read {
        address: String,
        #[arg(short, long, default_value_t = 16)]
        size: u32,
    },
    /// Translate `gva` to GPA/HPA using kernel CR3 only.
    Translate {
        /// Guest virtual address.
        address: String,
        #[arg(long, conflicts_with = "cr3")]
        pid: Option<u32>,
        #[arg(long, conflicts_with = "pid")]
        cr3: Option<String>,
        /// Translation method: `page-walk` (default) or `cr3-switch`.
        #[arg(long, value_parser = parse_translate_method, default_value = "page-walk")]
        method: u32,
    },
    /// Read guest memory at `gva` after GVA->GPA->HPA translation (page-walk, kernel CR3).
    ReadGva {
        /// Guest virtual address.
        address: String,
        #[arg(long, conflicts_with = "cr3")]
        pid: Option<u32>,
        #[arg(long, conflicts_with = "pid")]
        cr3: Option<String>,
        #[arg(short, long, default_value_t = 16)]
        size: u32,
    },
    /// Write hex bytes to guest memory at `address`.
    Write {
        address: String,
        #[arg(long)]
        hex: String,
    },
    /// Write hex bytes to a host physical address.
    WritePhys {
        address: String,
        #[arg(long)]
        hex: String,
    },
    /// Get kernel CR3 (`DirectoryTableBase`) for a process ID.
    Cr3 {
        pid: u32,
    },
    /// List kernel CR3 for all processes (enumerated in user mode).
    ListCr3,
    /// Install an EPT Hook2 inline detour.
    Hook {
        /// Target function guest virtual address.
        #[arg(long)]
        target: String,
        /// Detour handler guest virtual address.
        #[arg(long)]
        hook: String,
        #[arg(long, default_value_t = 0)]
        pid: u32,
    },
    /// Remove an EPT Hook2 detour.
    Unhook {
        /// Target guest virtual address used when installing the hook.
        #[arg(long)]
        target: String,
        #[arg(long, default_value_t = 0)]
        pid: u32,
    },
    /// Locate `KeServiceDescriptorTable` / shadow SSDT addresses (HyperDbg-style scan).
    Ssdt,
    /// Resolve an ntoskrnl SSDT handler by export name.
    SsdtFn {
        /// Export name (e.g. `NtOpenProcess`).
        name: String,
    },
    /// Clear kernel driver load/unload traces (PiDDB, MmUnloadedDrivers, CI caches).
    ClearTrace {
        /// Driver file name (e.g. `win_hv.sys`).
        name: String,
        /// PiDDB timestamp (hex). Use `0` to skip PiDDB lookup by stamp.
        #[arg(long, default_value = "0")]
        stamp: String,
    },
    /// Query kernel driver load/unload traces without modifying them.
    QueryTrace {
        /// Driver file name (e.g. `win_hv.sys`).
        name: String,
        /// PiDDB timestamp (hex). Use `0` to search PiDDB by name only.
        #[arg(long, default_value = "0")]
        stamp: String,
    },
    /// Control the `ssdt_hook` example driver (`\\.\SsdtHook`).
    SsdtHook {
        #[command(subcommand)]
        action: SsdtHookAction,
    },
}

#[derive(Subcommand)]
enum SsdtHookAction {
    /// Show SSDT target and kernel hook handler addresses.
    Info,
    /// Install the EPT hook (requires `win_hv` loaded).
    Install,
    /// Remove the EPT hook.
    Uninstall,
    /// Deny `NtOpenProcess` when `ClientId` matches this PID (`0` clears the filter).
    BlockPid {
        /// Target process ID (`0` disables blocking).
        pid: u32,
    },
}

fn parse_translate_method(input: &str) -> Result<u32, String> {
    match input {
        "page-walk" | "walk" | "0" | "2" => Ok(TRANSLATE_METHOD_PAGE_WALK),
        "cr3-switch" | "switch" | "1" => Ok(TRANSLATE_METHOD_CR3_SWITCH),
        other => Err(format!(
            "unknown method {other:?}; use page-walk or cr3-switch"
        )),
    }
}

fn parse_address(input: &str) -> anyhow::Result<u64> {
    let trimmed = input.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(trimmed, 16).with_context(|| format!("invalid address: {input}"))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    println!("contract version: {}", shared_contract::CONTRACT_VERSION);

    match cli.command {
        Commands::SsdtHook { action } => {
            println!("opening: {SSDT_HOOK_USER_DEVICE_PATH}");
            let handle = open_device(SSDT_HOOK_USER_DEVICE_PATH)?;
            let result = match action {
                SsdtHookAction::Info => ssdt_hook_info(&handle),
                SsdtHookAction::Install => ssdt_hook_install(&handle),
                SsdtHookAction::Uninstall => ssdt_hook_uninstall(&handle),
                SsdtHookAction::BlockPid { pid } => ssdt_hook_set_block_pid(&handle, pid),
            };
            unsafe {
                CloseHandle(handle)?;
            }
            result
        }
        command => {
            let device = cli.device.as_deref().unwrap_or(USER_DEVICE_PATH);
            println!("opening: {device}");
            let handle = open_device(device)?;
            let result = dispatch_win_hv(&handle, command);
            unsafe {
                CloseHandle(handle)?;
            }
            result
        }
    }
}

fn dispatch_win_hv(h: &HANDLE, command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Ping => ping(h),
        Commands::Read { address, size } => read_memory(h, &address, size),
        Commands::Translate {
            pid,
            cr3,
            address,
            method,
        } => translate_gva_cmd(h, pid, cr3.as_deref(), &address, method),
        Commands::ReadGva { pid, cr3, address, size } => {
            read_gva(h, pid, cr3.as_deref(), &address, size)
        }
        Commands::Write { address, hex } => write_memory(h, &address, &hex),
        Commands::WritePhys { address, hex } => write_physical(h, &address, &hex),
        Commands::Cr3 { pid } => get_cr3(h, pid),
        Commands::ListCr3 => list_cr3(h),
        Commands::Hook { target, hook, pid } => ept_hook2(h, &target, &hook, pid),
        Commands::Unhook { target, pid } => ept_unhook(h, &target, pid),
        Commands::Ssdt => get_ssdt(h),
        Commands::SsdtFn { name } => get_ssdt_function(h, &name),
        Commands::ClearTrace { name, stamp } => clear_trace(h, &name, &stamp),
        Commands::QueryTrace { name, stamp } => query_trace(h, &name, &stamp),
        Commands::SsdtHook { .. } => unreachable!(),
    }
}

fn ping(h: &HANDLE) -> anyhow::Result<()> {
    let mut out = [0u8; 4];
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_PING,
            None,
            0,
            Some(out.as_mut_ptr().cast::<c_void>()),
            4,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned != 4 {
        bail!("IOCTL_PING expected 4 bytes, got {returned}");
    }
    let value = u32::from_le_bytes(out);
    println!("ping ok: output u32 = {value:#010x} (expect {PING_RESPONSE_U32:#010x})");
    Ok(())
}

fn read_memory(h: &HANDLE, address: &str, size: u32) -> anyhow::Result<()> {
    let address = parse_address(address)?;
    let size = size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        bail!("size must be 1..={MEM_IO_MAX_LEN}");
    }

    let request = MemIoRequest {
        address,
        size: size as u32,
    };
    let mut buffer = vec![0u8; size];
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_READ_MEMORY,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<MemIoRequest>() as u32,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            size as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size {
        bail!("IOCTL_READ_MEMORY returned {returned} bytes, expected {size}");
    }
    println!("read {size} bytes from {address:#x}:");
    println!("{}", hex::encode(&buffer));
    Ok(())
}

fn resolve_gva_target(
    pid: Option<u32>,
    cr3: Option<&str>,
) -> anyhow::Result<(u32, u64)> {
    match (pid, cr3) {
        (Some(pid), None) => Ok((pid, 0)),
        (None, Some(cr3)) => Ok((0, parse_address(cr3)?)),
        (Some(_), Some(_)) => bail!("use either --pid or CR3, not both"),
        (None, None) => bail!("either --pid or CR3 is required"),
    }
}

fn translate_fail_stage_name(stage: u8) -> &'static str {
    match stage {
        TRANSLATE_FAIL_CR3 => "cr3_resolve",
        TRANSLATE_FAIL_INVALID => "invalid_gva_or_root",
        TRANSLATE_FAIL_PML4 => "pml4",
        TRANSLATE_FAIL_PDPT => "pdpt",
        TRANSLATE_FAIL_PD => "pd",
        TRANSLATE_FAIL_PTE => "pte",
        TRANSLATE_FAIL_MMGPA => "mmgpa",
        _ => "unknown",
    }
}

fn format_translate_failure(
    gva: u64,
    process_id: u32,
    cr3: u64,
    response: &TranslateGvaResponse,
) -> String {
    let mut message = format!(
        "translation failed: gva={gva:#x} stage={} status={:#x}",
        translate_fail_stage_name(response.fail_stage),
        response.status as u32
    );
    if process_id != 0 {
        message.push_str(&format!(" pid={process_id}"));
    }
    if response.used_cr3 != 0 {
        message.push_str(&format!(" used_cr3={:#x}", response.used_cr3));
    } else if cr3 != 0 {
        message.push_str(&format!(" requested_cr3={cr3:#x}"));
    }
    if response.pml4e_pa != 0 {
        message.push_str(&format!(" pml4e_pa={:#x}", response.pml4e_pa));
    }
    if response.pdpe_pa != 0 {
        message.push_str(&format!(" pdpe_pa={:#x}", response.pdpe_pa));
    }
    if response.pde_pa != 0 {
        message.push_str(&format!(" pde_pa={:#x}", response.pde_pa));
    }
    if response.pte_pa != 0 {
        message.push_str(&format!(" pte_pa={:#x}", response.pte_pa));
    }
    message
}

fn translate_gva_ioctl(
    h: &HANDLE,
    process_id: u32,
    method: u32,
    cr3: u64,
    gva: u64,
) -> anyhow::Result<TranslateGvaResponse> {
    let request = TranslateGvaRequest {
        process_id,
        method,
        cr3,
        gva,
    };
    let mut response = TranslateGvaResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_TRANSLATE_GVA,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<TranslateGvaRequest>() as u32,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<TranslateGvaResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<TranslateGvaResponse>() {
        bail!("IOCTL_TRANSLATE_GVA returned {returned} bytes");
    }
    if response.success == 0 {
        bail!(format_translate_failure(gva, process_id, cr3, &response));
    }
    Ok(response)
}

fn print_vtop_walk(gva: u64, translation: &TranslateGvaResponse) {
    let method = match translation.method as u32 {
        TRANSLATE_METHOD_CR3_SWITCH => "cr3-switch",
        _ => "page-walk",
    };
    println!("method: {method}");
    let pagedir = translation.used_cr3 & 0x000F_FFFF_FFFF_F000;
    println!("Amd64VtoP: Virt {gva:016x}, pagedir {pagedir:016x}");
    if translation.pml4e_pa != 0 {
        println!("Amd64VtoP: PML4E {:016x}", translation.pml4e_pa);
    }
    if translation.pdpe_pa != 0 {
        println!("Amd64VtoP: PDPE {:016x}", translation.pdpe_pa);
    }
    if translation.pde_pa != 0 {
        println!("Amd64VtoP: PDE {:016x}", translation.pde_pa);
    }
    if translation.pte_pa != 0 {
        println!("Amd64VtoP: PTE {:016x}", translation.pte_pa);
    }
    println!("Amd64VtoP: Mapped phys {:016x}", translation.gpa);
    println!(
        "Virtual address {gva:x} translates to physical address {:x}.",
        translation.gpa
    );
    if translation.hpa != translation.gpa {
        println!("Host physical address: {:x}", translation.hpa);
    }
}

fn translate_gva_cmd(
    h: &HANDLE,
    pid: Option<u32>,
    cr3: Option<&str>,
    address: &str,
    method: u32,
) -> anyhow::Result<()> {
    let (process_id, cr3) = resolve_gva_target(pid, cr3)?;
    let gva = parse_address(address)?;
    let translation = translate_gva_ioctl(h, process_id, method, cr3, gva)?;
    print_vtop_walk(gva, &translation);
    Ok(())
}

fn read_gva(
    h: &HANDLE,
    pid: Option<u32>,
    cr3: Option<&str>,
    address: &str,
    size: u32,
) -> anyhow::Result<()> {
    let (process_id, cr3) = resolve_gva_target(pid, cr3)?;
    let gva = parse_address(address)?;
    let size = size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        bail!("size must be 1..={MEM_IO_MAX_LEN}");
    }

    let request = ReadGvaRequest {
        process_id,
        size: size as u32,
        cr3,
        gva,
    };
    let mut buffer = vec![0u8; size];
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_READ_GVA,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<ReadGvaRequest>() as u32,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            size as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size {
        bail!("IOCTL_READ_GVA returned {returned} bytes, expected {size}");
    }
    println!("read {size} bytes:");
    println!("{}", hex::encode(&buffer));
    Ok(())
}

fn write_memory(h: &HANDLE, address: &str, hex_data: &str) -> anyhow::Result<()> {
    let address = parse_address(address)?;
    let data = hex::decode(hex_data.replace(' ', "")).context("invalid hex payload")?;
    let size = data.len();
    if size == 0 || size > MEM_IO_MAX_LEN {
        bail!("payload length must be 1..={MEM_IO_MAX_LEN}");
    }

    let mut input = Vec::with_capacity(size_of::<MemIoRequest>() + size);
    let request = MemIoRequest {
        address,
        size: size as u32,
    };
    input.extend_from_slice(unsafe {
        core::slice::from_raw_parts(
            std::ptr::from_ref(&request).cast::<u8>(),
            size_of::<MemIoRequest>(),
        )
    });
    input.extend_from_slice(&data);

    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_WRITE_MEMORY,
            Some(input.as_ptr().cast::<c_void>()),
            input.len() as u32,
            None,
            0,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    println!("wrote {size} bytes to {address:#x}");
    Ok(())
}

fn write_physical(h: &HANDLE, address: &str, hex_data: &str) -> anyhow::Result<()> {
    let address = parse_address(address)?;
    let data = hex::decode(hex_data.replace(' ', "")).context("invalid hex payload")?;
    let size = data.len();
    if size == 0 || size > MEM_IO_MAX_LEN {
        bail!("payload length must be 1..={MEM_IO_MAX_LEN}");
    }

    let mut input = Vec::with_capacity(size_of::<PhysMemIoRequest>() + size);
    let request = PhysMemIoRequest {
        address,
        size: size as u32,
    };
    input.extend_from_slice(unsafe {
        core::slice::from_raw_parts(
            std::ptr::from_ref(&request).cast::<u8>(),
            size_of::<PhysMemIoRequest>(),
        )
    });
    input.extend_from_slice(&data);

    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_WRITE_PHYSICAL,
            Some(input.as_ptr().cast::<c_void>()),
            input.len() as u32,
            None,
            0,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    println!("wrote {size} bytes to physical {address:#x}");
    Ok(())
}

fn ept_hook2(h: &HANDLE, target: &str, hook: &str, pid: u32) -> anyhow::Result<()> {
    let request = EptHook2Request {
        process_id: pid,
        syscall_number: 0,
        target_gva: parse_address(target)?,
        hook_gva: parse_address(hook)?,
    };
    let mut response = EptHook2Response::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_EPT_HOOK2,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<EptHook2Request>() as u32,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<EptHook2Response>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if response.success == 0 {
        bail!("EPT hook failed: error_code={}", response.error_code);
    }
    println!(
        "hook ok: target_gpa={:#x} trampoline_gva={:#x} patched_len={}",
        response.target_gpa, response.trampoline_gva, response.patched_len
    );
    Ok(())
}

fn ept_unhook(h: &HANDLE, target: &str, pid: u32) -> anyhow::Result<()> {
    let request = EptUnhookRequest {
        target_gva: parse_address(target)?,
        process_id: pid,
        _padding: 0,
    };
    let mut error_code = 0u8;
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_EPT_UNHOOK,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<EptUnhookRequest>() as u32,
            Some(std::ptr::from_mut(&mut error_code).cast::<c_void>()),
            size_of::<u8>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if error_code != 0 {
        bail!("EPT unhook failed: error_code={error_code}");
    }
    println!("unhook ok: target={target}");
    Ok(())
}

fn ssdt_hook_export_name(response: &SsdtHookInfoResponse) -> String {
    let end = response
        .export_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(response.export_name.len());
    String::from_utf8_lossy(&response.export_name[..end]).into_owned()
}

fn ssdt_hook_info(h: &HANDLE) -> anyhow::Result<()> {
    let response = ssdt_hook_query_info(h)?;
    if response.ready == 0 {
        bail!("ssdt_hook driver not ready (target not resolved)");
    }
    let name = ssdt_hook_export_name(&response);
    println!("export:           {name}");
    println!("target_gva:       {:#x}", response.target_gva);
    println!("hook_gva:         {:#x}", response.hook_gva);
    println!("installed:        {}", response.installed);
    if response.trampoline_gva != 0 {
        println!("trampoline_gva:   {:#x}", response.trampoline_gva);
    }
    if response.block_pid != 0 {
        println!("block_pid:        {}", response.block_pid);
    }
    println!();
    println!("install:   win_hv_client ssdt-hook install");
    println!("block-pid: win_hv_client ssdt-hook block-pid <pid>");
    println!(
        "manual:  win_hv_client hook --target {:#x} --hook {:#x}",
        response.target_gva, response.hook_gva
    );
    Ok(())
}

fn ssdt_hook_query_info(h: &HANDLE) -> anyhow::Result<SsdtHookInfoResponse> {
    let mut response = SsdtHookInfoResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_SSDT_HOOK_GET_INFO,
            None,
            0,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<SsdtHookInfoResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<SsdtHookInfoResponse>() {
        bail!("IOCTL_SSDT_HOOK_GET_INFO returned {returned} bytes");
    }
    Ok(response)
}

fn ssdt_hook_install(h: &HANDLE) -> anyhow::Result<()> {
    let info = ssdt_hook_query_info(h)?;
    if info.ready == 0 {
        bail!("ssdt_hook driver not ready");
    }
    if info.installed != 0 {
        bail!("hook already installed (trampoline={:#x})", info.trampoline_gva);
    }

    let mut response = EptHook2Response::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_SSDT_HOOK_INSTALL,
            None,
            0,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<EptHook2Response>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<EptHook2Response>() {
        bail!("IOCTL_SSDT_HOOK_INSTALL returned {returned} bytes");
    }
    if response.success == 0 {
        bail!("ssdt-hook install failed: error_code={}", response.error_code);
    }
    println!(
        "hook ok: target={:#x} hook={:#x} trampoline={:#x} patched_len={}",
        info.target_gva, info.hook_gva, response.trampoline_gva, response.patched_len
    );
    Ok(())
}

fn ssdt_hook_uninstall(h: &HANDLE) -> anyhow::Result<()> {
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_SSDT_HOOK_UNINSTALL,
            None,
            0,
            None,
            0,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    println!("ssdt-hook removed");
    Ok(())
}

fn ssdt_hook_set_block_pid(h: &HANDLE, pid: u32) -> anyhow::Result<()> {
    let request = SsdtHookSetBlockPidRequest {
        pid,
        _padding: 0,
    };
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_SSDT_HOOK_SET_BLOCK_PID,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<SsdtHookSetBlockPidRequest>() as u32,
            None,
            0,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if pid == 0 {
        println!("ssdt-hook block-pid cleared");
    } else {
        println!("ssdt-hook block-pid set to {pid} (matching NtOpenProcess will be denied)");
    }
    Ok(())
}

fn ssdt_error_name(code: u8) -> &'static str {
    match code {
        SSDT_ERR_NOT_FOUND => "not_found",
        SSDT_ERR_EXPORT => "export_not_found",
        SSDT_ERR_NO_MATCH => "no_ssdt_match",
        SSDT_ERR_NAME => "invalid_name",
        _ => "unknown",
    }
}

fn parse_trace_stamp(stamp: &str) -> anyhow::Result<u32> {
    let stamp_trimmed = stamp.trim();
    let stamp_trimmed = stamp_trimmed.strip_prefix("0x").unwrap_or(stamp_trimmed);
    u32::from_str_radix(stamp_trimmed, 16)
        .with_context(|| format!("invalid PiDDB stamp: {stamp}"))
}

fn trace_status_name(status: u8) -> &'static str {
    match status {
        TRACE_ABSENT => "absent",
        TRACE_PRESENT => "present",
        TRACE_SCAN_FAILED => "scan_failed",
        _ => "unknown",
    }
}

fn clear_trace(h: &HANDLE, name: &str, stamp: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() >= CLEAR_TRACE_DRIVER_NAME_MAX {
        bail!("driver name length must be 1..{CLEAR_TRACE_DRIVER_NAME_MAX}");
    }

    let stamp = parse_trace_stamp(stamp)?;

    let mut request = ClearTraceRequest::default();
    request.name[..name.len()].copy_from_slice(name.as_bytes());
    request.stamp = stamp;

    let mut response = ClearTraceResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_CLEAR_TRACE,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<ClearTraceRequest>() as u32,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<ClearTraceResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<ClearTraceResponse>() {
        bail!("IOCTL_CLEAR_TRACE returned {returned} bytes");
    }
    if response.success == 0 {
        bail!("clear-trace failed: no matching traces were cleared for {name}");
    }

    println!("clear-trace ok for {name}:");
    println!("  PiDDBCacheTable:          {}", flag(response.piddb));
    println!("  MmUnloadedDrivers:        {}", flag(response.unloaded));
    println!("  g_KernelHashBucketList:   {}", flag(response.hash_bucket));
    println!("  g_CiEaCacheLookasideList: {}", flag(response.ci_ea_cache));
    Ok(())
}

fn query_trace(h: &HANDLE, name: &str, stamp: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() >= CLEAR_TRACE_DRIVER_NAME_MAX {
        bail!("driver name length must be 1..{CLEAR_TRACE_DRIVER_NAME_MAX}");
    }

    let stamp = parse_trace_stamp(stamp)?;

    let mut request = QueryTraceRequest::default();
    request.name[..name.len()].copy_from_slice(name.as_bytes());
    request.stamp = stamp;

    let mut response = QueryTraceResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_QUERY_TRACE,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<QueryTraceRequest>() as u32,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<QueryTraceResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<QueryTraceResponse>() {
        bail!("IOCTL_QUERY_TRACE returned {returned} bytes");
    }

    print_trace_query(name, &response);
    Ok(())
}

fn print_trace_query(name: &str, response: &QueryTraceResponse) {
    println!("query-trace for {name}:");
    print_trace_field("PiDDBCacheTable", response.piddb);
    if response.piddb == TRACE_PRESENT {
        println!("    stamp: {:#x}", response.piddb_stamp);
    }
    print_trace_field("MmUnloadedDrivers", response.unloaded);
    if response.unloaded == TRACE_PRESENT {
        println!("    slot:  {}", response.unloaded_slot);
    }
    print_trace_field("g_KernelHashBucketList", response.hash_bucket);
    print_trace_field("g_CiEaCacheLookasideList", response.ci_ea);

    let any_present = response.piddb == TRACE_PRESENT
        || response.unloaded == TRACE_PRESENT
        || response.hash_bucket == TRACE_PRESENT;
    let any_scan_failed = response.piddb == TRACE_SCAN_FAILED
        || response.unloaded == TRACE_SCAN_FAILED
        || response.hash_bucket == TRACE_SCAN_FAILED
        || response.ci_ea == TRACE_SCAN_FAILED;

    if any_scan_failed {
        println!("summary: one or more structures could not be scanned on this OS build");
    } else if any_present {
        println!("summary: driver trace still present in at least one structure");
    } else {
        println!("summary: no matching driver trace found");
    }
}

fn print_trace_field(label: &str, status: u8) {
    println!("  {label:28} {}", trace_status_name(status));
}

fn flag(value: u8) -> &'static str {
    if value != 0 {
        "cleared"
    } else {
        "skipped"
    }
}

fn get_ssdt(h: &HANDLE) -> anyhow::Result<()> {
    let mut response = GetSsdtResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_GET_SSDT,
            None,
            0,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<GetSsdtResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<GetSsdtResponse>() {
        bail!("IOCTL_GET_SSDT returned {returned} bytes");
    }
    if response.success == 0 {
        bail!(
            "SSDT lookup failed: error_code={} ({})",
            response.error_code,
            ssdt_error_name(response.error_code)
        );
    }

    println!("ntoskrnl: base={:#x} size={:#x}", response.ntoskrnl_base, response.ntoskrnl_size);
    println!(
        "KeServiceDescriptorTable:        {:#x}",
        response.ke_service_descriptor_table
    );
    println!(
        "  KiServiceTable:                {:#x}  services={}",
        response.service_table_base, response.number_of_services
    );
    println!(
        "KeServiceDescriptorTableShadow:  {:#x}",
        response.ke_service_descriptor_table_shadow
    );
    println!(
        "  shadow[0] KiServiceTable:      {:#x}  services={}",
        response.shadow_service_table_base, response.shadow_number_of_services
    );
    if response.win32k_service_table_base != 0 {
        println!(
            "  shadow[1] win32k service table: {:#x}  services={}",
            response.win32k_service_table_base, response.win32k_number_of_services
        );
    }
    Ok(())
}

fn get_ssdt_function(h: &HANDLE, name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() >= SSDT_FUNCTION_NAME_MAX {
        bail!("export name length must be 1..{SSDT_FUNCTION_NAME_MAX}");
    }

    let mut request = GetSsdtFunctionRequest::default();
    request.name[..name.len()].copy_from_slice(name.as_bytes());

    let mut response = GetSsdtFunctionResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_GET_SSDT_FUNCTION,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<GetSsdtFunctionRequest>() as u32,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<GetSsdtFunctionResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<GetSsdtFunctionResponse>() {
        bail!("IOCTL_GET_SSDT_FUNCTION returned {returned} bytes");
    }
    if response.success == 0 {
        bail!(
            "SSDT resolve failed for {name}: error_code={} ({})",
            response.error_code,
            ssdt_error_name(response.error_code)
        );
    }

    println!("{name}:");
    println!("  syscall_number:   {}", response.syscall_number);
    println!("  function_address: {:#x}", response.function_address);
    println!("  export_address:   {:#x}", response.export_address);
    Ok(())
}

fn get_cr3(h: &HANDLE, pid: u32) -> anyhow::Result<()> {
    let process_cr3 = query_process_cr3(h, pid)?;
    println!("pid {pid}: kernel_cr3 = {:#x}", process_cr3.cr3);
    Ok(())
}

fn query_process_cr3(h: &HANDLE, pid: u32) -> anyhow::Result<GetCr3ByPidResponse> {
    let request = GetCr3ByPidRequest { process_id: pid };
    let mut response = GetCr3ByPidResponse::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            *h,
            IOCTL_GET_CR3_BY_PID,
            Some(std::ptr::from_ref(&request).cast::<c_void>()),
            size_of::<GetCr3ByPidRequest>() as u32,
            Some(std::ptr::from_mut(&mut response).cast::<c_void>()),
            size_of::<GetCr3ByPidResponse>() as u32,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )?;
    }
    if returned as usize != size_of::<GetCr3ByPidResponse>() {
        bail!("IOCTL_GET_CR3_BY_PID returned {returned} bytes");
    }
    if response.found == 0 {
        bail!("process {pid} not found");
    }
    Ok(response)
}

fn query_cr3(h: &HANDLE, pid: u32) -> anyhow::Result<u64> {
    Ok(query_process_cr3(h, pid)?.cr3)
}

fn list_cr3(h: &HANDLE) -> anyhow::Result<()> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.context("CreateToolhelp32Snapshot failed")?;
    if snapshot == INVALID_HANDLE_VALUE {
        bail!("CreateToolhelp32Snapshot returned INVALID_HANDLE_VALUE");
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut listed = 0usize;
    let mut skipped = 0usize;
    println!("{:>8}  {:>18}", "PID", "CR3");

    let first_ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if first_ok.is_ok() {
        loop {
            let pid = entry.th32ProcessID;
            match query_cr3(h, pid) {
                Ok(cr3) => {
                    println!("{pid:>8}  {cr3:#018x}");
                    listed += 1;
                }
                Err(_) => skipped += 1,
            }

            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe {
        CloseHandle(snapshot)?;
    }

    println!("listed {listed} processes ({skipped} skipped)");
    Ok(())
}
