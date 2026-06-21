//! Bypass `AsusCertService.exe` certificate gatekeeping for `AsIO3.sys`.
//!
//! Two modes:
//! - **patch** — in-memory hook of the running service (skip Authenticode + whitelist loop)
//! - **serve** — standalone `\\.\pipe\asuscert` proxy (no validation, any PID → IOCTL whitelist)
//!
//! RVAs match `AsusCertService.exe` SHA256:
//! `050682fd3d943b791db5fdbfc08718fd08d99634b26badc6b45e4544696b0846`

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    SetNamedPipeHandleState, WaitNamedPipeW,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_STATUS,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, WaitForSingleObject, LPTHREAD_START_ROUTINE,
};
use windows::core::PCWSTR;

const SERVICE_EXE: &str = "AsusCertService.exe";
const PIPE_PATH: &str = r"\\.\pipe\asuscert";
const ASIO3_DEVICE: &str = r"\\.\Asusgio3";
const IOCTL_ADD_WHITELIST: u32 = 0xA040_A490;
const OK_REPLY: &[u8] = b"O\0K\0!\0\0\0";
/// `RegisterAppToDriver` RVA inside `AsusCertService.exe`.
const REGISTER_APP_RVA: u64 = 0x134C0;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

#[cfg(target_pointer_width = "64")]
const PEB_IMAGE_BASE_OFFSET: u64 = 0x10;
#[cfg(target_pointer_width = "32")]
const PEB_IMAGE_BASE_OFFSET: u64 = 0x08;

#[repr(C)]
struct ProcessBasicInfo {
    exit_status: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// `mov eax, 1; ret`
const PATCH_RET_TRUE: [u8; 6] = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
/// `jmp 0x140013804` — skip GetEmbeddedSignatureInfo + whitelist loop → whitelist-match
/// success path (must include `call sub_140004C60` before ASIO_Register logging)
/// (replacing `call GetEmbeddedSignatureInfo` at RVA 0x135F1)
const PATCH_JMP_ASIO_REGISTER: [u8; 5] = [0xE9, 0x0E, 0x02, 0x00, 0x00];
/// NOP out `call sub_1400120D0(v38)` @ RVA 0x13A6F — v38 is never constructed when
/// the whitelist loop is skipped; running its destructor crashes the service thread.
const PATCH_NOP5: [u8; 5] = [0x90, 0x90, 0x90, 0x90, 0x90];

struct PatchSpec {
    name: &'static str,
    rva: u64,
    bytes: &'static [u8],
}

const PATCHES: &[PatchSpec] = &[
    PatchSpec {
        name: "VerifyEmbeddedSignature",
        rva: 0x10090,
        bytes: &PATCH_RET_TRUE,
    },
    PatchSpec {
        name: "skip_to_asio_register",
        rva: 0x135F1,
        bytes: &PATCH_JMP_ASIO_REGISTER,
    },
    PatchSpec {
        name: "skip_v38_destructor",
        rva: 0x13A6F,
        bytes: &PATCH_NOP5,
    },
];

#[derive(Parser)]
#[command(
    name = "asuscert_bypass",
    about = "Bypass AsusCertService validation and whitelist arbitrary PIDs for AsIO3.sys"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Patch the running AsusCertService process in memory (recommended).
    ///
    /// After patching, existing clients can connect to `\\.\pipe\asuscert` and
    /// register any PID without Authenticode / certificate fingerprint checks.
    Patch {
        /// AsusCertService PID (default: auto-detect).
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Run a replacement pipe server that skips all validation.
    ///
    /// Requires the ability to open `\\.\Asusgio3` (ASUS-signed PE or already
    /// whitelisted). Use `--stop-service` to release the pipe name first.
    Serve {
        /// Stop the AsusCertService Windows service before listening.
        #[arg(long)]
        stop_service: bool,
    },
    /// Register a PID (default: remote call into patched service — no pipe needed).
    Register {
        /// Target PID (default: current process).
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        svc_pid: Option<u32>,
        /// Use `\\.\pipe\asuscert` instead of in-process remote call.
        #[arg(long)]
        via_pipe: bool,
        /// Per-attempt wait when the pipe is busy (ms, default 5000).
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u32,
        /// Number of wait/connect attempts (default 6).
        #[arg(long, default_value_t = 6)]
        retries: u32,
    },
    /// Directly IOCTL-whitelist a PID via `\\.\Asusgio3` (no pipe).
    Whitelist {
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Show patch RVAs and pipe/IOCTL constants.
    Info,
    /// Read and print virtual addresses + bytes at each patch site (before/after comparison).
    Dump {
        /// AsusCertService PID (default: auto-detect).
        #[arg(long)]
        pid: Option<u32>,
        /// Extra bytes to dump before each patch site.
        #[arg(long, default_value_t = 8)]
        context: usize,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Commands::Patch { pid } => patch_service(pid),
        Commands::Serve { stop_service } => run_proxy(stop_service),
        Commands::Register { pid, via_pipe, timeout_ms, retries,svc_pid } => {
            let pid = pid.unwrap_or(std::process::id());
            if via_pipe {
                pipe_register(pid, timeout_ms, retries)
            } else {
                remote_register(pid, svc_pid)
            }
        }
        Commands::Whitelist { pid } => direct_whitelist(pid.unwrap_or(std::process::id())),
        Commands::Info => {
            print_info();
            Ok(())
        }
        Commands::Dump { pid, context } => dump_patch_sites(pid, context),
    }
}

fn print_info() {
    println!("target service:   {SERVICE_EXE}");
    println!("pipe:             {PIPE_PATH}");
    println!("device:           {ASIO3_DEVICE}");
    println!("whitelist IOCTL:  {IOCTL_ADD_WHITELIST:#010x}");
    println!();
    println!("in-memory patches (RVA):");
    for p in PATCHES {
        println!("  {:#x}  {}  ({:02x?})", p.rva, p.name, p.bytes);
    }
    println!();
    println!("recommended:  asuscert_bypass patch   (admin, service must be running)");
    println!("then:         asuscert_bypass register --pid <pid>   (remote, no pipe)");
    println!("alt:          asuscert_bypass register --pid <pid> --via-pipe");
    println!();
    println!("compare:      asuscert_bypass dump    (before patch)");
    println!("              asuscert_bypass patch");
    println!("              asuscert_bypass dump    (after patch)");
}

struct TargetProcess {
    pid: u32,
    base: u64,
    handle: HANDLE,
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

fn enable_debug_privilege() -> anyhow::Result<()> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) }
        .context("OpenProcessToken failed")?;

    let mut luid = Default::default();
    unsafe { LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid) }
        .context("LookupPrivilegeValueW(SeDebugPrivilege) failed")?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe {
        AdjustTokenPrivileges(token, false, Some(&tp as *const _), 0, None, None)
    }
    .context("AdjustTokenPrivileges(SeDebugPrivilege) failed")?;
    let _ = unsafe { CloseHandle(token) };
    Ok(())
}

fn open_process_for_target(pid: u32, write: bool, create_thread: bool) -> anyhow::Result<HANDLE> {
    let mut access = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ;
    if write {
        access |= PROCESS_VM_WRITE;
    }
    if create_thread {
        access |= PROCESS_CREATE_THREAD;
    }
    if let Ok(handle) = unsafe { OpenProcess(access, false, pid) } {
        return Ok(handle);
    }
    enable_debug_privilege().context("failed to enable SeDebugPrivilege")?;
    unsafe { OpenProcess(access, false, pid) }
        .with_context(|| format!("OpenProcess({pid}) failed — run as Administrator"))
}

fn module_base_from_peb(process: HANDLE) -> anyhow::Result<u64> {
    let mut info = ProcessBasicInfo {
        exit_status: 0,
        peb_base_address: std::ptr::null_mut(),
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            0,
            (&mut info as *mut ProcessBasicInfo).cast(),
            size_of::<ProcessBasicInfo>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        bail!("NtQueryInformationProcess failed: {status:#x}");
    }
    let peb = info.peb_base_address as u64;
    if peb == 0 {
        bail!("PEB address is null");
    }

    let ptr_size = size_of::<usize>();
    let bytes = read_remote(process, peb + PEB_IMAGE_BASE_OFFSET, ptr_size)?;
    let base = usize::from_ne_bytes(bytes.as_slice().try_into().unwrap()) as u64;
    if base == 0 {
        bail!("ImageBaseAddress is null");
    }
    Ok(base)
}

fn open_target(pid: Option<u32>, write: bool) -> anyhow::Result<TargetProcess> {
    let pid = pid.unwrap_or_else(|| find_service_pid().expect("auto-detect failed"));
    let handle = open_process_for_target(pid, write, false)?;
    let base = module_base_from_peb(handle)?;
    Ok(TargetProcess { pid, base, handle })
}

fn remote_register(target_pid: u32, service_pid: Option<u32>) -> anyhow::Result<()> {
    let svc_pid = match service_pid {
        Some(p) => p,
        None => find_service_pid()?,
    };
    println!("svc_pid:{svc_pid}");


    let handle = open_process_for_target(svc_pid, false, true)?;
    let base = module_base_from_peb(handle)?;
    let register_va = base + REGISTER_APP_RVA;

    println!(
        "remote RegisterAppToDriver({target_pid}) @ {register_va:#x} (service pid {svc_pid})"
    );

    let entry = unsafe { std::mem::transmute::<u64, LPTHREAD_START_ROUTINE>(register_va) };
    let mut thread_id = 0u32;
    let thread = unsafe {
        CreateRemoteThread(
            handle,
            None,
            0,
            entry,
            Some(target_pid as *const c_void),
            0,
            Some(&mut thread_id),
        )
    }.context("CreateRemoteThread(RegisterAppToDriver) failed — run patch first")?;

    let wait = unsafe { WaitForSingleObject(thread, 30_000) };
    let _ = unsafe { CloseHandle(thread) };
    let _ = unsafe { CloseHandle(handle) };

    if wait == WAIT_OBJECT_0 {
        println!("registered pid {target_pid} (remote thread {thread_id} finished)");
        Ok(())
    } else if wait == WAIT_TIMEOUT {
        bail!(
            "RegisterAppToDriver timed out — is AsIO3.sys loaded? \
             check %ProgramData%\\ASUS\\AsIO3\\AsusCertService.exe.log"
        );
    } else {
        bail!("WaitForSingleObject failed: {wait:?}");
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn patch_status(current: &[u8], patch: &[u8]) -> &'static str {
    if current == patch {
        "patched"
    } else {
        "original"
    }
}

fn read_remote(process: HANDLE, address: u64, size: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut read = 0usize;
    unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            buf.as_mut_ptr().cast(),
            size,
            Some(&mut read),
        )
    }
    .context("ReadProcessMemory failed")?;
    if read != size {
        bail!("ReadProcessMemory returned {read}/{size} bytes @ {address:#x}");
    }
    Ok(buf)
}

fn dump_patch_sites(pid: Option<u32>, context: usize) -> anyhow::Result<()> {
    let target = open_target(pid, false)?;

    println!("{SERVICE_EXE}");
    println!("  pid:  {}", target.pid);
    println!("  base: {:#x}", target.base);
    println!();

    for spec in PATCHES {
        let addr = target.base + spec.rva;
        let patch_len = spec.bytes.len();
        let read_start = addr.saturating_sub(context as u64);
        let prefix_len = (addr - read_start) as usize;
        let total = prefix_len + patch_len;

        let bytes = read_remote(target.handle, read_start, total)?;
        let prefix = &bytes[..prefix_len];
        let current = &bytes[prefix_len..];

        println!("{}", spec.name);
        println!("  RVA:     {:#x}", spec.rva);
        println!("  VA:      {addr:#x}");
        println!("  status:  {}", patch_status(current, spec.bytes));
        if context > 0 {
            println!("  before:  {read_start:#x}  {}", hex_bytes(prefix));
        }
        println!("  current: {addr:#x}  {}", hex_bytes(current));
        println!("  patch:   {addr:#x}  {}", hex_bytes(spec.bytes));
        println!();
    }

    Ok(())
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn find_service_pid() -> anyhow::Result<u32> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .context("CreateToolhelp32Snapshot failed")?;
    if snap == INVALID_HANDLE_VALUE {
        bail!("invalid process snapshot handle");
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found = None;
    let mut ok = unsafe { Process32FirstW(snap, &mut entry).is_ok() };
    while ok {
        let name = String::from_utf16_lossy(
            &entry
                .szExeFile
                .iter()
                .take_while(|&&c| c != 0)
                .copied()
                .collect::<Vec<_>>(),
        );
        if name.eq_ignore_ascii_case(SERVICE_EXE) {
            found = Some(entry.th32ProcessID);
            break;
        }
        ok = unsafe { Process32NextW(snap, &mut entry).is_ok() };
    }
    let _ = unsafe { CloseHandle(snap) };

    found.with_context(|| format!("{SERVICE_EXE} is not running — start the service first"))
}

fn patch_remote(process: HANDLE, address: u64, patch: &[u8]) -> anyhow::Result<()> {
    let mut old = PAGE_EXECUTE_READWRITE;
    unsafe {
        VirtualProtectEx(
            process,
            address as *const c_void,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
    }
    .context("VirtualProtectEx failed")?;

    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            process,
            address as *const c_void,
            patch.as_ptr().cast(),
            patch.len(),
            Some(&mut written),
        )
    }
    .context("WriteProcessMemory failed")?;

    if written != patch.len() {
        bail!("WriteProcessMemory wrote {written}/{} bytes", patch.len());
    }
    Ok(())
}

fn patch_service(pid: Option<u32>) -> anyhow::Result<()> {
    let target = open_target(pid, true)?;

    println!("patching {SERVICE_EXE} pid={} base={:#x}", target.pid, target.base);

    for spec in PATCHES {
        let addr = target.base + spec.rva;
        let before = read_remote(target.handle, addr, spec.bytes.len())?;
        patch_remote(target.handle, addr, spec.bytes)
            .with_context(|| format!("failed to patch {} @ {addr:#x}", spec.name))?;
        let after = read_remote(target.handle, addr, spec.bytes.len())?;
        println!("  OK  {} @ {addr:#x}", spec.name);
        println!("       before: {}", hex_bytes(&before));
        println!("       after:  {}", hex_bytes(&after));
    }

    println!();
    println!("patch applied — pipe clients may now register arbitrary PIDs.");
    println!("test:  asuscert_bypass register --pid {}", std::process::id());
    Ok(())
}

fn stop_asuscert_service() -> anyhow::Result<()> {
    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .context("OpenSCManagerW failed")?;
        let svc = OpenServiceW(
            scm,
            PCWSTR(to_wide("AsusCertService").as_ptr()),
            windows::Win32::System::Services::SERVICE_STOP
                | windows::Win32::System::Services::SERVICE_QUERY_STATUS,
        )
        .context("OpenServiceW(AsusCertService) failed — is the service installed?")?;

        let mut status = SERVICE_STATUS::default();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status)
            .context("ControlService(STOP) failed")?;
        CloseServiceHandle(svc)?;
        CloseServiceHandle(scm)?;
    }
    println!("sent STOP to AsusCertService, waiting for pipe release...");
    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn open_asio3() -> anyhow::Result<HANDLE> {
    let wide = to_wide(ASIO3_DEVICE);
    unsafe {
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
    .with_context(|| {
        format!(
            "CreateFileW({ASIO3_DEVICE}) failed — need ASUS-signed PE or whitelisted PID; \
             try `asuscert_bypass patch` on the running service instead"
        )
    })
}

fn ioctl_whitelist(device: HANDLE, pid: u32) -> anyhow::Result<()> {
    let mut pid_buf = pid;
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            device,
            IOCTL_ADD_WHITELIST,
            Some(std::ptr::from_mut(&mut pid_buf).cast()),
            size_of::<u32>() as u32,
            None,
            0,
            Some(std::ptr::from_mut(&mut returned)),
            None,
        )
    }
    .context("DeviceIoControl(IOCTL_ADD_WHITELIST) failed")?;
    Ok(())
}

fn direct_whitelist(pid: u32) -> anyhow::Result<()> {
    let device = open_asio3()?;
    ioctl_whitelist(device, pid)?;
    let _ = unsafe { CloseHandle(device) };
    println!("whitelisted pid {pid} via {ASIO3_DEVICE}");
    Ok(())
}

fn connect_pipe(timeout_ms: u32, retries: u32) -> anyhow::Result<HANDLE> {
    let wide = to_wide(PIPE_PATH);
    let attempts = retries.max(1);

    for attempt in 1..=attempts {
        if attempt > 1 {
            eprintln!("pipe busy, retrying ({attempt}/{attempts})...");
        }
        let waited = unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), timeout_ms) };
        if !waited.as_bool() {
            let err = unsafe { GetLastError() };
            if attempt == attempts {
                bail!(
                    "WaitNamedPipeW({PIPE_PATH}) timed out after {attempts} attempts \
                     (last error {err:?}) — another client may hold the single pipe instance; \
                     try: Restart-Service AsusCertService"
                );
            }
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }

        match unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(handle) if handle != INVALID_HANDLE_VALUE => return Ok(handle),
            Ok(_) | Err(_) => {
                let err = unsafe { GetLastError() };
                if attempt == attempts {
                    bail!(
                        "connect to {PIPE_PATH} failed ({err:?}) — service running but pipe \
                         unavailable (ERROR_PIPE_BUSY=231 means another client is connected; \
                         only 1 instance). Restart-Service AsusCertService, close other ASUS \
                         tools, or use `asuscert_bypass serve --stop-service`"
                    );
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    bail!("connect to {PIPE_PATH} failed")
}

fn pipe_register(pid: u32, timeout_ms: u32, retries: u32) -> anyhow::Result<()> {
    let pipe = connect_pipe(timeout_ms, retries)?;

    let mode = NAMED_PIPE_MODE(PIPE_READMODE_MESSAGE.0);
    unsafe {
        SetNamedPipeHandleState(pipe, Some(&mode as *const _), None, None)
    }
    .context("SetNamedPipeHandleState(PIPE_READMODE_MESSAGE) failed")?;

    let pid_le = pid.to_le_bytes();
    let mut written = 0u32;
    unsafe {
        WriteFile(
            pipe,
            Some(&pid_le),
            Some(&mut written),
            None,
        )
    }
    .context("WriteFile(pid) failed")?;
    if written != 4 {
        bail!("wrote {written} bytes, expected 4");
    }

    let mut reply = [0u8; 16];
    let mut read = 0u32;
    let read_ok = unsafe { ReadFile(pipe, Some(&mut reply), Some(&mut read), None) }.is_ok();
    let _ = unsafe { CloseHandle(pipe) };

    if !read_ok {
        let err = unsafe { GetLastError() };
        bail!(
            "ReadFile(reply) failed ({err:?}) — service closed the pipe before replying; \
             common causes: (1) old patch crashed the service thread (re-run `patch` with \
             the latest build), (2) target pid {pid} invalid / OpenProcess failed, \
             (3) CreateFile(\\\\.\\Asusgio3) failed inside the service. \
             Check log: %ProgramData%\\ASUS\\AsIO3\\AsusCertService.exe.log"
        );
    }

    let text = String::from_utf16_lossy(
        &reply
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect::<Vec<_>>(),
    );
    println!("registered pid {pid}, reply: {text:?} ({read} bytes)");
    Ok(())
}

fn run_proxy(stop_service: bool) -> anyhow::Result<()> {
    if stop_service {
        stop_asuscert_service()?;
    }

    let device = open_asio3()?;
    println!("proxy listening on {PIPE_PATH} (Ctrl+C to stop)");
    println!("device {ASIO3_DEVICE} open — registering PIDs without validation");

    loop {
        let wide = to_wide(PIPE_PATH);
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                NAMED_PIPE_MODE(PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0),
                PIPE_UNLIMITED_INSTANCES,
                64,
                64,
                5000,
                None,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            bail!("CreateNamedPipeW failed — is the original service still holding the pipe?");
        }

        unsafe { ConnectNamedPipe(pipe, None) }.context("ConnectNamedPipe failed")?;

        let mut pid_buf = [0u8; 4];
        let mut read = 0u32;
        let read_ok = unsafe { ReadFile(pipe, Some(&mut pid_buf), Some(&mut read), None) }.is_ok();

        if read_ok && read == 4 {
            let pid = u32::from_le_bytes(pid_buf);
            print!("client pid {pid} → ");
            match ioctl_whitelist(device, pid) {
                Ok(()) => {
                    println!("whitelisted");
                    let mut written = 0u32;
                    let _ = unsafe {
                        WriteFile(pipe, Some(OK_REPLY), Some(&mut written), None)
                    };
                    let _ = unsafe { FlushFileBuffers(pipe) };
                }
                Err(e) => {
                    println!("IOCTL failed: {e:#}");
                }
            }
        } else {
            eprintln!("invalid read ({read} bytes)");
        }

        let _ = unsafe { DisconnectNamedPipe(pipe) };
        let _ = unsafe { CloseHandle(pipe) };
    }
}
