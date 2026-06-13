//! User-mode IOCTL client for `win_hv` (ping / read / write via hypercalls).

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use shared_contract::{
    GetCr3ByPidRequest, GetCr3ByPidResponse, IOCTL_GET_CR3_BY_PID, IOCTL_PING, IOCTL_READ_GVA,
    IOCTL_READ_MEMORY, IOCTL_TRANSLATE_GVA, IOCTL_WRITE_MEMORY, MEM_IO_MAX_LEN, MemIoRequest,
    PING_RESPONSE_U32, ReadGvaRequest, TranslateGvaRequest, TranslateGvaResponse, USER_DEVICE_PATH,
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
    /// Translate `gva` with `cr3` to GPA/HPA.
    Translate {
        cr3: String,
        address: String,
    },
    /// Read guest memory at `gva` using `cr3` (GVA->GPA->HPA inside driver).
    ReadGva {
        cr3: String,
        address: String,
        #[arg(short, long, default_value_t = 16)]
        size: u32,
    },
    /// Write hex bytes to guest memory at `address`.
    Write {
        address: String,
        #[arg(short, long)]
        hex: String,
    },
    /// Get CR3 (`DirectoryTableBase`) for a process ID.
    Cr3 {
        pid: u32,
    },
    /// List CR3 for all processes (enumerated in user mode).
    ListCr3,
}

fn parse_address(input: &str) -> anyhow::Result<u64> {
    let trimmed = input.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(trimmed, 16).with_context(|| format!("invalid address: {input}"))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let device = cli.device.as_deref().unwrap_or(USER_DEVICE_PATH);

    println!("contract version: {}", shared_contract::CONTRACT_VERSION);
    println!("opening: {device}");

    let handle = open_device(device)?;
    let result = match cli.command {
        Commands::Ping => ping(&handle),
        Commands::Read { address, size } => read_memory(&handle, &address, size),
        Commands::Translate { cr3, address } => translate_gva_cmd(&handle, &cr3, &address),
        Commands::ReadGva { cr3, address, size } => read_gva(&handle, &cr3, &address, size),
        Commands::Write { address, hex } => write_memory(&handle, &address, &hex),
        Commands::Cr3 { pid } => get_cr3(&handle, pid),
        Commands::ListCr3 => list_cr3(&handle),
    };
    unsafe {
        CloseHandle(handle)?;
    }
    result
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

fn translate_gva(h: &HANDLE, cr3: u64, gva: u64) -> anyhow::Result<TranslateGvaResponse> {
    let request = TranslateGvaRequest { cr3, gva };
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
        bail!("failed to translate gva {gva:#x} with cr3 {cr3:#x}");
    }
    Ok(response)
}

fn translate_gva_cmd(h: &HANDLE, cr3: &str, address: &str) -> anyhow::Result<()> {
    let cr3 = parse_address(cr3)?;
    let gva = parse_address(address)?;
    let translation = translate_gva(h, cr3, gva)?;
    println!(
        "gva {gva:#x} -> gpa {:#x} -> hpa {:#x}",
        translation.gpa, translation.hpa
    );
    Ok(())
}

fn read_gva(h: &HANDLE, cr3: &str, address: &str, size: u32) -> anyhow::Result<()> {
    let cr3 = parse_address(cr3)?;
    let gva = parse_address(address)?;
    let size = size as usize;
    if size == 0 || size > MEM_IO_MAX_LEN {
        bail!("size must be 1..={MEM_IO_MAX_LEN}");
    }

    let request = ReadGvaRequest {
        cr3,
        gva,
        size: size as u32,
        _padding: 0,
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
    println!("read {size} bytes from gva {gva:#x} (cr3 {cr3:#x}):");
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

fn get_cr3(h: &HANDLE, pid: u32) -> anyhow::Result<()> {
    let cr3 = query_cr3(h, pid)?;
    println!("pid {pid}: cr3 = {cr3:#x}");
    Ok(())
}

fn query_cr3(h: &HANDLE, pid: u32) -> anyhow::Result<u64> {
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
    Ok(response.cr3)
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
