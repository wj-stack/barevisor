//! IOMap64.sys BYOVD client — arbitrary physical memory map/read/write via `\\.\IOMap`.
//!
//! IOCTL layout derived from static analysis of IOMap64.sys V3.1 (2024-11-28).

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, bail};
use clap::Subcommand;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

pub(crate) const IOMAP_DEVICE_PATH: &str = r"\\.\IOMap";

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

const MAP_SIZE_256K: u32 = 0x4_0000;
const MAP_SIZE_16M: u32 = 0x100_0000;

/// Default PCI coordinates that pass IOMap_ValidatePciDevice on typical Gigabyte systems.
const DEFAULT_PCI_BUS: u32 = 1;
const DEFAULT_PCI_DEV: u32 = 0;

// Primary dispatch IOCTLs (IOMap_DispatchDeviceControl).
const IOCTL_MAP_16M_SLOT0: u32 = 0x8300_20D0;
const IOCTL_GET_MAX_MAP_SIZE: u32 = 0x8300_20D8;
const IOCTL_MAP_256K: u32 = 0x8300_2104;
const IOCTL_MAP_16M_SLOT1: u32 = 0x8300_2118;
/// Returns 1/0 whether a 16M slot is mapped; also refreshes driver active-read cache.
const IOCTL_GET_MAP_STATUS: u32 = 0x8300_2134;

// Secondary dispatch IOCTLs (IOMap_DispatchSecondaryIoctl, METHOD_BUFFERED).
const IOCTL_READ_BYTE_256K: u32 = 0x8300_2108;
const IOCTL_READ_DWORD_256K: u32 = 0x8300_2110;
const IOCTL_READ_DWORD_16M: u32 = 0x8300_20DC;
const IOCTL_READ_WORD_16M: u32 = 0x8300_20E4;
const IOCTL_WRITE_DWORD_16M: u32 = 0x8300_20E0;
const IOCTL_WRITE_WORD_16M: u32 = 0x8300_20E8;
const IOCTL_WRITE_BYTE_16M: u32 = 0x8300_20F0;

/// Which IOMap64 mapping slot to use after a map IOCTL succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapSlot {
    /// 256 KiB window (`IOCTL 0x83002104`).
    Phys256K,
    /// 16 MiB window slot 0 (`IOCTL 0x830020D0`).
    Phys16M0,
    /// 16 MiB window slot 1 (`IOCTL 0x83002118`).
    Phys16M1,
}

impl MapSlot {
    pub(crate) fn map_size(self) -> u32 {
        match self {
            Self::Phys256K => MAP_SIZE_256K,
            Self::Phys16M0 | Self::Phys16M1 => MAP_SIZE_16M,
        }
    }

    fn map_ioctl(self) -> u32 {
        match self {
            Self::Phys256K => IOCTL_MAP_256K,
            Self::Phys16M0 => IOCTL_MAP_16M_SLOT0,
            Self::Phys16M1 => IOCTL_MAP_16M_SLOT1,
        }
    }

    /// Slot index accepted by `IOCTL_GET_MAP_STATUS` (`0x83002134`).
    fn map_status_index(self) -> Option<u32> {
        match self {
            Self::Phys16M0 => Some(0),
            Self::Phys16M1 => Some(1),
            Self::Phys256K => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Phys256K => "256k",
            Self::Phys16M0 => "16m0",
            Self::Phys16M1 => "16m1",
        }
    }
}

/// Result of a map or map-query IOCTL (`MapPhysRequest` in/out).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MapResult {
    pub physical: u64,
    pub kernel_va: u64,
}

/// Input buffer for map IOCTLs (`bus`, `dev`, `phys_lo`, `phys_hi` — last two updated by driver).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MapPhysRequest {
    bus: u32,
    dev: u32,
    phys_lo: u32,
    phys_hi: u32,
}

/// IOMap64 device handle wrapper.
pub(crate) struct IOMapClient {
    handle: HANDLE,
    active: Option<MapSlot>,
}

impl IOMapClient {
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
        .with_context(|| format!("CreateFileW failed for {path} (is IOMap64.sys loaded?)"))?;
        Ok(Self {
            handle,
            active: None,
        })
    }

    pub(crate) fn get_max_map_size(&self) -> anyhow::Result<u32> {
        let mut out = 0u32;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_GET_MAX_MAP_SIZE,
                None,
                0,
                Some(std::ptr::from_mut(&mut out).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        if returned != size_of::<u32>() as u32 {
            bail!("IOCTL_GET_MAX_MAP_SIZE returned {returned} bytes");
        }
        Ok(out)
    }

    /// Map `physical` into a driver window. Requires a PCI device at `bus`/`dev` with class 0x03.
    pub(crate) fn map_physical(
        &mut self,
        slot: MapSlot,
        physical: u64,
        bus: u32,
        dev: u32,
    ) -> anyhow::Result<MapResult> {
        let result = self.map_physical_ioctl(slot, physical, bus, dev)?;
        self.active = Some(slot);
        println!(
            "mapped {:#x}..{:#x} into {} (bus={bus} dev={dev})",
            result.physical,
            result.physical + slot.map_size() as u64,
            slot.label()
        );
        println!("kernel_va: {:#x}", result.kernel_va);
        Ok(result)
    }

    /// Issue a map IOCTL and parse the in/out buffer (also used to refresh/query kernel VA).
    fn map_physical_ioctl(
        &self,
        slot: MapSlot,
        physical: u64,
        bus: u32,
        dev: u32,
    ) -> anyhow::Result<MapResult> {
        if physical > u32::MAX as u64 {
            bail!("physical address must fit in 32 bits for this driver build");
        }

        let mut req = MapPhysRequest {
            bus,
            dev,
            phys_lo: physical as u32,
            phys_hi: 0,
        };
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                slot.map_ioctl(),
                Some(std::ptr::from_mut(&mut req).cast::<c_void>()),
                size_of::<MapPhysRequest>() as u32,
                Some(std::ptr::from_mut(&mut req).cast::<c_void>()),
                size_of::<MapPhysRequest>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }

        Ok(MapResult {
            physical: req.phys_lo as u64,
            kernel_va: req.phys_hi as u64,
        })
    }

    /// Query whether a 16M slot currently holds a mapping (`IOCTL 0x83002134`).
    pub(crate) fn query_map_status(&self, slot: MapSlot) -> anyhow::Result<bool> {
        let index = slot
            .map_status_index()
            .ok_or_else(|| anyhow::anyhow!("256k slot has no status IOCTL; use probe or --phys"))?;

        let mut buf = index;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_GET_MAP_STATUS,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut buf).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(buf != 0)
    }

    /// Probe whether the 256K window responds to read IOCTLs.
    fn probe_256k_mapped(&self) -> bool {
        self.read_byte_256k(0).is_ok()
    }

    /// Get kernel VA for a slot. Uses map-status IOCTL for 16M when unmapped; with `--phys`
    /// re-issues the map IOCTL (remaps) and reads `kernel_va` from the output buffer.
    pub(crate) fn get_mapped_va(
        &self,
        slot: MapSlot,
        physical: Option<u64>,
        bus: u32,
        dev: u32,
    ) -> anyhow::Result<Option<MapResult>> {
        match slot {
            MapSlot::Phys16M0 | MapSlot::Phys16M1 => {
                let mapped = self.query_map_status(slot)?;
                if !mapped {
                    return Ok(None);
                }
                if let Some(phys) = physical {
                    return Ok(Some(self.map_physical_ioctl(slot, phys, bus, dev)?));
                }
                bail!(
                    "{} is mapped but kernel VA is not exposed by status IOCTL; pass --phys to refresh via map IOCTL",
                    slot.label()
                );
            }
            MapSlot::Phys256K => {
                if !self.probe_256k_mapped() {
                    return Ok(None);
                }
                let phys = physical.ok_or_else(|| {
                    anyhow::anyhow!("256k slot is mapped; pass --phys to query kernel VA via map IOCTL")
                })?;
                Ok(Some(self.map_physical_ioctl(slot, phys, bus, dev)?))
            }
        }
    }

    pub(crate) fn active_slot(&self) -> anyhow::Result<MapSlot> {
        self.active
            .ok_or_else(|| anyhow::anyhow!("no active mapping; run map first"))
    }

    pub(crate) fn read_bytes(&self, offset: u32, size: usize) -> anyhow::Result<Vec<u8>> {
        let slot = self.active_slot()?;
        let max = slot.map_size();
        if offset as u64 + size as u64 > max as u64 {
            bail!("read range {offset:#x}+{size:#x} exceeds map size {max:#x}");
        }

        let mut out = Vec::with_capacity(size);
        match slot {
            MapSlot::Phys256K => {
                let mut pos = 0usize;
                while pos < size {
                    let off = offset + pos as u32;
                    if size - pos >= 4 && off % 4 == 0 {
                        let v = self.read_dword_256k(off)?;
                        let chunk = v.to_le_bytes();
                        let take = (size - pos).min(4);
                        out.extend_from_slice(&chunk[..take]);
                        pos += take;
                    } else {
                        out.push(self.read_byte_256k(off)?);
                        pos += 1;
                    }
                }
            }
            MapSlot::Phys16M0 | MapSlot::Phys16M1 => {
                let mut pos = 0usize;
                while pos < size {
                    let off = offset + pos as u32;
                    if size - pos >= 4 && off % 4 == 0 {
                        let v = self.read_dword_16m(off)?;
                        let chunk = v.to_le_bytes();
                        let take = (size - pos).min(4);
                        out.extend_from_slice(&chunk[..take]);
                        pos += take;
                    } else if size - pos >= 2 && off % 2 == 0 {
                        let v = self.read_word_16m(off)?;
                        let chunk = v.to_le_bytes();
                        let take = (size - pos).min(2);
                        out.extend_from_slice(&chunk[..take]);
                        pos += take;
                    } else {
                        out.push(self.read_byte_16m(off)?);
                        pos += 1;
                    }
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn write_bytes(&self, offset: u32, data: &[u8]) -> anyhow::Result<()> {
        let slot = self.active_slot()?;
        let max = slot.map_size();
        if offset as u64 + data.len() as u64 > max as u64 {
            bail!("write range {offset:#x}+{} exceeds map size {max:#x}", data.len());
        }

        match slot {
            MapSlot::Phys256K => bail!("256K slot is read-only via known IOCTLs; use 16M slot for writes"),
            MapSlot::Phys16M0 | MapSlot::Phys16M1 => {
                let mut pos = 0usize;
                while pos < data.len() {
                    let off = offset + pos as u32;
                    if data.len() - pos >= 4 && off % 4 == 0 {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&data[pos..pos + 4]);
                        self.write_dword_16m(off, u32::from_le_bytes(buf))?;
                        pos += 4;
                    } else if data.len() - pos >= 2 && off % 2 == 0 {
                        let mut buf = [0u8; 2];
                        buf.copy_from_slice(&data[pos..pos + 2]);
                        self.write_word_16m(off, u16::from_le_bytes(buf))?;
                        pos += 2;
                    } else {
                        self.write_byte_16m(off, data[pos])?;
                        pos += 1;
                    }
                }
            }
        }
        Ok(())
    }

    fn read_dword_256k(&self, offset: u32) -> anyhow::Result<u32> {
        let mut in_off = offset;
        let mut out = 0u32;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_DWORD_256K,
                Some(std::ptr::from_mut(&mut in_off).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut out).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(out)
    }

    fn read_byte_256k(&self, offset: u32) -> anyhow::Result<u8> {
        let mut in_off = offset;
        let mut out = 0u32;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_BYTE_256K,
                Some(std::ptr::from_mut(&mut in_off).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut out).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(out as u8)
    }

    fn read_word_16m(&self, offset: u32) -> anyhow::Result<u16> {
        let mut in_off = offset;
        let mut out = 0u32;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_WORD_16M,
                Some(std::ptr::from_mut(&mut in_off).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut out).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(out as u16)
    }

    fn read_dword_16m(&self, offset: u32) -> anyhow::Result<u32> {
        let mut in_off = offset;
        let mut out = 0u32;
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_DWORD_16M,
                Some(std::ptr::from_mut(&mut in_off).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut out).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(out)
    }

    fn read_byte_16m(&self, offset: u32) -> anyhow::Result<u8> {
        let dword_base = offset & !3;
        let shift = (offset & 3) * 8;
        let dword = self.read_dword_16m(dword_base)?;
        Ok((dword >> shift) as u8)
    }

    fn write_byte_16m(&self, offset: u32, value: u8) -> anyhow::Result<()> {
        let mut buf = [0u8; 8];
        buf[0] = value;
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_WRITE_BYTE_16M,
                Some(buf.as_mut_ptr().cast::<c_void>()),
                8,
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(())
    }

    fn write_word_16m(&self, offset: u32, value: u16) -> anyhow::Result<()> {
        let mut buf = [0u8; 8];
        buf[..2].copy_from_slice(&value.to_le_bytes());
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_WRITE_WORD_16M,
                Some(buf.as_mut_ptr().cast::<c_void>()),
                8,
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(())
    }

    fn write_dword_16m(&self, offset: u32, value: u32) -> anyhow::Result<()> {
        let mut buf = [0u8; 20];
        buf[12..16].copy_from_slice(&value.to_le_bytes());
        buf[16..20].copy_from_slice(&offset.to_le_bytes());
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_WRITE_DWORD_16M,
                Some(buf.as_mut_ptr().cast::<c_void>()),
                20,
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )?;
        }
        Ok(())
    }
}

impl Drop for IOMapClient {
    fn drop(&mut self) {
        unsafe {
            let _unused = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

fn to_wide(path: &str) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

fn parse_address(input: &str) -> anyhow::Result<u64> {
    let trimmed = input.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(trimmed, 16).with_context(|| format!("invalid address: {input}"))
}

fn parse_slot(input: &str) -> anyhow::Result<MapSlot> {
    match input {
        "256k" | "256K" | "0" => Ok(MapSlot::Phys256K),
        "16m0" | "16M0" | "1" => Ok(MapSlot::Phys16M0),
        "16m1" | "16M1" | "2" => Ok(MapSlot::Phys16M1),
        other => bail!("unknown slot {other:?}; use 256k, 16m0, or 16m1"),
    }
}

/// Scan bus/dev pairs that pass IOMap_ValidatePciDevice (class 0x03 display controller).
pub(crate) fn scan_valid_pci() -> anyhow::Result<()> {
    let client = IOMapClient::open(IOMAP_DEVICE_PATH)?;
    println!("scanning PCI bus/dev for IOMap64 validation (class 0x03)...");
    let mut found = 0usize;
    for bus in 0..=0x10u32 {
        for dev in 0..=0x20u32 {
            let mut req = MapPhysRequest {
                bus,
                dev,
                phys_lo: 0,
                phys_hi: 0,
            };
            let mut returned = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    client.handle,
                    IOCTL_MAP_256K,
                    Some(std::ptr::from_mut(&mut req).cast::<c_void>()),
                    size_of::<MapPhysRequest>() as u32,
                    Some(std::ptr::from_mut(&mut req).cast::<c_void>()),
                    size_of::<MapPhysRequest>() as u32,
                    Some(std::ptr::from_mut(&mut returned)),
                    None,
                )
            };
            if ok.is_ok() {
                println!("  valid: bus={bus:3} dev={dev:3} (dev={dev:#x})");
                found += 1;
            }
        }
    }
    println!("found {found} valid bus/dev pair(s)");
    if found > 0 {
        println!("hint: use --bus {DEFAULT_PCI_BUS} --dev {DEFAULT_PCI_DEV} (or any pair above) with map/dump");
    }
    Ok(())
}

fn parse_slot_or_all(input: &str) -> anyhow::Result<Vec<MapSlot>> {
    match input {
        "all" | "ALL" => Ok(vec![MapSlot::Phys256K, MapSlot::Phys16M0, MapSlot::Phys16M1]),
        other => Ok(vec![parse_slot(other)?]),
    }
}

fn print_va_line(slot: MapSlot, mapped: bool, result: Option<MapResult>) {
    print!("{}: ", slot.label());
    if !mapped {
        println!("not mapped");
        return;
    }
    if let Some(info) = result {
        println!(
            "mapped  physical={:#x}  kernel_va={:#x}",
            info.physical, info.kernel_va
        );
    } else {
        println!("mapped  (kernel_va unknown — pass --phys to query)");
    }
}

fn query_va_slots(
    client: &IOMapClient,
    slots: &[MapSlot],
    physical: Option<u64>,
    bus: u32,
    dev: u32,
) -> anyhow::Result<()> {
    for &slot in slots {
        match client.get_mapped_va(slot, physical, bus, dev) {
            Ok(None) => print_va_line(slot, false, None),
            Ok(Some(info)) => print_va_line(slot, true, Some(info)),
            Err(e) if physical.is_none() => {
                let mapped = match slot {
                    MapSlot::Phys256K => client.probe_256k_mapped(),
                    MapSlot::Phys16M0 | MapSlot::Phys16M1 => client.query_map_status(slot).unwrap_or(false),
                };
                if mapped {
                    print_va_line(slot, true, None);
                } else {
                    print_va_line(slot, false, None);
                }
                if mapped {
                    eprintln!("  note: {}", e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[derive(Subcommand)]
pub(crate) enum Iomap64Action {
    /// Query driver max map size (`IOCTL 0x830020D8`).
    Info,
    /// Brute-scan PCI bus/dev pairs accepted by the driver's weak validator.
    Scan,
    /// Show current mapping status / kernel virtual address per slot.
    Va {
        /// Slot to query (`256k`, `16m0`, `16m1`, or `all`).
        #[arg(long, default_value = "all")]
        slot: String,
        /// Physical address used for map IOCTL refresh (required to obtain kernel VA).
        #[arg(long)]
        phys: Option<String>,
        #[arg(long, default_value_t = DEFAULT_PCI_BUS)]
        bus: u32,
        #[arg(long, default_value_t = DEFAULT_PCI_DEV)]
        dev: u32,
    },
    /// Map a physical address range into a driver window.
    Map {
        /// Physical address to map.
        address: String,
        /// Mapping slot: `256k` (256 KiB), `16m0` or `16m1` (16 MiB).
        #[arg(long, default_value = "16m0")]
        slot: String,
        /// PCI bus number for validation bypass.
        #[arg(long, default_value_t = DEFAULT_PCI_BUS)]
        bus: u32,
        /// PCI device number for validation bypass.
        #[arg(long, default_value_t = DEFAULT_PCI_DEV)]
        dev: u32,
    },
    /// Read bytes from the active mapped window at `offset`.
    Read {
        /// Offset within the mapped window.
        #[arg(long, default_value = "0")]
        offset: String,
        #[arg(short, long, default_value_t = 64)]
        size: u32,
        /// Mapped slot to read from (must match prior `map`).
        #[arg(long, default_value = "16m0")]
        slot: String,
    },
    /// Write hex bytes at `offset` within the active 16M mapped window.
    Write {
        #[arg(long, default_value = "0")]
        offset: String,
        #[arg(long)]
        hex: String,
        /// Mapped slot to write into (must match prior `map`).
        #[arg(long, default_value = "16m0")]
        slot: String,
    },
    /// Map physical memory and dump `size` bytes (combines map + read).
    Dump {
        /// Host physical address.
        address: String,
        #[arg(short, long, default_value_t = 256)]
        size: u32,
        #[arg(long, default_value = "16m0")]
        slot: String,
        #[arg(long, default_value_t = DEFAULT_PCI_BUS)]
        bus: u32,
        #[arg(long, default_value_t = DEFAULT_PCI_DEV)]
        dev: u32,
    },
}

pub(crate) fn run_iomap64(device: Option<&str>, action: Iomap64Action) -> anyhow::Result<()> {
    let path = device.unwrap_or(IOMAP_DEVICE_PATH);
    println!("opening: {path}");

    match action {
        Iomap64Action::Scan => scan_valid_pci(),
        other => {
            let mut client = IOMapClient::open(path)?;
            match other {
                Iomap64Action::Info => {
                    let max = client.get_max_map_size()?;
                    println!("max map size: {max:#x} ({max} bytes)");
                    println!("256K map IOCTL: {IOCTL_MAP_256K:#010x}");
                    println!("16M  map IOCTL: {IOCTL_MAP_16M_SLOT0:#010x} / {IOCTL_MAP_16M_SLOT1:#010x}");
                    println!("map status IOCTL: {IOCTL_GET_MAP_STATUS:#010x}");
                    Ok(())
                }
                Iomap64Action::Va { slot, phys, bus, dev } => {
                    let slots = parse_slot_or_all(&slot)?;
                    let physical = phys
                        .as_deref()
                        .map(parse_address)
                        .transpose()?;
                    query_va_slots(&client, &slots, physical, bus, dev)
                }
                Iomap64Action::Map {
                    address,
                    slot,
                    bus,
                    dev,
                } => {
                    let phys = parse_address(&address)?;
                    let slot = parse_slot(&slot)?;
                    let _ = client.map_physical(slot, phys, bus, dev)?;
                    Ok(())
                }
                Iomap64Action::Read { offset, size, slot } => {
                    let offset = parse_address(&offset)? as u32;
                    let slot = parse_slot(&slot)?;
                    client.active = Some(slot);
                    let data = client.read_bytes(offset, size as usize)?;
                    println!("read {} bytes at offset {offset:#x}:", data.len());
                    println!("{}", hex::encode(&data));
                    Ok(())
                }
                Iomap64Action::Write { offset, hex, slot } => {
                    let offset = parse_address(&offset)? as u32;
                    let slot = parse_slot(&slot)?;
                    client.active = Some(slot);
                    let data = hex::decode(hex.replace(' ', "")).context("invalid hex payload")?;
                    client.write_bytes(offset, &data)?;
                    println!("wrote {} bytes at offset {offset:#x}", data.len());
                    Ok(())
                }
                Iomap64Action::Dump {
                    address,
                    size,
                    slot,
                    bus,
                    dev,
                } => {
                    let phys = parse_address(&address)?;
                    let slot = parse_slot(&slot)?;
                    let size = size as usize;
                    if size == 0 {
                        bail!("size must be > 0");
                    }
                    if size as u64 > slot.map_size() as u64 {
                        bail!("size exceeds slot map window ({:#x})", slot.map_size());
                    }
                    let _ = client.map_physical(slot, phys, bus, dev)?;
                    let data = client.read_bytes(0, size)?;
                    println!("dump {size} bytes from physical {phys:#x}:");
                    print_hex_dump(phys, &data);
                    Ok(())
                }
                Iomap64Action::Scan => unreachable!(),
            }
        }
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
