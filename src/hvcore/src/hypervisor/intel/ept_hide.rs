//! Hide host physical pages from the guest via EPT (redirect reads to a zero page).

use core::ptr::addr_of;

use spin::LazyLock;
use x86::bits64::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE};

use crate::hypervisor::platform_ops;
use crate::hypervisor::support::zeroed_box;

use super::epts::{EptError, EptState};

#[repr(C, align(4096))]
struct ZeroPage {
    bytes: [u8; BASE_PAGE_SIZE],
}

static ZERO_PAGE: LazyLock<ZeroPage> = LazyLock::new(|| *zeroed_box::<ZeroPage>());

/// Errors while hiding guest access to a physical range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HideError {
    Ept(EptError),
}

fn zero_pfn() -> u64 {
    platform_ops::get().pa(addr_of!(ZERO_PAGE.bytes) as *const _) >> BASE_PAGE_SHIFT
}

/// Redirects each 4 KB page in `[start_pa, start_pa + size)` to a shared zero page.
pub fn hide_physical_range(ept: &mut EptState, start_pa: u64, size: u64) -> Result<u32, HideError> {
    ept.hide_physical_range(start_pa, size, zero_pfn())
        .map_err(HideError::Ept)
}
