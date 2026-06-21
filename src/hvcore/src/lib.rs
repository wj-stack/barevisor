#![no_std]

extern crate alloc;

pub mod hypervisor;

pub use hypervisor::SharedHostData;
#[cfg(not(test))]
pub use hypervisor::allocator;
pub use hypervisor::debug_out::set_debug_print;
pub use hypervisor::gdt_tss::GdtTss;
pub use hypervisor::hypercall;
pub use hypervisor::interrupt_handlers::InterruptDescriptorTable;
pub use hypervisor::paging_structures::PagingStructures;
pub use hypervisor::panic::panic_impl;
pub use hypervisor::platform_ops;
pub use hypervisor::devirtualize_system;
pub use hypervisor::hide_guest_physical_memory;
pub use hypervisor::virtualize_system;
