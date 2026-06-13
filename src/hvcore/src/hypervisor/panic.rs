pub fn panic_impl(info: &core::panic::PanicInfo<'_>) -> ! {
    crate::hv_dbg!("PANIC: {info}");
    log::error!("{info}");
    loop {
        unsafe {
            x86::irq::disable();
            x86::halt();
        };
    }
}
