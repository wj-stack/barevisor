//! Optional host-side debug output (e.g. Windows `DbgPrintEx`).

use core::fmt::Write;
use spin::Once;

static DEBUG_PRINT: Once<fn(&str)> = Once::new();

/// Registers a platform callback that prints a null-terminated ASCII line.
pub fn set_debug_print(callback: fn(&str)) {
    let _ = DEBUG_PRINT.call_once(|| callback);
}

pub(crate) fn print(args: core::fmt::Arguments<'_>) {
    let mut buffer = [0u8; 384];
    struct BufWriter<'a> {
        buffer: &'a mut [u8],
        length: usize,
    }

    impl Write for BufWriter<'_> {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let remaining = self.buffer.len().saturating_sub(self.length);
            let count = text.len().min(remaining);
            self.buffer[self.length..self.length + count].copy_from_slice(&text.as_bytes()[..count]);
            self.length += count;
            Ok(())
        }
    }

    let mut writer = BufWriter {
        buffer: &mut buffer,
        length: 0,
    };
    let _ = writer.write_fmt(args);
    let length = writer.length.min(buffer.len().saturating_sub(1));
    buffer[length] = 0;

    if let Some(print) = DEBUG_PRINT.get() {
        if let Ok(message) = core::str::from_utf8(&buffer[..length]) {
            print(message);
        }
    } else {
        log::info!("{}", core::str::from_utf8(&buffer[..length]).unwrap_or("?"));
    }
}

#[macro_export]
macro_rules! hv_dbg {
    ($($arg:tt)*) => {
        $crate::hypervisor::debug_out::print(format_args!($($arg)*))
    };
}
