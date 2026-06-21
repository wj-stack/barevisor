//! DbgPrint logging for stealth helpers (no heap allocation).

use core::fmt::Write;

use wdk_sys::{_DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, ntddk::DbgPrintEx};

struct LineWriter {
    buf: [u8; 384],
    len: usize,
}

impl LineWriter {
    const fn new() -> Self {
        Self {
            buf: [0; 384],
            len: 0,
        }
    }

    fn flush_line(&mut self) {
        if self.len == 0 {
            return;
        }
        if self.buf[self.len - 1] != b'\n' {
            if self.len + 1 < self.buf.len() {
                self.buf[self.len] = b'\n';
                self.len += 1;
            }
        }
        let msg_ptr = self.buf.as_mut_ptr().cast::<i8>();
        let _ = unsafe {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID as _,
                DPFLTR_ERROR_LEVEL,
                c"%s".as_ptr(),
                msg_ptr,
            )
        };
        self.len = 0;
    }
}

impl Write for LineWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if !s.is_ascii() {
            return Err(core::fmt::Error);
        }
        for byte in s.bytes() {
            if self.len + 1 >= self.buf.len() {
                self.flush_line();
            }
            if byte == b'\n' {
                self.flush_line();
            } else if self.len + 1 < self.buf.len() {
                self.buf[self.len] = byte;
                self.len += 1;
            }
        }
        Ok(())
    }
}

pub(crate) fn print(args: core::fmt::Arguments<'_>) {
    let mut writer = LineWriter::new();
    let _ = writer.write_fmt(args);
    writer.flush_line();
}
