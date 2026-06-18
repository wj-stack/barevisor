//! DbgPrint-based implementation of the `log` crate for kernel debugger output.

use spin::Once;

use crate::eprintln;

static LOGGER: Once<DbgLogger> = Once::new();

/// Registers the DbgPrint logger and sets the maximum log level.
pub(crate) fn init(level: log::LevelFilter) {
    let logger = LOGGER.call_once(DbgLogger::new);
    log::set_logger(logger).unwrap();
    log::set_max_level(level);
}

struct DbgLogger;

impl DbgLogger {
    const fn new() -> Self {
        Self
    }
}

impl log::Log for DbgLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln::print(format_args!(
                "#{}:{:5}: {}\n",
                apic_id(),
                record.level(),
                record.args()
            ));
        }
    }

    fn flush(&self) {}
}

fn apic_id() -> u8 {
    // See: (AMD) CPUID Fn0000_0001_EBX LocalApicId, LogicalProcessorCount, CLFlush
    // See: (Intel) Table 3-8. Information Returned by CPUID Instruction
    (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8
}
