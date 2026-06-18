//! This module implements enablement and disablement of AMD SVM.

use crate::hypervisor::{
    host::Extension,
    x86_instructions::{rdmsr, wrmsr},
};

#[derive(Default)]
pub(crate) struct Svm {
    saved_efer: u64,
}

impl Extension for Svm {
    fn enable(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        // Enable SVM. We assume the processor is compatible with this.
        // See: 15.4 Enabling SVM
        self.saved_efer = rdmsr(x86::msr::IA32_EFER);
        wrmsr(x86::msr::IA32_EFER, self.saved_efer | EFER_SVME);
    }

    fn disable(&mut self) {
        wrmsr(x86::msr::IA32_EFER, self.saved_efer);
    }
}
