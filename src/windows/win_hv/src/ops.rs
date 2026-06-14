//! This module implements Windows kernel driver-based implementation of
//! [`hv::PlatformOps`].

use core::ffi::c_void;

use hv::platform_ops::PlatformOps;
use wdk_sys::{
    ALL_PROCESSOR_GROUPS, GROUP_AFFINITY, KDPC, NT_SUCCESS, PAGED_CODE, PKDEFERRED_ROUTINE,
    PROCESSOR_NUMBER,
    ntddk::{
        KeGetCurrentProcessorNumberEx, KeGetProcessorNumberFromIndex,
        KeQueryActiveProcessorCountEx, KeRevertToUserGroupAffinityThread,
        KeSetSystemGroupAffinityThread, MmGetPhysicalAddress,
    },
};

#[link(name = "ntoskrnl")]
unsafe extern "system" {
    fn KeGenericCallDpc(
        broadcast_function: PKDEFERRED_ROUTINE,
        context: *mut c_void,
    );
    fn KeSignalCallDpcSynchronize(system_argument2: *mut c_void);
    fn KeSignalCallDpcDone(system_argument1: *mut c_void);
}

pub(crate) struct WindowsOps;

fn current_processor_label() -> (u16, u8) {
    let mut processor_number = PROCESSOR_NUMBER::default();
    unsafe { KeGetCurrentProcessorNumberEx(&raw mut processor_number) };
    (processor_number.Group, processor_number.Number)
}

unsafe extern "C" fn broadcast_dpc_routine(
    _dpc: *mut KDPC,
    deferred_context: *mut c_void,
    system_argument1: *mut c_void,
    system_argument2: *mut c_void,
) {
    let (group, number) = current_processor_label();
    crate::eprintln!("devirt dpc: group={group} cpu={number} enter");

    let callback: fn() = unsafe { core::mem::transmute(deferred_context) };
    callback();

    crate::eprintln!("devirt dpc: group={group} cpu={number} callback returned, syncing");
    unsafe {
        KeSignalCallDpcSynchronize(system_argument2);
        KeSignalCallDpcDone(system_argument1);
    }
    crate::eprintln!("devirt dpc: group={group} cpu={number} done");
}

impl PlatformOps for WindowsOps {
    fn run_on_all_processors(&self, callback: fn()) {
        fn processor_count() -> u32 {
            unsafe { KeQueryActiveProcessorCountEx(u16::try_from(ALL_PROCESSOR_GROUPS).unwrap()) }
        }

        PAGED_CODE!();

        for index in 0..processor_count() {
            let mut processor_number = PROCESSOR_NUMBER::default();
            let status = unsafe { KeGetProcessorNumberFromIndex(index, &raw mut processor_number) };
            assert!(NT_SUCCESS(status));

            let mut old_affinity = GROUP_AFFINITY::default();
            let mut affinity = GROUP_AFFINITY {
                Group: processor_number.Group,
                Mask: 1 << processor_number.Number,
                Reserved: [0, 0, 0],
            };
            unsafe { KeSetSystemGroupAffinityThread(&raw mut affinity, &raw mut old_affinity) };

            callback();

            unsafe { KeRevertToUserGroupAffinityThread(&raw mut old_affinity) };
        }
    }

    fn broadcast_on_all_processors(&self, callback: fn()) {
        crate::eprintln!("devirt: KeGenericCallDpc broadcast begin");
        unsafe {
            KeGenericCallDpc(Some(broadcast_dpc_routine), callback as *mut c_void);
        }
        crate::eprintln!("devirt: KeGenericCallDpc broadcast returned");
    }

    fn pa(&self, va: *const core::ffi::c_void) -> u64 {
        #[expect(clippy::cast_sign_loss)]
        unsafe {
            MmGetPhysicalAddress(va.cast_mut()).QuadPart as u64
        }
    }
}
