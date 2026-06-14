# Intel Devirtualize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Exit Intel VMX on all logical processors via `devirtualize_system()` (HyperDbg-style `VMCALL` + DPC broadcast) and allow `virtualize_system()` to run again.

**Architecture:** Platform API sets `DEVIRT_IN_PROGRESS`, uninstalls EPT hooks, broadcasts `hypercall::vmxoff()` per CPU (`KeGenericCallDpc` on Windows). Each `VMCALL` VM-exit runs `perform_vmxoff` (10-step HyperDbg sequence) then `exit_vmx_to_guest` asm — no return to host loop. Global EPT resets for re-virtualize.

**Tech Stack:** Rust `no_std`, Intel VMX, `wdk-sys` (Windows DPC), UEFI MpServices fallback, GNU/MSVC inline asm in `run_guest.S`.

**Spec:** [`docs/superpowers/specs/2026-06-14-intel-devirtualize-design.md`](../specs/2026-06-14-intel-devirtualize-design.md)

---

## File map

| File | Responsibility |
|------|----------------|
| `src/hvcore/src/hypervisor/platform_ops.rs` | Add `broadcast_on_all_processors` |
| `src/windows/win_hv/src/ops.rs` | `KeGenericCallDpc` implementation |
| `src/uefi/uefi_hv/src/ops.rs` | Delegate broadcast to `run_on_all_processors` |
| `src/hvcore/src/hypervisor/hypercall.rs` | `HV_HYPERCALL_VMXOFF`, `vmxoff()` |
| `src/hvcore/src/hypervisor/mod.rs` | `devirtualize_system`, `devirt_in_progress`, `is_virtualized` |
| `src/hvcore/src/lib.rs` | Re-export `devirtualize_system` |
| `src/hvcore/src/hypervisor/intel/devirt.rs` | **new** — `DevirtState`, `hv_restore_registers`, `perform_vmxoff` |
| `src/hvcore/src/hypervisor/intel/mod.rs` | `mod devirt;` |
| `src/hvcore/src/hypervisor/intel/vmx.rs` | `Extension::disable`, `vmclear`/`vmxoff` helpers |
| `src/hvcore/src/hypervisor/intel/run_guest.S` | `exit_vmx_to_guest`, `restore_guest_xmm` |
| `src/hvcore/src/hypervisor/intel/guest.rs` | `Guest::devirtualize`, VMCS read helpers |
| `src/hvcore/src/hypervisor/intel/ept_hook.rs` | `uninstall_all()` |
| `src/hvcore/src/hypervisor/intel/epts.rs` | `invept_all_contexts`, `EptState::reset` |
| `src/hvcore/src/hypervisor/host.rs` | VMXOFF in `handle_vmcall`, `Extension::disable` on trait |
| `src/hvcore/src/hypervisor/amd/svm.rs` | `disable()` stub |
| `src/windows/win_hv/src/device.rs` | `hv::devirtualize_system()` in `driver_unload` |

---

### Task 1: `broadcast_on_all_processors` (platform trait)

**Files:**
- Modify: `src/hvcore/src/hypervisor/platform_ops.rs`
- Modify: `src/windows/win_hv/src/ops.rs`
- Modify: `src/uefi/uefi_hv/src/ops.rs`

- [ ] **Step 1: Extend trait**

```rust
// platform_ops.rs
pub trait PlatformOps {
    fn run_on_all_processors(&self, callback: fn());
    /// Runs `callback` on every logical processor in parallel (DPC on Windows).
    fn broadcast_on_all_processors(&self, callback: fn()) {
        self.run_on_all_processors(callback); // default: sequential
    }
    fn pa(&self, va: *const core::ffi::c_void) -> u64;
}
```

- [ ] **Step 2: Windows `KeGenericCallDpc`**

```rust
// ops.rs — add imports:
use core::ffi::c_void;
use wdk_sys::ntddk::{KeGenericCallDpc, KeSignalCallDpcDone, KeSignalCallDpcSynchronize};
use wdk_sys::PKDEFERRED_ROUTINE;

unsafe extern "C" fn broadcast_dpc_routine(
    _dpc: *mut wdk_sys::KDPC,
    deferred_context: *mut c_void,
    system_argument1: *mut c_void,
    system_argument2: *mut c_void,
) {
    let callback: fn() = core::mem::transmute(deferred_context);
    callback();
    KeSignalCallDpcSynchronize(system_argument2);
    KeSignalCallDpcDone(system_argument1);
}

impl PlatformOps for WindowsOps {
    fn broadcast_on_all_processors(&self, callback: fn()) {
        unsafe {
            KeGenericCallDpc(
                Some(broadcast_dpc_routine),
                callback as *mut c_void,
            );
        }
    }
    // run_on_all_processors unchanged
}
```

- [ ] **Step 3: UEFI fallback**

```rust
// uefi_hv/src/ops.rs
fn broadcast_on_all_processors(&self, callback: fn()) {
    self.run_on_all_processors(callback);
}
```

- [ ] **Step 4: Build check**

Run: `cd src/windows && cargo build -p win_hv 2>&1 | tail -20`  
Expected: compiles (may fail later until all tasks done — at minimum no trait errors from Task 1 if hvcore compiles).

- [ ] **Step 5: Commit**

```bash
git add src/hvcore/src/hypervisor/platform_ops.rs src/windows/win_hv/src/ops.rs src/uefi/uefi_hv/src/ops.rs
git commit -m "feat(hvcore): add broadcast_on_all_processors platform API"
```

---

### Task 2: VMXOFF hypercall constant

**Files:**
- Modify: `src/hvcore/src/hypervisor/hypercall.rs`

- [ ] **Step 1: Add constant and helper**

```rust
/// Turns off VMX on the current logical processor (only honored during `devirtualize_system`).
pub const HV_HYPERCALL_VMXOFF: u64 = 6;

#[inline]
pub fn vmxoff() -> bool {
    let (status, _, _, _) = issue(HV_HYPERCALL_VMXOFF, 0, 0, 0, 0);
    status == HV_HYPERCALL_SUCCESS
}
```

- [ ] **Step 2: Commit**

```bash
git add src/hvcore/src/hypervisor/hypercall.rs
git commit -m "feat(hvcore): add HV_HYPERCALL_VMXOFF hypercall"
```

---

### Task 3: Devirt globals and `devirtualize_system` skeleton

**Files:**
- Modify: `src/hvcore/src/hypervisor/mod.rs`
- Modify: `src/hvcore/src/lib.rs`

- [ ] **Step 1: Add globals and guard helper**

```rust
// mod.rs — after SHARED_HOST_DATA
use core::sync::atomic::{AtomicBool, Ordering};

static DEVIRT_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

pub(crate) fn devirt_in_progress() -> bool {
    DEVIRT_IN_PROGRESS.load(Ordering::SeqCst)
}

fn is_virtualized() -> bool {
    // After first full virtualize, any CPU sees Barevisor signature
    is_our_hypervisor_present()
}
```

- [ ] **Step 2: Add `devirtualize_system` skeleton**

```rust
pub fn devirtualize_system() {
    serial_logger::init(log::LevelFilter::Info);
    if !is_virtualized() {
        log::info!("devirtualize_system: not virtualized, skipping");
        return;
    }
    log::info!("Devirtualizing all processors");
    DEVIRT_IN_PROGRESS.store(true, Ordering::SeqCst);

    intel::ept_hook::uninstall_all();
    intel::epts::invept_all_contexts();

    platform_ops::get().broadcast_on_all_processors(|| {
        if !hypercall::vmxoff() {
            log::error!("vmxoff hypercall failed on this processor");
        }
    });

    intel::guest::reset_shared_guest_state();
    DEVIRT_IN_PROGRESS.store(false, Ordering::SeqCst);
    log::info!("Devirtualized all processors");
}
```

Add `pub use hypervisor::devirtualize_system;` in `lib.rs`.

Stub `uninstall_all`, `invept_all_contexts`, `reset_shared_guest_state` as empty fns in next tasks if needed for compile — or implement Task 4 first.

- [ ] **Step 3: Commit**

```bash
git add src/hvcore/src/hypervisor/mod.rs src/hvcore/src/lib.rs
git commit -m "feat(hvcore): add devirtualize_system entry skeleton"
```

---

### Task 4: EPT hook uninstall all + INVEPT all contexts

**Files:**
- Modify: `src/hvcore/src/hypervisor/intel/ept_hook.rs`
- Modify: `src/hvcore/src/hypervisor/intel/epts.rs`

- [ ] **Step 1: `uninstall_all` in ept_hook.rs**

```rust
pub(crate) fn uninstall_all() {
    let mut hooks = HOOKS.lock();
    let gpas: Vec<u64> = hooks
        .entries
        .iter()
        .filter_map(|e| e.map(|h| h.gpa_page_base))
        .collect();
    drop(hooks);

    if gpas.is_empty() {
        return;
    }
    let mut ept = super::guest::ept_state().lock();
    for gpa in gpas {
        let _ = uninstall(&mut ept, gpa);
    }
    invept_single_context(ept.eptp());
}
```

Expose `entries` via a method on `HookTable` if fields are private:

```rust
impl HookTable {
    fn hooked_gpas(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.iter().filter_map(|e| e.map(|h| h.gpa_page_base))
    }
    fn clear(&mut self) {
        self.entries = [None; MAX_HOOKS];
    }
}
```

Then `uninstall_all` clears the table after restoring PTEs.

- [ ] **Step 2: `invept_all_contexts` in epts.rs**

```rust
pub(crate) fn invept_all_contexts() {
    let descriptor = [0u64, 0u64];
    unsafe {
        #[cfg(target_env = "msvc")]
        core::arch::asm!(
            "invept rcx, [{desc}]",
            desc = in(reg) descriptor.as_ptr(),
            in("rcx") 2u64,
            options(nostack),
        );
        #[cfg(not(target_env = "msvc"))]
        core::arch::asm!(
            "invept ({desc}), {ty}",
            desc = in(reg) descriptor.as_ptr(),
            ty = in(reg) 2u64,
            options(nostack),
        );
    }
}
```

- [ ] **Step 3: `EptState::reset` and guest wrapper**

```rust
// epts.rs
impl EptState {
    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }
}

// guest.rs
pub(crate) fn reset_shared_guest_state() {
    SHARED_GUEST_DATA.ept.lock().reset();
    // MSR bitmap unchanged — all zeros is fine across cycles
}
```

- [ ] **Step 4: Commit**

```bash
git add src/hvcore/src/hypervisor/intel/ept_hook.rs src/hvcore/src/hypervisor/intel/epts.rs src/hvcore/src/hypervisor/intel/guest.rs
git commit -m "feat(hvcore): EPT hook uninstall_all and EptState reset"
```

---

### Task 5: Per-CPU `DevirtState` and `hv_restore_registers`

**Files:**
- Create: `src/hvcore/src/hypervisor/intel/devirt.rs`
- Modify: `src/hvcore/src/hypervisor/intel/mod.rs`
- Modify: `src/hvcore/src/hypervisor/intel/guest.rs` (re-export vmread helpers if needed)

- [ ] **Step 1: Create `devirt.rs`**

```rust
//! Intel VMXOFF teardown (port of HyperDbg VmxPerformVmxoff / HvRestoreRegisters).

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;

use x86::bits64::segmentation::{ds, es, fs, ss, SegmentSelector};
use x86::vmx::vmcs;

use crate::hypervisor::{
    apic_id::{self, PROCESSOR_COUNT},
    x86_instructions::{cr3_write, rdmsr, wrmsr},
};

use super::guest::{self, VmxGuest};

pub(crate) struct DevirtState {
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub is_done: AtomicBool,
}

static PER_CPU_DEVIRT: Once<Box<[DevirtState]>> = Once::new();

fn per_cpu_devirt() -> &'static [DevirtState] {
    PER_CPU_DEVIRT.call_once(|| {
        let n = PROCESSOR_COUNT.load(Ordering::Relaxed).max(1);
        (0..n)
            .map(|_| DevirtState {
                guest_rip: 0,
                guest_rsp: 0,
                is_done: AtomicBool::new(false),
            })
            .collect()
    })
}

fn current_devirt_state() -> &'static DevirtState {
    let id = apic_id::processor_id_from(apic_id::get()).unwrap_or(0);
    &per_cpu_devirt()[id]
}

pub(crate) fn devirt_guest_rip() -> u64 {
    current_devirt_state().guest_rip
}

pub(crate) fn devirt_guest_rsp() -> u64 {
    current_devirt_state().guest_rsp
}

fn vmread_u64(field: u32) -> u64 {
    unsafe { x86::vmx::vmread(field) }
}

fn vmread_u16(field: u32) -> u16 {
    vmread_u64(field) as u16
}

/// Port of HyperDbg `HvRestoreRegisters` — before VMXOFF.
pub(crate) fn hv_restore_registers() {
    let fs_base = vmread_u64(vmcs::guest::FS_BASE);
    let gs_base = vmread_u64(vmcs::guest::GS_BASE);
    wrmsr(x86::msr::IA32_FS_BASE, fs_base);
    wrmsr(x86::msr::IA32_GS_BASE, gs_base);

    let gdtr_base = vmread_u64(vmcs::guest::GDTR_BASE);
    let gdtr_limit = vmread_u64(vmcs::guest::GDTR_LIMIT) as u32;
    unsafe { reload_gdtr(gdtr_base, gdtr_limit) };

    let idtr_base = vmread_u64(vmcs::guest::IDTR_BASE);
    let idtr_limit = vmread_u64(vmcs::guest::IDTR_LIMIT) as u32;
    unsafe { reload_idtr(idtr_base, idtr_limit) };

    unsafe {
        ds.set(SegmentSelector::from_raw(vmread_u16(vmcs::guest::DS_SELECTOR)));
        es.set(SegmentSelector::from_raw(vmread_u16(vmcs::guest::ES_SELECTOR)));
        ss.set(SegmentSelector::from_raw(vmread_u16(vmcs::guest::SS_SELECTOR)));
        fs.set(SegmentSelector::from_raw(vmread_u16(vmcs::guest::FS_SELECTOR)));
    }
}

unsafe fn reload_gdtr(base: u64, limit: u32) {
    #[repr(C, packed)]
    struct Desc { limit: u16, base: u64 }
    let d = Desc { limit: limit as u16, base };
    core::arch::asm!(
        "lgdt [{}]",
        in(reg) &d,
        options(nostack),
    );
}

unsafe fn reload_idtr(base: u64, limit: u32) {
    #[repr(C, packed)]
    struct Desc { limit: u16, base: u64 }
    let d = Desc { limit: limit as u16, base };
    core::arch::asm!(
        "lidt [{}]",
        in(reg) &d,
        options(nostack),
    );
}
```

- [ ] **Step 2: Register module**

```rust
// intel/mod.rs
pub(crate) mod devirt;
```

- [ ] **Step 3: Commit**

```bash
git add src/hvcore/src/hypervisor/intel/devirt.rs src/hvcore/src/hypervisor/intel/mod.rs
git commit -m "feat(hvcore): add DevirtState and hv_restore_registers"
```

---

### Task 6: `perform_vmxoff` and `Vmx::disable`

**Files:**
- Modify: `src/hvcore/src/hypervisor/intel/devirt.rs`
- Modify: `src/hvcore/src/hypervisor/intel/vmx.rs`
- Modify: `src/hvcore/src/hypervisor/host.rs` (trait)

- [ ] **Step 1: `Extension::disable` on trait**

```rust
// host.rs
pub(crate) trait Extension: Default {
    fn enable(&mut self);
    fn disable(&mut self);
}
```

```rust
// amd/svm.rs
fn disable(&mut self) {
    panic!("AMD devirtualize not implemented");
}
```

- [ ] **Step 2: Intel `disable` in vmx.rs**

```rust
impl Extension for Vmx {
    fn disable(&mut self) {
        vmclear(&mut self.vmxon_region); // use Vmcs from guest instead — see below
    }
}

fn vmclear(vmcs_region: &mut VmxonRaw) { /* wrong type — use guest Vmcs */ }
```

`perform_vmxoff` receives `&mut VmxGuest` and calls `guest.vmcs_vmclear()` + `vmxoff` instruction. Add on `VmxGuest`:

```rust
pub(crate) fn vmclear_and_vmxoff(&mut self) {
    vmclear(&mut self.vmcs);
    unsafe { x86::bits64::vmx::vmxoff().unwrap() };
}
```

Clear `CR4.VMXE` in `perform_vmxoff` after `vmxoff`:

```rust
use x86::controlregs::{Cr4, cr4, cr4_write};
cr4_write(cr4() & !Cr4::CR4_ENABLE_VMX);
```

- [ ] **Step 3: `perform_vmxoff`**

```rust
// devirt.rs
use crate::hypervisor::hypercall::HV_HYPERCALL_SUCCESS;

unsafe extern "C" {
    fn restore_guest_xmm_regs(ptr: *const u8);
    fn exit_vmx_to_guest() -> !;
}

pub(crate) fn perform_vmxoff(guest: &mut VmxGuest) -> ! {
    // 1. Guest CR3
    let guest_cr3 = vmread_u64(vmcs::guest::CR3);
    cr3_write(guest_cr3);

    // 2–3. RIP/RSP + instruction length
    let mut guest_rip = vmread_u64(vmcs::guest::RIP);
    let guest_rsp = vmread_u64(vmcs::guest::RSP);
    let instr_len = vmread_u64(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
    guest_rip = guest_rip.wrapping_add(instr_len);

    let state = current_devirt_state();
    state.guest_rip = guest_rip;
    state.guest_rsp = guest_rsp;
    state.is_done.store(true, Ordering::SeqCst);

    // 6. Partial segment restore
    hv_restore_registers();

    // 7. XMM before VMXOFF
    unsafe { restore_guest_xmm_regs(guest.regs() as *const _ as *const u8) };

    // 8–9. VMCLEAR + VMXOFF
    guest.vmclear_and_vmxoff();

    // 10. CR4.VMXE
    use x86::controlregs::{Cr4, cr4, cr4_write};
    cr4_write(cr4() & !Cr4::CR4_ENABLE_VMX);

    guest.regs_mut().rax = HV_HYPERCALL_SUCCESS;

    unsafe { exit_vmx_to_guest() }
}
```

Add `regs_mut()` on `VmxGuest` if not on `Guest` trait.

- [ ] **Step 4: Commit**

```bash
git add src/hvcore/src/hypervisor/intel/devirt.rs src/hvcore/src/hypervisor/intel/vmx.rs src/hvcore/src/hypervisor/intel/guest.rs src/hvcore/src/hypervisor/host.rs src/hvcore/src/hypervisor/amd/svm.rs
git commit -m "feat(hvcore): implement perform_vmxoff sequence"
```

---

### Task 7: Assembly `exit_vmx_to_guest` and XMM restore

**Files:**
- Modify: `src/hvcore/src/hypervisor/intel/run_guest.S`
- Modify: `src/hvcore/src/hypervisor/intel/guest.rs` (global_asm exports)

- [ ] **Step 1: Add asm helpers** (port `AsmVmxoffRestoreXmmRegs` + `AsmVmxoffHandler`)

```asm
# run_guest.S — after run_vmx_guest

.global restore_guest_xmm_regs
restore_guest_xmm_regs:
    # rcx -> &Registers
    movaps  xmm0, [rcx + registers_xmm0]
    movaps  xmm1, [rcx + registers_xmm1]
    movaps  xmm2, [rcx + registers_xmm2]
    movaps  xmm3, [rcx + registers_xmm3]
    movaps  xmm4, [rcx + registers_xmm4]
    movaps  xmm5, [rcx + registers_xmm5]
    ret

.extern devirt_guest_rsp
.extern devirt_guest_rip

.global exit_vmx_to_guest
exit_vmx_to_guest:
    call    devirt_guest_rsp    # rax = rsp (Rust returns u64 in rax)
    mov     rsp, rax
    call    devirt_guest_rip    # rax = rip
    push    rax
    xor     rax, rax            # HV_HYPERCALL_SUCCESS already in guest rax from Rust
    ret
```

Rust exports for asm `.extern`:

```rust
#[unsafe(no_mangle)]
pub extern "C" fn devirt_guest_rsp() -> u64 {
    super::devirt::devirt_guest_rsp()
}
#[unsafe(no_mangle)]
pub extern "C" fn devirt_guest_rip() -> u64 {
    super::devirt::devirt_guest_rip()
}
```

Place in `guest.rs` or `devirt.rs`.

- [ ] **Step 2: Commit**

```bash
git add src/hvcore/src/hypervisor/intel/run_guest.S src/hvcore/src/hypervisor/intel/guest.rs src/hvcore/src/hypervisor/intel/devirt.rs
git commit -m "feat(hvcore): add exit_vmx_to_guest assembly path"
```

---

### Task 8: Wire `handle_vmcall` → `perform_vmxoff`

**Files:**
- Modify: `src/hvcore/src/hypervisor/host.rs`
- Modify: `src/hvcore/src/hypervisor/intel/guest.rs`

- [ ] **Step 1: `Guest::devirtualize`**

```rust
// host.rs trait
pub(crate) trait Guest {
    // ... existing ...
    fn devirtualize(&mut self) -> ! {
        panic!("devirtualize not supported for this architecture");
    }
}
```

```rust
// guest.rs
impl Guest for VmxGuest {
    fn devirtualize(&mut self) -> ! {
        super::devirt::perform_vmxoff(self)
    }
}
```

- [ ] **Step 2: VMXOFF branch in `handle_vmcall`**

```rust
use crate::hypervisor::{devirt_in_progress, hypercall::HV_HYPERCALL_VMXOFF};

fn handle_vmcall<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let hypercall = guest.regs().rax;
    if hypercall == HV_HYPERCALL_VMXOFF {
        if !devirt_in_progress() {
            guest.regs().rax = HV_HYPERCALL_INVALID;
            guest.regs().rip = info.next_rip;
            return;
        }
        guest.regs().rax = HV_HYPERCALL_SUCCESS;
        guest.devirtualize(); // !
    }
    // ... existing match for other hypercalls ...
    guest.regs().rax = status;
    guest.regs().rip = info.next_rip;
}
```

Import `HV_HYPERCALL_VMXOFF` at top of `host.rs`.

- [ ] **Step 3: Build**

Run: `cd src/windows && cargo build -p win_hv 2>&1 | tail -30`  
Expected: `Finished` or fix link/asm symbol errors.

- [ ] **Step 4: Commit**

```bash
git add src/hvcore/src/hypervisor/host.rs src/hvcore/src/hypervisor/intel/guest.rs
git commit -m "feat(hvcore): handle HV_HYPERCALL_VMXOFF in vmcall handler"
```

---

### Task 9: Windows driver unload integration

**Files:**
- Modify: `src/windows/win_hv/src/device.rs`

- [ ] **Step 1: Call `devirtualize_system` before device teardown**

```rust
extern "C" fn driver_unload(driver: *mut DRIVER_OBJECT) {
    eprintln!("win_hv unload: devirtualizing");
    hv::devirtualize_system();

    eprintln!("win_hv unload: removing win_hv EPT hook allocations");
    crate::ept_hook::uninstall_all(); // driver-side fake pages — keep if separate from hvcore

    // ... IoDeleteSymbolicLink / IoDeleteDevice unchanged ...
}
```

Remove duplicate hvcore hook uninstall if `devirtualize_system` already calls `intel::ept_hook::uninstall_all`.

- [ ] **Step 2: Build driver**

Run: `cd src/windows && cargo build -p win_hv`  
Expected: `Finished dev [unoptimized + debuginfo] target(s)`

- [ ] **Step 3: Commit**

```bash
git add src/windows/win_hv/src/device.rs
git commit -m "feat(win_hv): devirtualize on driver unload"
```

---

### Task 10: Manual verification (Windows)

**Files:** none (runtime test)

- [ ] **Step 1: Load driver**

```powershell
# From src/windows — use your existing test signing / sc.exe workflow
sc create win_hv type= kernel binPath= "...\win_hv.sys"
sc start win_hv
```

Expected: `HV_HYPERCALL_PING succeeded` in DbgView / serial log.

- [ ] **Step 2: Unload driver**

```powershell
sc stop win_hv
sc delete win_hv
```

Expected: no BSOD; log shows `Devirtualizing all processors` / `Devirtualized all processors`.

- [ ] **Step 3: Re-load driver**

```powershell
sc create win_hv type= kernel binPath= "...\win_hv.sys"
sc start win_hv
```

Expected: `HV_HYPERCALL_PING succeeded` again — re-virtualize works.

- [ ] **Step 4: Stray VMXOFF test (optional)**

With a test IOCTL or client calling `hypercall::vmxoff()` **outside** unload: expect failure / stay virtualized (`ping` still succeeds).

- [ ] **Step 5: Multi-CPU**

On a multi-core VM: unload without BSOD; all processors native after `devirtualize_system` returns.

---

## Self-review (spec coverage)

| Spec requirement | Task |
|------------------|------|
| `devirtualize_system()` API | Task 3, 9 |
| `HV_HYPERCALL_VMXOFF` + DPC broadcast | Task 1, 2, 3 |
| `DEVIRT_IN_PROGRESS` gate | Task 3, 8 |
| HyperDbg 10-step `perform_vmxoff` | Task 5, 6 |
| `AsmVmxoffHandler` asm path | Task 7 |
| `uninstall_all` + INVEPT before VMXOFF | Task 4 |
| `EptState::reset` re-virt | Task 4 |
| `host::main` stays `!` | No switch_stack change |
| AMD `disable` stub | Task 6 |
| win_hv unload | Task 9 |

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-14-intel-devirtualize.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration  
2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
