# EPT Hook2 (Inline Detour) Design Spec

**Date:** 2026-06-13  
**Status:** Draft — pending user review  
**Scope:** Intel Windows (`win_hv` + `hvcore`), x64 kernel, detour model A

## Goal

Implement HyperDbg-style **EPT Hook2** in barevisor: hidden inline function detour via a fake executable page and EPT permission swapping, without patching the original guest page in RAM.

When the guest executes the hooked virtual address, it runs code from a **fake page** that jumps to a user-supplied **hook function** (`hook_gva`). The hook function may call the **trampoline** to invoke the original instructions.

## Non-Goals (v1)

- AMD NPT equivalent
- x86 user-mode / WOW64 hooks
- Multiple hooks per physical page
- HyperDbg debugger event scripts / break-to-debugger (model B/C)
- UEFI driver support in v1
- GPA ≥ 512 GB (1 GB EPT pages in barevisor identity map)
- Cross-page hooks (target + 19-byte jump must fit in one page)

## Background: HyperDbg EPT Hook2

Reference: `HyperDbg/hyperhv/code/hooks/ept-hook/EptHook.c`

1. Copy the target 4 KB page into `FakePageContents` (page-aligned struct field).
2. Overwrite the target offset in the fake page with a 19-byte absolute jump to `HookFunction`.
3. Build a **trampoline**: copied prologue instructions + 14-byte absolute jump back to `target + patched_len`.
4. Split the target GPA's EPT mapping from 2 MB → 4 KB.
5. Set EPT PML1 to **execute-only** (R=0, W=0, X=1) with PFN = fake page HPA.
6. On EPT violation:
   - **Execute** on hooked page → keep fake page mapping.
   - **Read/Write** → swap to original PFN for one instruction (MTF restores hook mapping).

## Architecture

```
win_hv_client  --IOCTL-->  win_hv (install prep)  --VMCALL-->  hvcore (EPT apply + runtime)
```

### Responsibility split

| Layer | Responsibility |
|-------|----------------|
| `win_hv_client` | CLI: `hook` / `unhook` |
| `shared-contract` | IOCTL + request/response structs, error codes |
| `win_hv` | CR3 resolve, GVA→GPA, read target page, iced-x86 insn length, build fake page + trampoline, allocate NonPagedPool, issue hypercall |
| `hvcore` | Dynamic EPT split, hook registry, EPT violation + MTF VM-exit, INVEPT, hypercall handlers |

### Hook callback model (chosen: A)

- User supplies `hook_gva` (kernel VA of replacement function).
- IOCTL response returns `trampoline_gva` so the caller can store it (e.g. as `OrigFn` pointer).
- No user-mode notification on hook hit in v1.

## Data Structures

### `shared-contract`

```rust
pub const IOCTL_EPT_HOOK2: u32 = ...;      // function 0x909
pub const IOCTL_EPT_UNHOOK: u32 = ...;     // function 0x90A

#[repr(C)]
pub struct EptHook2Request {
    pub process_id: u32,      // 0 = kernel CR3 from caller context / system
    pub _padding: u32,
    pub target_gva: u64,      // function to hook
    pub hook_gva: u64,        // detour handler
}

#[repr(C)]
pub struct EptHook2Response {
    pub success: u8,
    pub error_code: u8,       // EPT_HOOK2_ERR_*
    pub patched_len: u8,      // bytes overwritten in fake page
    pub _padding: u8,
    pub trampoline_gva: u64,  // VA of trampoline in kernel space
    pub target_gpa: u64,      // for debugging / unhook
}

#[repr(C)]
pub struct EptUnhookRequest {
    pub target_gva: u64,      // same VA used at install (page-aligned lookup)
}
```

Error codes (`error_code`):

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Invalid parameter |
| 2 | CR3 / process lookup failed |
| 3 | GVA→GPA translation failed |
| 4 | GPA ≥ 512 GB |
| 5 | Page already hooked |
| 6 | Instruction length / disassembly failed |
| 7 | Hook spans page boundary |
| 8 | Pool allocation failed |
| 9 | Hypercall / EPT install failed |
| 10 | CPU lacks EPT execute-only support |
| 11 | Hook not found (unhook) |

Bump `CONTRACT_VERSION` to `0.5.0`.

### Hypercall payloads (`hvcore`)

```rust
pub const HV_HYPERCALL_INSTALL_EPT_HOOK2: u64 = 3;
pub const HV_HYPERCALL_UNINSTALL_EPT_HOOK2: u64 = 4;

// Install args (guest registers):
// RCX = target_gpa_page_base (4K aligned)
// RDX = fake_page_hpa (4K aligned)
// R8  = patched_insn_len (u8 in low byte)
// R9  = reserved
//
// Trampoline VA is NOT needed in hvcore; only fake page content matters for execution.
// Returns RAX = HV_HYPERCALL_SUCCESS | error

// Uninstall args:
// RCX = target_gpa_page_base
```

### `hvcore` internal: `EptHookedPage`

```rust
struct EptHookedPage {
    gpa_page_base: u64,
    fake_page_hpa: u64,
    original_pte: EptEntry,
    hooked_pte: EptEntry,
    // Used by MTF restore:
    mtf_pending: bool,
}
```

Stored in a `spin::Mutex<Vec<EptHookedPage>>` (max hooks bounded; v1 limit: 16).

## hvcore Changes

### 1. EPT dynamic split (`intel/epts.rs`)

Add to shared `Epts`:

- `split_2mb_to_4kb(&mut self, gpa: u64) -> Result<(), EptError>`
  - Walk PML4→PDPT→PD; if PDE is 2 MB large page, allocate a new 4 KB PT from hv allocator, populate 512 PTEs from the 2 MB frame, clear large bit on PDE.
  - If already 4 KB mapped (first 2 MB region), no-op success.
- `pml1_entry_mut(&mut self, gpa: u64) -> Option<&mut Entry>`
- `invept_single_context(eptp: u64)` — inline asm `invept` type 1

`SharedGuestData.epts` must use interior mutability: wrap in `spin::RwLock` or `Mutex`.

### 2. New module `intel/ept_hook.rs`

- `check_ept_hook_support() -> bool` — `IA32_VMX_EPT_VPID_CAP` execute-only bit
- `install(gpa_page_base, fake_page_hpa, patched_len) -> Result<(), HookError>`
- `uninstall(gpa_page_base) -> Result<(), HookError>`
- `handle_ept_violation(qualification: u64, guest_phys_addr: u64) -> bool`
- `handle_mtf() -> bool`

**Install algorithm** (mirrors HyperDbg):

1. Reject if GPA page already in hook list.
2. `split_2mb_to_4kb(gpa)`.
3. Read current PML1 entry → `original_pte`.
4. Build `hooked_pte`: R=0, W=0, X=1, memory type from original, PFN = `fake_page_hpa >> 12`.
5. Write `hooked_pte` to PML1, `invept_single_context`.
6. Push `EptHookedPage` to list.

**Violation handler**:

```
if guest_phys_addr page matches hook:
  if qualification.read or qualification.write:
    restore original_pte; set per-vcpu mtf_restore = Some(hook); enable MTF
  else if qualification.execute:
    ensure hooked_pte is active (already default)
  suppress guest RIP increment
  return handled
```

**MTF handler**:

```
if mtf_restore present:
  re-apply hooked_pte; invept; disable MTF; clear mtf_restore
```

Per-vCPU state: store `mtf_restore` in a static array indexed by APIC id (max 256), matching barevisor's processor model.

### 3. VM-exit handling (`intel/guest.rs`, `host.rs`)

Enable in VMCS primary controls: `MONITOR_TRAP_FLAG`.

Add exit reasons:

| Reason | Value | Action |
|--------|-------|--------|
| EPT violation | 48 | `ept_hook::handle_ept_violation` |
| MTF | 37 | `ept_hook::handle_mtf` |

Wire `VmExitReason::EptViolation` and `VmExitReason::MonitorTrapFlag` in `host.rs` loop (no RIP advance by default — handler manages it).

Read qualification from `VM_EXIT_QUALIFICATION`, guest physical address from `GUEST_PHYSICAL_ADDRESS` VMCS fields.

### 4. Hypercall handlers (`host.rs`)

`INSTALL_EPT_HOOK2`: validate GPA < 512 GB, call `ept_hook::install`, return status in RAX.

`UNINSTALL_EPT_HOOK2`: call `ept_hook::uninstall`.

## win_hv Changes

### New module `ept_hook.rs`

**Dependencies:** add `iced-x86` to `win_hv/Cargo.toml` (driver builds with std).

```rust
fn build_hook_buffers(
    cr3: u64,
    target_gva: u64,
    hook_gva: u64,
) -> Result<HookBuffers, HookError>
```

Steps:

1. `gpa = gva_to_gpa_cr3_switch(cr3, target_gva & !0xFFF)?`
2. Read 4096 bytes from `gpa` via `read_hpa`.
3. `offset = target_gva & 0xFFF`
4. Disassemble from `offset` until length ≥ 14 (trampoline tail) using iced-x86 64-bit kernel mode.
5. Reject if `offset + 19 > 4095`.
6. Allocate two NonPagedPool pages: `fake_page`, `trampoline`.
7. Copy page → fake_page; write 19-byte abs jump at `fake_page[offset]` → `hook_gva`.
8. Copy `patched_len` bytes to trampoline; append 14-byte abs jump → `target_gva + patched_len`.
9. Return `{ fake_hpa, trampoline_va, patched_len, gpa_page_base }`.

**Absolute jump encodings** (from HyperDbg):

- 19-byte (fake page): `call $+5` padding + push imm32 + mov [rsp+4], imm32 + ret — use HyperDbg `EptHookWriteAbsoluteJump`.
- 14-byte (trampoline tail): push imm32 + mov [rsp+4], imm32 + ret — `EptHookWriteAbsoluteJump2`.

Issue hypercall with `fake_hpa` and `gpa_page_base`.

### `device.rs`

Add IOCTL handlers calling `ept_hook::install` / `unhook`.

Track driver-allocated pools per hook in a static `Mutex<Vec<HookAllocation>>` for cleanup on unhook / driver unload.

### `win_hv_client`

```text
win_hv_client hook --target <gva> --hook <gva> [--pid <pid>]
win_hv_client unhook --target <gva>
```

Print `trampoline_gva` and `patched_len` on success.

## Execution Flow (detailed)

### Install

1. Client sends `EptHook2Request`.
2. Driver resolves CR3 (PID or current).
3. Driver builds fake page + trampoline in NonPagedPool.
4. Driver `hv::hypercall::install_ept_hook2(gpa_base, fake_hpa, patched_len)`.
5. Hypervisor splits EPT, applies hooked_pte, INVEPT.
6. Driver returns `trampoline_gva` to client.

### Guest execution at hooked function

1. CPU fetches from `target_gva` → EPT uses fake PFN → executes jump to `hook_gva`.
2. Hook function runs; may call trampoline.
3. Trampoline runs original instructions, jumps back to `target_gva + patched_len`.

### Read/write to hooked page (e.g. patch scan)

1. EPT violation (read or write).
2. Hypervisor swaps to original PFN.
3. MTF set; guest re-executes the access against real memory.
4. MTF fires; hypervisor restores fake PFN.

### Unhook

1. Hypervisor restores `original_pte`, removes list entry, INVEPT.
2. Driver frees fake page + trampoline pools.

## Error Handling

- All install failures roll back: free pools, hypervisor does not add list entry.
- If hypercall succeeds but driver loses track, unhook by GPA may leak pool — driver owns pool bookkeeping.
- Unexpected EPT violation (no matching hook): log error, `DbgBreak` in debug builds; guest may bugcheck (acceptable v1).

## Testing Plan

1. **Unit (host build):** test 19/14-byte jump encoders, iced-x86 length loop on known kernel prologues (compile-time or `#[cfg(test)]` in win_hv_client).
2. **Integration (VMware):**
   - Load `win_hv.sys`, confirm ping.
   - Allocate a test hook handler in a companion `.sys` or use an existing export (e.g. wrap `DbgPrint` with a count).
   - `win_hv_client hook --target nt!DbgPrint --hook <MyHook>`.
   - Trigger `DbgPrint`; verify hook runs and trampoline reaches original.
   - `win_hv_client unhook --target nt!DbgPrint`.
   - Re-trigger; verify original behavior.
3. **Read/write sanity:** byte-read hooked page from kernel debugger or driver `read_hpa`; verify original bytes visible (not jump patch).

## File Change Summary

| File | Change |
|------|--------|
| `shared-contract/src/lib.rs` | IOCTLs, structs, errors, version bump |
| `hvcore/src/hypervisor/hypercall.rs` | New hypercall numbers + guest helpers |
| `hvcore/src/hypervisor/host.rs` | Hypercall + new VM-exit routes |
| `hvcore/src/hypervisor/intel/epts.rs` | Split, mut entry, INVEPT |
| `hvcore/src/hypervisor/intel/ept_hook.rs` | **New** — core hook logic |
| `hvcore/src/hypervisor/intel/guest.rs` | MTF control, EPT/MTF exits, RwLock epts |
| `hvcore/src/hypervisor/intel/mod.rs` | mod ept_hook |
| `windows/win_hv/src/ept_hook.rs` | **New** — install prep |
| `windows/win_hv/src/device.rs` | IOCTL dispatch |
| `windows/win_hv/src/lib.rs` | mod ept_hook |
| `windows/win_hv/Cargo.toml` | iced-x86 |
| `windows/win_hv_client/src/main.rs` | hook/unhook commands |

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| No execute-only EPT | Check at driver load; fail IOCTL with error 10 |
| Static EPT layout insufficient for many splits | Allocate new PT pages from hv allocator per split; v1 cap 16 hooks |
| Patch length edge cases | iced-x86 with min 14 bytes; reject ambiguous cases |
| SMP race on hook list | Mutex; install before returning IOCTL; INVEPT all contexts |
| Driver unload with active hooks | `DriverUnload`: uninstall all, restore EPT |

## Open Items (deferred)

- IOCTL to list active hooks
- AMD NPT port
- Pre-allocated hook pool at driver load (HyperDbg style)
