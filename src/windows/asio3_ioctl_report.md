# AsIO3.sys 全 IOCTL 分析报告

**目标二进制：** `AsIO3.sys`（IDA 设备 `\\.\Asusgio3`）  
**分析入口：** `AsIO3_DispatchIrp` @ `0x1400019A0`  
**方法：** IDA 反编译 + 汇编交叉验证 + MCP 注释标注

---

## 结论摘要

- 共识别 **40+ 个有效 IOCTL**（含按宽度拆分的 I/O 端口/PCI 变体）。
- **唯一**向 phys 白名单链表 `qword_140009470` 插入节点的 IOCTL：**`0xA040A488`**。
- **进程白名单**（CREATE 门控）：**`0xA040A490`**（与 phys 无关）。
- 高危原语：`0xA0402450`（映射 `\Device\PhysicalMemory`）、`0xA0400F7C/0xF80`（phys 读写）、`0xA0400F8C/0xA040A45C`（写 MSR）。

---

## IOCTL 设备类型

所有 IOCTL 设备类型均为 **`0xA040`**（`FILE_DEVICE_ASUSIO` 自定义设备，DriverInit 中 `IoCreateDevice(..., 0xA040u, ...)`）。

---

## 一、物理内存

| IOCTL | Handler | 最小 Buffer | 作用 |
|-------|---------|-------------|------|
| **`0xA0400F7C`** | `AsIO3_PhysMemRead` | 4136 (`0x1028`) | 从**物理地址**读 1/2/4 字节；经 `AsIO3_MapPhysMemPage` 映射一页；**需通过 `AsIO3_CheckPhysMemAllowed`** |
| **`0xA0400F80`** | `AsIO3_PhysMemWrite` | 4136 | 向物理地址写 1/2/4 字节；同上白名单检查 |
| **`0xA0400F84`** | `AsIO3_PhysMemReadPage` | 4136 | 映射物理页并拷贝**最多 4 KiB** 到 buffer |
| **`0xA040200C`** | `AsIO3_PhysMemMap` | 4136 | 映射物理页，返回 mapped VA（不读内容） |
| **`0xA0402450`** | `AsIO3_MapPhysicalMemory` | 40 | 打开并映射 `\Device\PhysicalMemory` section；输出 kernel VA + handle；**白名单检查** |
| **`0xA040244C`** | `sub_1400033EC` | WoW64: 24 / Native: 40 | **32 位进程**版物理内存映射（`\Device\PhysicalMemory` + `HalTranslateBusAddress`） |
| **`0xA0402010`** | `sub_1400040F0` | >4127 | **Unmap** 先前映射的 phys section view（handle @buf+8，地址 @+0x18 或 +0x20） |

### 连续内存分配

| IOCTL | Handler | Buffer | 作用 |
|-------|---------|--------|------|
| **`0xA040A488`** | inline @ `0x140002520` | 8 字节 in/out | `MmAllocateContiguousMemory` + **插入 phys 白名单链表**；out: `[phys_lo][kernel_va_lo]` |
| **`0xA0400F90`** | inline @ `0x14000210D` | 4136 | 仅 `MmAllocateContiguousMemory`；out @+0x18 physical、@+0x20 **完整 kernel_va**；**不注册白名单** |
| **`0xA0400F94`** | inline @ `0x1400020EB` | 4136 | `MmFreeContiguousMemory(kernel_va @+0x20)` |

### Phys 白名单检查逻辑（`AsIO3_CheckPhysMemAllowed`）

1. 动态链表 `qword_140009470`（**仅 A488 插入**）
2. 静态范围：`0xE0000–0x100000`、`0xF8000000–0xFFFFFFFF`
3. 若 `dword_1400093C0==0`：ASUS 配置 blob 中额外允许范围（`qword_1400093E8`）
4. 若 `dword_1400093C0!=0`（CREATE 时 ASUS 证书路径加载系统 RAM 范围）：**黑名单模式**——与系统 RAM 重叠则拒绝

---

## 二、MSR 读写

| IOCTL | Handler | 最小 Buffer | 作用 |
|-------|---------|-------------|------|
| **`0xA0400F88`** | inline @ `0x1400021C5` | 16 | 读 MSR：`CheckMsrAllowed` → `__readmsr` |
| **`0xA0400F8C`** | inline @ `0x140002182` | 16 | 写 MSR：`CheckMsrAllowed` → `__writemsr` |
| **`0xA0406458`** | `AsIO3_ReadMsr` | in≥4, out≥8 | 读 MSR（结构化路径，返回 8 字节） |
| **`0xA040A45C`** | `AsIO3_WriteMsr` | ≥12 | 写 MSR：index @0 + u64 value @4 |

---

## 三、I/O 端口（带 `AsIO3_CheckIoPortAllowed`）

### PCI 配置空间（CF8/CFC，需 `KeWaitForSingleObject` 串行化）

| IOCTL | 宽度 | 作用 |
|-------|------|------|
| **`0xA0400F58`** | 1/2/4 | PCI **读**（写 CF8 地址，读 CFC） |
| **`0xA0400F5C`** | 1/2/4 | PCI **写**（写 CF8 + CFC） |
| **`0xA0400F70`** | dword×N | PCI **批量读**（最多 0x200 dwords） |

### 直接 I/O 端口

| IOCTL | 宽度 | 作用 |
|-------|------|------|
| **`0xA0400F60`** | 1/2/4 | `in` 读端口 |
| **`0xA0400F64`** | 1/2/4 | `out` 写端口 |
| **`0xA0400F68`** | byte×2 | 写端口 + 读相邻端口 |
| **`0xA0400F6C`** | byte×2 | 写两个相邻端口 |
| **`0xA0400F74`** | byte×N | 批量 `in`（最多 0x200 字节） |
| **`0xA0400F78`** | byte×N | 写+读组合批量（最多 0x200） |

### 高级 I/O 端口（`HalTranslateBusAddress` + buffer ≥0x24）

| IOCTL | 宽度 | Handler | 作用 |
|-------|------|---------|------|
| **`0xA0402014`** | 1/2/4 | `AsIO3_IoPortOut` | 端口**写**（buffer 布局，带同步事件） |
| **`0xA0402018`** | 1/2/4 | `AsIO3_IoPortIn` | 端口**读** |

### ISA 端口读（`sub_1400027A4`，6400 系列）

| IOCTL | 宽度 | 作用 |
|-------|------|------|
| **`0xA0406400`** | byte | `HalTranslateBusAddress` + `in`/内存读 |
| **`0xA0406404`** | word | 同上 16 位 |
| **`0xA0406408`** | dword | 同上 32 位 |
| **`0xA040640C`** | — | **未实现**（跳过后返回 `STATUS_INVALID_DEVICE_REQUEST`） |

### 端口写（A440 / A540 系列，`sub_1400028D0` / `sub_140002A68`）

| IOCTL | 宽度 | Handler | 作用 |
|-------|------|---------|------|
| **`0xA040A440`** | byte | `sub_1400028D0` | 端口写 8 位 |
| **`0xA040A444`** | word | 同上 | 端口写 16 位 |
| **`0xA040A448`** | dword | 同上 | 端口写 32 位 |
| **`0xA040A540`** | byte | `sub_140002A68` | 端口写（另一 buffer 布局） |
| **`0xA040A544`** | word | 同上 | |
| **`0xA040A548`** | dword | 同上 | |
| **`0xA040A54C`** | — | **显式拒绝**（`jz` → invalid） |

WoW64（32 位进程）走 `sub_1400028D0(..., a3=1)`；64 位走 native buffer 路径 @ `0x140002688`。

---

## 四、PCI 配置空间（Hal 接口）

| IOCTL | Handler | 最小 Buffer | 作用 |
|-------|---------|-------------|------|
| **`0xA0402000`** | `HalGetBusDataByOffset` | 0x14 | 读 PCI 配置空间 |
| **`0xA0402004`** | `HalSetBusDataByOffset` | 0x14 | 写 PCI 配置空间 |

---

## 五、进程 / 访问控制

| IOCTL | Handler | 最小 Buffer | 作用 |
|-------|---------|-------------|------|
| **`0xA040A490`** | `AsIO3_AddProcessWhitelist` | 4 | 将 **PID** 写入 `qword_1400091C0[64]`；用于 CREATE 门控 |
| **`0xA040A48C`** | noop | — | 直接返回成功（空操作） |
| **`0xA040A480`** | `sub_1400033EC` | WoW64 | 32 位进程的 phys 映射辅助路径 |

---

## 六、非 DEVICE_CONTROL IRP

| Major | 作用 |
|-------|------|
| **IRP_MJ_CREATE (0)** | `AsIO3_VerifyAsusCert()` 或 PID 白名单；证书通过时 `sub_140002D18()` 加载 phys 范围配置 |
| **IRP_MJ_CLOSE (2)** | `sub_140003DC0()` — **清除当前进程 PID** 白名单 |
| **IRP_MJ_DEVICE_CONTROL (14)** | 上表全部 IOCTL |

---

## 七、Buffer 布局速查（常用）

### Phys read/write（4136 字节，`PhysOpBuffer`）

```
@0x00  width (1/2/4)
@0x18  physical address (u64) — read/write 使用
@0x10  map_size (u32) — write 路径用于 MapPhysMemPage
```

### `0xA040A488`（8 字节）

```
in  @0: u32 size (max 0x8000000)
out @0: u32 physical_lo
out @4: u32 kernel_va_lo (x64 截断)
```

### `0xA0400F90`（4136 字节）

```
in  @0x10: u32 size
out @0x18: u32 physical
out @0x20: u64 kernel_va
```

### `0xA0402450`（40 字节）

```
@0x00  map_size (u64)
@0x08  physical (u64)
out @0x10 kernel_va
out @0x18 section_handle
```

---

## IDA 分析步骤

1. `AsIO3_DispatchIrp` 反编译 — 定位 `IoControlCode` 分层 `cmp`/`switch`
2. 扫描全部 `cmp ecx, 0A040xxxxh` 常量（40 个唯一码）
3. 对 `lea eax,[rcx+5FBF9C00h]` / `5FBF5AC0h` 解码 IOCTL **族**（6400/A540）
4. 反编译各 handler：`AsIO3_PhysMem*`、`AsIO3_MapPhysicalMemory`、`AsIO3_*Msr`、PCI/端口例程
5. `XrefsTo(qword_140009470)` — 确认 **仅 A488** 插入 phys 白名单
6. `set_comments` 在 dispatch 关键分支添加 IOCTL 标注

---

## BYOVD 利用相关 IOCTL 推荐

| 目的 | 推荐 IOCTL |
|------|------------|
| 打开 CREATE 门 | 先 `0xA040A490` 注册 PID，或 ASUS 签名 PE |
| 分配 + phys 读写 | `0xA040A488` alloc → `0xA0400F7C/0xF80` |
| 完整 kernel_va + free | `0xA0400F90` + `0xA0400F94`（无 phys 读写） |
| 任意 phys map | `0xA0402450`（需白名单） |
| 写 MSR | `0xA0400F8C` 或 `0xA040A45C` |

---

## 备注

- `0xA0400F7C` 在 dispatch 中是 **switch 默认值**（`<= 0xA0400F7C` 时仅精确匹配 F7C，无更小 IOCTL）。
- 所有端口/PCI/MSR 类 IOCTL 在访问前均有对应 **Allow 检查**（phys/port/msr 各自独立表）。
- 驱动卸载时 **不释放** A488 链表节点（仅 init 空链表；unload 未 walk free）。
