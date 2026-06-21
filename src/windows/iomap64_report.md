# IOMap64.sys 漏洞分析报告

## 基本信息

| 字段 | 值 |
|------|-----|
| 文件 | `IOMap64.sys` |
| 路径 | `C:\Users\Administrator\Desktop\IOMap64.sys` |
| SHA256 | `03fffd666bd9c04655414a8db2268f8825f392526c28a65fde66c1bee58fb2d4` |
| MD5 | `80fb7ca66c2a6023274d4bcc0aeb612a` |
| 架构 | x64 |
| 大小 | 0xD878 字节 |
| PDB | `IOMap-V3.1_20241128_vs2019` (Gigabyte 工具驱动) |
| 设备名 | `\Device\IOMap` |
| 符号链接 | `\DosDevices\IOMap` (用户态 `\\.\IOMap`) |
| 设备类型 | `0x8300` |

## 分析结论

**该驱动存在多个严重安全漏洞，属于典型的 BYOVD（Bring Your Own Vulnerable Driver）目标驱动。**

虽然设备 SDDL 限制为 `D:P(A;;GA;;;SY)(A;;GA;;;BA)`（仅 SYSTEM 和 Administrators 可访问），但任何具备管理员权限的进程仍可：

1. 映射任意物理内存到内核虚拟地址空间
2. 对映射区域进行任意读/写（且无偏移边界检查）
3. 通过内核执行端口 I/O 和 PCI 配置空间操作

这些能力可用于禁用内核保护（PatchGuard/DSE）、读写内核内存、绕过 EDR，实现权限维持或提权。

---

## 驱动架构

```
DriverEntry
  └── IOMap_DriverInit (0x1400019C4)
        ├── 创建设备 \Device\IOMap (IoCreateDeviceSecure)
        ├── 创建符号链接 \DosDevices\IOMap
        ├── 注册 IRP 分发例程
        └── 初始化互斥锁

IRP 分发:
  IRP_MJ_DEVICE_CONTROL → IOMap_DispatchDeviceControl (0x1400025A0)
  IRP_MJ_POWER            → IOMap_DispatchPower (0x1400028F0)
  DriverUnload            → IOMap_DriverUnload (0x140002950)
```

### 关键导入

- `MmMapIoSpace` / `MmUnmapIoSpace` — 物理内存映射
- `HalTranslateBusAddress` — PCI 总线地址转换
- `KeStallExecutionProcessor` — CPU 延迟
- `IoCreateDeviceSecure` (动态解析) — 安全创建设备

---

## IOCTL 清单

| IOCTL Code | 功能 | 风险 |
|------------|------|------|
| `0x830020D0` | 映射 16MB 物理内存 (Slot 0) | **严重** |
| `0x830020D4` | 枚举 PCI 设备并修改 BAR | **高** |
| `0x830020D8` | 返回最大映射大小 `0x1000000` | 信息泄露 |
| `0x830020DC` | 从 16MB 映射区读 DWORD | **严重** (无边界检查) |
| `0x830020E0` | 从 16MB 映射区读 WORD | **严重** |
| `0x830020E8` | 向 16MB 映射区写 WORD | **严重** |
| `0x830020F0` | 向 16MB 映射区写 BYTE | **严重** |
| `0x830020F4` | PCI 配置操作 | **高** |
| `0x830020F8` | 端口 I/O 读 (0xD808/0xD80C) | **高** |
| `0x830020FC` | 端口 I/O 写 (0xD808/0xD80C/0xD830) | **高** |
| `0x83002100` | PCI 配置操作 | **高** |
| `0x83002104` | 映射 256KB 物理内存 | **严重** |
| `0x83002108` | 从 256KB 映射区读 BYTE | **严重** |
| `0x8300210C` | 从 256KB 映射区读 WORD | **严重** |
| `0x83002110` | 从 256KB 映射区读 DWORD | **严重** |
| `0x83002114` | PCI 配置读写 | **高** |
| `0x83002118` | 映射 16MB 物理内存 (Slot 1) | **严重** |
| `0x83002134` | 返回已映射虚拟地址 | 信息泄露 |
| `0x83002138`~`0x83002144` | 额外映射/PCI 操作 | **高** |
| `0x830020C8`~`0x83002130` | 二级 IOCTL 分发 | 各异 |

未识别的 IOCTL 由 `IOMap_DispatchSecondaryIoctl` (0x140003180) 处理，内部先获取互斥锁再分发。

---

## 漏洞详情

### VULN-1: 任意物理内存映射 (Critical)

**函数**: `IOMap_MapPhysicalMemory256K` / `IOMap_MapPhysicalMemory16M_Slot0/1`

**调用链**:
```
IOCTL 0x83002104 / 0x830020D0 / 0x83002118
  → IOMap_MapPhysicalMemory*
    → IOMap_ValidatePciDevice (弱校验)
    → IOMap_DoMapIoSpace* → MmMapIoSpace(PhysicalAddress, Size, MmNonCached)
```

**问题**:

1. 用户通过 IOCTL 输入缓冲区指定物理地址（`input[2]`），驱动直接传给 `MmMapIoSpace`
2. `IOMap_ValidatePciDevice` 仅验证 PCI 配置空间头（bus ≤ 0x100, dev ≤ 0x20, 类型 = 0x03），**不验证物理地址是否在合法 MMIO/RAM 范围内**
3. 攻击者可映射内核物理页、设备 MMIO 区域等敏感物理内存

**映射大小**:
- 256KB 映射: `0x40000` (262144 字节)
- 16MB 映射: `0x1000000` (16777216 字节)
- 最多 16 个 16MB slot + 16 个 256KB slot

### VULN-2: 映射内存读写无边界检查 (Critical)

**函数**: `IOMap_ReadMappedByte`, `IOMap_WriteMappedDword16M` 等

**示例** (`IOMap_ReadMappedByte` @ 0x140003094):
```c
*a5 = *(unsigned __int8 *)(g_MappedPhys256K_Cache + *a4);  // offset 来自用户，无上限检查
```

**问题**:
- 偏移量 `*a4` 完全由用户控制
- 未与映射大小 (`0x40000` 或 `0x1000000`) 比较
- 可导致内核虚拟地址空间越界读/写 → 内核信息泄露、内存破坏、BSOD

### VULN-3: 内核端口 I/O (High)

**IOCTL `0x830020F8` / `0x830020FC`** 在 `IOMap_DispatchDeviceControl` 中直接执行:

```asm
out 0xD808, al       ; 选择 Super I/O 索引
in  eax, dx          ; 从 0xD80C/0xD830 读
out 0xD80C, eax       ; 写 0x59490C 到数据端口
```

允许用户态（经管理员权限）通过内核驱动访问硬件 I/O 端口，可能修改 CMOS、Super I/O 寄存器等。

### VULN-4: PCI 配置空间任意读写 (High)

**函数**: `IOMap_ReadPciConfigDword` (0x140002DE8)

```c
__outdword(0xCF8, offset + ((func + 32 * (bus + 0x8000)) << 11));
return __indword(0xCFC);
```

- 使用标准 PCI 配置端口 0xCF8/0xCFC
- `IOMap_EnumeratePciDevices` (0x140001C84) 可修改 PCI BAR (`sub_140002FA4` 写配置空间)
- 可能导致资源冲突或硬件异常

### VULN-5: IoValidateDeviceIoControlAccess 未使用 (Medium)

**函数**: `IOMap_ResolveSecureCreateDevice` (0x140009000)

驱动动态解析了 `IoValidateDeviceIoControlAccess` 并存入 `g_pfnIoValidateDeviceIoControlAccess`，但 **全二进制仅有一处引用（存储指令本身）**，从未在 IOCTL 路径中调用。

这意味着驱动没有利用 Windows 提供的 IOCTL 访问级别校验机制。

### VULN-6: SDDL 限制不足以缓解 BYOVD (Medium)

SDDL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)`

- 仅 SYSTEM 和 Built-in Administrators 拥有 Generic All
- 无法阻止已获取管理员权限的恶意软件加载此签名驱动
- 该驱动在 [loldrivers.io](https://www.loldrivers.io/) 等 BYOVD 数据库中已被广泛收录

---

## 攻击场景

```
[管理员权限进程]
    │
    ├─ LoadLibrary / NtLoadDriver → 加载 IOMap64.sys
    │
    ├─ CreateFile("\\\\.\\IOMap")
    │
    ├─ DeviceIoControl(0x83002104) → 映射内核物理页
    │
    ├─ DeviceIoControl(0x83002108/0x83002110) → 读取内核结构
    │       或
    ├─ DeviceIoControl(0x830020F0/0x830020DC) → 写入 shellcode 到内核
    │
    └─ 禁用 DSE / 篡改 EPROCESS / 注入内核代码
```

---

## IDA 分析步骤

1. **`survey_binary`** — 获取二进制概览、导入表、入口点
2. **`analyze_function DriverEntry`** — 定位初始化函数 `IOMap_DriverInit`
3. **分析 IRP 分发** — 识别 `IOMap_DispatchDeviceControl` 中 IOCTL switch
4. **追踪 `MmMapIoSpace` 调用链** — 确认物理地址来源为用户输入
5. **分析 `IOMap_ValidatePciDevice`** — 确认校验逻辑不足
6. **检查读写函数** — 确认无 offset 边界检查
7. **xref 分析 `g_pfnIoValidateDeviceIoControlAccess`** — 确认未使用
8. **重命名函数/变量、添加注释** — 已在 IDA 中完成

### 已重命名符号 (IDA)

| 原名称 | 新名称 |
|--------|--------|
| `sub_1400019C4` | `IOMap_DriverInit` |
| `sub_1400025A0` | `IOMap_DispatchDeviceControl` |
| `sub_140002950` | `IOMap_DriverUnload` |
| `sub_140001FBC` | `IOMap_MapPhysicalMemory256K` |
| `sub_14000207C` | `IOMap_MapPhysicalMemory16M_Slot0` |
| `sub_14000304C` | `IOMap_ValidatePciDevice` |
| `BaseAddress` | `g_MappedPhys256K_VA` |
| `qword_140007268` | `g_MappedPhys16M_Slot0_VA` |

---

## 修复建议

1. **停止分发/卸载该驱动** — 从系统中移除 IOMap64.sys，加入驱动黑名单
2. **如需保留功能**:
   - 映射前验证物理地址在白名单范围内（仅允许特定 MMIO 区域）
   - 所有读写操作必须校验 `offset + size <= mapped_size`
   - 调用 `IoValidateDeviceIoControlAccess` 限制 IOCTL 为 `FILE_DEVICE_SECURE_OPEN`
   - 移除端口 I/O 和 PCI 配置空间直接访问接口
   - 使用 `METHOD_NEITHER` 的 IOCTL 应配合 `ProbeForRead/Write`
3. **系统层面**: 启用 Microsoft Vulnerable Driver Blocklist (HVCI/VBS)

---

## 参考

- CVE-2018-19326 (Gigabyte 相关驱动同类漏洞)
- [LOLDrivers - IOMap64.sys](https://www.loldrivers.io/)
- Microsoft BYOVD 缓解指南

---

*分析工具: IDA Pro + MCP (user-ida-pro-mcp)*  
*分析日期: 2026-06-21*
