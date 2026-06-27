# ACE-BASE.sys 逆向分析报告

> **说明**：`ACE-BASE.sys` 是腾讯 ACE（Anti-Cheat Expert）反作弊体系的**内核基础驱动**，并非传统 crackme。本报告不存在“密码”解法；分析目标是驱动架构、通信接口与安全能力。

## 基本信息

| 字段 | 值 |
|------|-----|
| 文件 | `ACE-BASE.sys` |
| IDA 数据库 | `C:\Users\Administrator\Desktop\ACE-BASE.sys.i64` |
| SHA256 | `5a88dbe617bc8f1a8b87d9b9f1221cafe24fbc26bcf87cb93db1afb3351040da` |
| 架构 | x64 |
| 镜像大小 | 0x680000 (~6.5 MB) |
| 函数数量 | 3403（绝大多数为 `.tvm0` 虚拟化桩） |
| PDB | `ACE-BASE.pdb` |

## 一句话总结

**ACE-BASE 是腾讯 ACE 反作弊的内核基座驱动**：创建设备 `\Device\ACE-BASE` 供用户态组件 IOCTL 通信，核心逻辑经 **TVM 虚拟机混淆**（`.tvm0` 段占 ~3MB），同时注册进程通知、BugCheck 回调、游戏进程白名单与物理内存映射等能力，为上层 ACE 组件提供内核级监控与防护支撑。

---

## 驱动架构

```
start (INIT @ 0x140393000)
  └── DriverEntry (0x14003E370)
        ├── 注册 IRP 分发:
        │     [0]  Ace_DispatchCreate      → TVM sub_14042F013
        │     [2]  Ace_DispatchClose        → 本地实现 + 转发
        │     [14] Ace_DispatchDeviceControl → TVM sub_14042F303
        │     [16] sub_14003E330 (SHUTDOWN) → TVM
        │     DriverUnload = Ace_DriverUnload → TVM
        ├── IoCreateDeviceSecure("\\Device\\ACE-BASE", DeviceType=0x22)
        ├── IoCreateSymbolicLink("\\DosDevices\\Global\\ACE-BASE")
        ├── SDDL: D:P(A;;GA;;;BA)  （仅内置管理员组完全访问）
        └── Ace_DriverInit → TVM sub_14042FBCE（主初始化）

Ace_DriverInit 链（部分可在 .text 中追踪）:
  ├── Ace_InitBugCheckCallbacks — KeRegisterBugCheckReasonCallback("Tesxnginx")
  ├── Ace_RegisterProcessNotify — PsSetCreateProcessNotifyRoutineEx
  ├── 进程白名单监控初始化 (sub_140015870)
  └── 2MB 环形事件缓冲区 (sub_14000F070, tag 'mibc')
```

### 段布局

| 段 | 大小 | 权限 | 说明 |
|----|------|------|------|
| `.text` | 0xAC000 | rx | 可读逻辑、thunk、部分明文 handler |
| `.tvm0` | 0x2E8000 | rx | **TVM 虚拟化代码**，IOCTL/Create/Init/Unload 主体 |
| `.data` | 0x291000 | rw | 全局态、进程表、事件队列 |
| `INIT` | 0x3000 | rx | DriverEntry 入口 |

---

## 设备与通信

### 设备节点

| 类型 | 路径 |
|------|------|
| 设备 | `\Device\ACE-BASE` |
| 符号链接 | `\DosDevices\Global\ACE-BASE` |
| 用户态打开 | `\\.\Global\ACE-BASE` |
| DeviceType | `0x22` (FILE_DEVICE_UNKNO状WN) |
| Characteristics | `0x100` (FILE_DEVICE_SECURE_OPEN) |

### IOCTL 处理流程（已反混淆关键路径）

`Ace_DispatchDeviceControl` 为 thunk，跳入 `.tvm0` 的 `sub_14042F303`。在 `0x14042F440–0x14042F5C4` 区间可读到明文逻辑：

1. 从 IRP 当前栈位置读取 **IoControlCode** → 写入 `g_CurrentIoctlCode`
2. 调用 **`Ace_LogProcessIoctl`**（`0x14003E170`）：
   - 维护最多 **4 个进程槽**，每进程记录最多 **3 个 IOCTL 码**
   - 同时保存 15 字节进程映像名（`PsGetProcessImageFileName`）
3. 若日志函数返回 0 → 完成 IRP，状态 **`STATUS_INVALID_DEVICE_REQUEST` (0xC00000A3)**
4. 否则调用 **`sub_140406DC1`**（TVM 内 IOCTL 分发器，~5KB，高度混淆）

### 已识别 IOCTL 码

| IOCTL | CTL_CODE 分解 | 用途（推断） |
|-------|---------------|-------------|
| `0x220003` | Device=0x22, Func=0, Method=NEITHER(3) | 内部转发 IOCTL（`sub_1400A2768` → `IoBuildDeviceIoControlRequest`） |
| `0x220067` | Device=0x22, Func=0x19, Method=NEITHER(3) | 出现在进程白名单数据区（与 `cgame.exe` 类字符串相关） |
| `0x220000` | Device=0x22, Func=0, Method=BUFFERED(0) | 大缓冲区分配尺寸参考（2MB 监控缓冲） |

> 完整 IOCTL 表在 TVM 内部，需进一步动态追踪或符号恢复。

### 内部 IOCTL 转发

`sub_1400A2768` 封装标准内核 IOCTL 转发：

```c
IoBuildDeviceIoControlRequest(IoControlCode, DeviceObject, ...);
IofCallDriver(lowerDevice, Irp);
KeWaitForSingleObject(event);
```

被 `sub_1400A1E60` 用于向**下层设备**发送 `0x220003`，获取宽字符串结果——说明 ACE-BASE 可能叠在另一个设备栈之上，或代理访问子设备。

---

## 进程白名单（`Ace_MatchWhitelistedProcess` @ 0x14006AAAC）

### 机制

1. 输入：进程路径/文件名的宽字符串（调用方保证 ≤ 0x208 字节）
2. `wcslwr` 转小写，取 basename（最后一个 `\` 之后）
3. 与 **9 组 XOR 混淆** 的内置字符串比较
4. 匹配成功 → 输出 **category ID**（如 3、4、5…）

### 解码结果（Python 脚本 XOR，key 见汇编）

| Category ID | 解码进程名 | 说明 |
|-------------|-----------|------|
| `0x3` | `crossfire.exe` | 穿越火线 |
| `0x4` | `gameapp.exe` | 游戏平台 |
| `0x5` | `dnf.exe` | 地下城与勇士 |
| `0x8` | `qqsg.exe` | QQ 三国（解码末尾有 1 字符偏差） |
| `0x17` | `league of legends.exe`（近似） | 英雄联盟相关 |
| `0x1c` | `tgame.exe` | 腾讯游戏 |
| `0x10b` | `tguard.exe` | 腾讯守护 |
| `0xac` | `sguard64.exe` | 64 位安全守护 |
| `0x172` | （部分解码失败） | 可能为 ACE 组件进程 |

### 白名单触发链

```
进程创建通知 Ace_OnProcessCreateNotify (0x1400159C0)
  ├── 提取 CreateInfo 中的映像路径
  ├── Ace_MatchWhitelistedProcess → category ID
  ├── sub_14006A910 附加校验
  └── Ace_RegisterProtectedProcess
        ├── 写入 qword_140144070[64] 进程表（最多 64 槽）
        └── Ace_EnqueueEvent(type=6) 通知用户态/worker
```

`Ace_IsProcessRegistered` 检查句柄是否已在 `qword_140144070` 表中——`Ace_DispatchClose` 对非主设备对象会经 `sub_140032920` 转发处理。

---

## 其他内核能力

### 1. 进程通知（`Ace_RegisterProcessNotify` @ 0x140058050）

- 通过 IOCTL 路径注册（参数 `a2 == 24`）
- 调用 `PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, 0)`
- `NotifyRoutine` @ 0x1400584D0：进程退出时调用 `sub_1400A5C60(ProcessId)` 清理

### 2. BugCheck 回调（`Ace_InitBugCheckCallbacks` @ 0x1400118C0）

- 组件名：**`"Tesxnginx"`**（故意混淆的字符串）
- 注册两个回调：
  - `CallbackRoutine` → `KbCallbackSecondaryDumpData`（崩溃时写入 secondary dump）
  - `sub_140011AC0` → `KbCallbackAddPages`
- 分配 4KB 非分页池（tag `'gubt'` / 0x74756267），头部 magic：
  - `[0] = 20201022`, `[4] = 20200827`, `[8] = 1`, `[16] = 2603`, `[20] = 17210`

### 3. 物理内存 / CPUID（`sub_1400913F8`）

- 检测 CPUID 位（SMAP/SMEP 相关位）
- 通过 `sub_140092F2C(27, ...)` 读取 MSR/平台信息
- 对物理页调用 **`MmMapIoSpace`** 映射 4KB（非缓存）
- 用途：硬件指纹 / 反调试 / 虚拟化检测

### 4. 大缓冲区监控（`sub_14000F070`）

- 分配 **0x220000 (2,097,152)** 字节 PagedPool（tag `'mibc'`）
- 配合 `sub_14000EEE0` 工作线程
- 通过 `Ace_EnqueueEvent` 向环形队列投递事件（每槽 0x800 字节 × 0x400 槽）

### 5. Minifilter 依赖

导入 **FLTMGR.SYS** 大量 API（`FltRegisterFilter` 未直接命名，但存在 `FltCreateFileEx`、`FltReadFile` 等），说明存在文件系统过滤监控能力（具体注册点在 TVM 内）。

---

## 混淆与反分析

| 技术 | 细节 |
|------|------|
| TVM 虚拟化 | `.tvm0` 段 886 次 xref 的 `sub_1404A8F74` 为主 VM 入口；IOCTL/Create/Init/Unload 均为 5 字节 thunk |
| 栈混淆 | TVM 函数大量 `pushfq/popfq`、`xchg/not`、间接 `jmp` |
| 字符串 XOR | 进程白名单 wchar 逐字符 XOR，key 为 16 位常量 |
| 动态 API | INIT 段嵌入 API 名字符串表（`0x140393000+`），运行时解析 |
| 假字符串 | `"Tesxnginx"`、`"xxxDestroyWindow"` 等干扰分析 |

---

## IDA 中已完成的标注

### 函数重命名

- `DriverEntry`（保持）
- `Ace_DispatchCreate` / `Close` / `DeviceControl`
- `Ace_DriverInit` / `Ace_DriverUnload`
- `Ace_LogProcessIoctl`
- `Ace_MatchWhitelistedProcess`
- `Ace_OnProcessCreateNotify` / `Ace_RegisterProtectedProcess`
- `Ace_IsProcessRegistered` / `Ace_EnqueueEvent`
- `Ace_InitBugCheckCallbacks` / `Ace_RegisterProcessNotify`

### 全局变量重命名

- `g_AceDeviceObject`, `g_AceDriverObject`
- `g_CurrentIoctlCode`, `g_IoctlTrackerPids`
- `g_ProcessNotifyRegistered`

### 注释

已在 `DriverEntry`、白名单函数、BugCheck 注册、进程通知注册等地址添加注释。

---

## 分析步骤记录

1. **`survey_binary`** — 确认 3403 函数、`.tvm0` 虚拟化段、FLTMGR/NDIS/HID 导入
2. **`analyze_function(DriverEntry)`** — 提取设备名、SDDL、IRP 表
3. **追踪 IRP 分发 thunk** → `.tvm0` 段；对 `sub_14042F303` 手工反汇编提取 IOCTL 明文路径
4. **`analyze_function(Ace_LogProcessIoctl)`** — 理解 per-PID IOCTL 追踪表
5. **`analyze_function(Ace_MatchWhitelistedProcess)`** — 识别 XOR 白名单；Python 脚本解码
6. **进程通知链** — `Ace_RegisterProcessNotify` → `NotifyRoutine` → `Ace_OnProcessCreateNotify`
7. **BugCheck 回调** — magic 常量、secondary dump 注入
8. **IOCTL 常量搜索** — `py_eval` 扫描 `.text` 中 `0x0022xxxx` 立即数
9. **IDA 批量 rename / set_comments**

---

## 安全评估（简要）

| 能力 | 风险 |
|------|------|
| 内核驱动 + 管理员 SDDL | 高权限，依赖 ACE 用户态组件配合 |
| 进程通知 / 白名单 | 监控特定游戏进程生命周期 |
| MmMapIoSpace / MmGetPhysicalAddress | 物理内存访问，可用于反作弊指纹 |
| BugCheck 回调 | 崩溃时注入数据，干扰 dump 分析 |
| TVM 混淆 | 刻意增加静态分析/签名难度 |
| 非标准 IOCTL 门控 | 未在追踪表登记的 IOCTL 直接拒绝 (0xC00000A3) |

**结论**：这是商业反作弊基础驱动，不是 CTF crackme。不存在单一“密码”；攻击面分析应聚焦 IOCTL 协议、filt 回调、与用户态 ACE 组件的通信协议。

---

## 后续建议

1. 动态调试：内核调试器附加，捕获 `\\.\Global\ACE-BASE` 的 IOCTL 流量
2. 对比新版 ACE-BASE.sys，diff TVM handler 签名
3. 关联用户态 `ACE-*.exe` / `SGuard64.exe` 还原完整协议
4. 对 `sub_140406DC1` 做 VM handler 语义 lifting（工作量大）

---

*报告生成时间：2026-06-21*
