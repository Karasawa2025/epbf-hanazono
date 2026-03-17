# eBPF Process Hider Demo

利用 eBPF 技术隐藏 Linux 进程的概念验证（PoC）程序。通过 hook `getdents64` 系统调用，在 `ps`、`top` 等工具的输出中隐藏指定进程。

> **⚠ 仅供安全研究和学术用途。请勿在生产环境中使用。**

## 原理

### 双组件架构

```
┌──────────────────────────────────────────────┐
│                   Kernel Space               │
│                                              │
│  ┌───────────────────────────────────────┐   │
│  │  eBPF Program (tracepoint hooks)      │   │
│  │                                       │   │
│  │  sys_enter_getdents64:                │   │
│  │    → 记录 dirent buffer 地址          │   │
│  │                                       │   │
│  │  sys_exit_getdents64:                 │   │
│  │    → 扫描 dirent buffer              │   │
│  │    → u64 快速匹配 PID 字符串         │   │
│  │    → 匹配成功 → 发送事件到 ringbuf    │   │
│  └───────────────────┬───────────────────┘   │
│                      │ ringbuf event          │
├──────────────────────┼───────────────────────┤
│                      ▼                        │
│  ┌───────────────────────────────────────┐   │
│  │  Go Userspace Program                 │   │
│  │                                       │   │
│  │  → 接收 ringbuf 事件                 │   │
│  │  → 通过 /proc/<caller_pid>/mem       │   │
│  │    修改调用者的 dirent buffer         │   │
│  │  → 扩展前一条目的 d_reclen           │   │
│  │    跳过目标 PID 条目                 │   │
│  └───────────────────────────────────────┘   │
│                   User Space                  │
└──────────────────────────────────────────────┘
```

### 技术细节

1. **sys_enter_getdents64**: 通过 `bpf_probe_read(ctx+24)` 读取 `dirent` 指针，存入 per-tid hash map
2. **sys_exit_getdents64**: 遍历用户态 `linux_dirent64` 数组，将 PID 字符串编码为 u64 进行快速比较
3. **隐藏机制**: 通过 ringbuf 通知用户态，用户态打开 `/proc/<caller_pid>/mem` 修改前一条目的 `d_reclen` 使其跳过目标条目
4. **性能优化**: PID 字符串作为 u64 存储，单次比较完成匹配，支持 256 次循环迭代

### 为什么不直接使用 bpf_probe_write_user

Debian 11 的 kernel 5.10 编译配置中，`bpf_probe_write_user` 不可用于 tracepoint 类型的 BPF 程序。因此采用 ringbuf + `/proc/pid/mem` 的双组件方案。

## 项目结构

```
ebpf-hide-proc/
├── bpf/
│   └── hide_proc.c          # eBPF 内核态 C 程序
├── main.go                   # Go 用户态控制程序
├── go.mod                    # Go module (cilium/ebpf v0.13.2)
├── Makefile                  # 构建系统
├── setup_debian11.sh         # Debian 11 一键环境配置
└── README.md
```

## 系统要求

| 组件 | 版本 |
|------|------|
| Linux kernel | 5.8+ (需 BTF: `/sys/kernel/btf/vmlinux`) |
| Go | 1.21+ |
| Clang/LLVM | 11+ |
| libbpf | 0.3+ |

## 快速开始

### 1. 环境准备（Debian 11）

```bash
chmod +x setup_debian11.sh
sudo ./setup_debian11.sh
source /etc/profile.d/go.sh
```

### 2. 构建

```bash
make          # vmlinux.h → bpf2go → go build
```

### 3. 运行

```bash
# 隐藏自身
sudo ./ebpf-hide-proc

# 隐藏指定 PID
sudo ./ebpf-hide-proc -pid 1234
```

### 4. 验证

```bash
# 隐藏效果 (进程不可见)
ps aux | grep <PID>           # 找不到
ps -ef | grep <PID>           # 找不到

# 直接访问仍有效
cat /proc/<PID>/cmdline       # 仍可读
cat /proc/<PID>/status        # 仍可读

# eBPF 日志
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 测试结果

在 AWS EC2 Debian 11 (kernel 5.10.0-38, ami-0b1e6494acfc67a42) 上测试:

```
=== Target PID: 12266 ===

--- ps aux ---     HIDDEN!
--- ps -ef ---     HIDDEN!
--- Direct access ---
Name:   sleep
State:  S (sleeping)

--- Hider events ---
[hide #1] Removed '12266' from PID 12276's readdir (offset=3736)
[hide #2] Removed '12266' from PID 12279's readdir (offset=3736)
```

## 局限性

1. **仅隐藏于 `ps`/`top`**: 对 `ls /proc/` 的隐藏效果不稳定（时序竞争）
2. **需要 root 权限**: 加载 eBPF + 写入 `/proc/pid/mem`
3. **单 PID**: 一次隐藏一个 PID（可扩展）
4. **依赖 BTF**: 内核需编译 `CONFIG_DEBUG_INFO_BTF=y`
5. **用户态时序**: ringbuf → 用户态 → 写 `/proc/pid/mem` 存在微秒级延迟

## 对抗检测

此隐藏方式可被以下方法检测:

- `stat("/proc/<PID>")` 或 `open("/proc/<PID>/status")` 直接访问
- `bpftool prog list` 查看已加载 eBPF 程序
- `bpftool map list` 查看活跃 BPF maps
- 审计 `/proc` 条目的序列连续性

## 参考资料

- [cilium/ebpf](https://github.com/cilium/ebpf) — Go eBPF 库
- [Linux eBPF docs](https://docs.kernel.org/bpf/)
- [getdents64(2)](https://man7.org/linux/man-pages/man2/getdents64.2.html)
