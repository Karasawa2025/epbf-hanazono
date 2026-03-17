# eBPF Process, File & Network Hider Demo

利用 eBPF 技术隐藏 Linux 进程、文件和网络连接的概念验证（PoC）程序。通过 hook `getdents64` 和 `tcp4/6_seq_show` 等系统调用/内核函数，在常用工具的输出中隐藏指定目标。

> **⚠ 仅供安全研究和学术用途。请勿在生产环境中使用。**

## 功能

| 功能 | Hook 点 | 影响范围 |
|------|---------|---------|
| **进程隐藏** | `getdents64` tracepoint | `ps`、`top`、`ls /proc/` |
| **文件隐藏** | `getdents64` tracepoint | `ls`、`find`、`readdir()` |
| **网络连接隐藏** | `tcp4/6_seq_show` kprobe + `read` tracepoint | `cat /proc/net/tcp[6]` |
| **自身隐藏** | 组合上述 | 进程 + 二进制文件同时隐藏 |

## 原理

### 三层架构

```
┌──────────────────────────────────────────────────┐
│                    Kernel Space                   │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │  eBPF Programs                              │  │
│  │                                             │  │
│  │  [tracepoint] sys_enter/exit_getdents64:    │  │
│  │    → 扫描 dirent buffer                    │  │
│  │    → u64 快速匹配 PID / hash map 匹配文件  │  │
│  │                                             │  │
│  │  [kprobe] tcp4/6_seq_show:                  │  │
│  │    → 读取 struct sock 端口信息             │  │
│  │    → 匹配 hide_ports_map → 标记 tid        │  │
│  │                                             │  │
│  │  [tracepoint] sys_enter/exit_read:          │  │
│  │    → 检测被标记的 tid                      │  │
│  │    → 发送 net_hide_event 到 ringbuf        │  │
│  └────────────────────┬────────────────────────┘  │
│                       │ ringbuf events             │
├───────────────────────┼───────────────────────────┤
│                       ▼                            │
│  ┌─────────────────────────────────────────────┐  │
│  │  Go Userspace Program                       │  │
│  │                                             │  │
│  │  → 接收 ringbuf 事件                       │  │
│  │  → 区分事件类型 (PID / FILE / NET)         │  │
│  │  → 通过 /proc/<caller_pid>/mem 修改:       │  │
│  │    - dirent: 扩展 prev d_reclen 跳过条目   │  │
│  │    - net: 用空格覆盖匹配端口的文本行       │  │
│  └─────────────────────────────────────────────┘  │
│                    User Space                      │
└──────────────────────────────────────────────────┘
```

### 技术细节

#### 进程/文件隐藏
1. **sys_enter_getdents64**: 记录 dirent buffer 指针到 per-tid hash map
2. **sys_exit_getdents64**: 遍历 `linux_dirent64` 数组，PID 用 u64 快速比较，文件名用 hash map 查找
3. **补丁方式**: 修改前一条目的 `d_reclen` 使其跳过目标条目

#### 网络连接隐藏
1. **kprobe tcp4/6_seq_show**: 从 `struct sock` 中读取端口 (`skc_num` @offset 14, `skc_dport` @offset 12)，匹配则标记 tid
2. **sys_exit_read**: 如果 tid 被标记，发送事件（含用户态 read buffer 地址和长度）
3. **补丁方式**: 读取 read buffer 内容，逐行扫描 `/proc/net/tcp` 格式文本，用空格覆盖匹配行

### 为什么不直接使用 bpf_probe_write_user / bpf_override_return

Debian 11 kernel 5.10 编译配置中：
- `bpf_probe_write_user` 不可用于 tracepoint 程序
- `CONFIG_BPF_KPROBE_OVERRIDE` 未启用

因此所有修改均通过 ringbuf + `/proc/pid/mem` 的用户态方案实现。

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
| Linux kernel | 5.8+ (需 BTF + kprobe 支持) |
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
# 隐藏自身进程
sudo ./ebpf-hide-proc

# 隐藏指定 PID
sudo ./ebpf-hide-proc -pid 1234

# 隐藏自身进程 + 自身二进制文件
sudo ./ebpf-hide-proc -hide-self-file

# 隐藏指定文件
sudo ./ebpf-hide-proc -hide-file secret.txt

# 隐藏网络端口
sudo ./ebpf-hide-proc -hide-port 4444

# 组合隐藏
sudo ./ebpf-hide-proc -hide-self-file -hide-file payload.bin -hide-port 4444 -hide-port 8080
```

### 4. 验证

```bash
# 进程隐藏
ps aux | grep <PID>           # 找不到

# 文件隐藏
ls -la /path/to/dir/          # 看不到隐藏的文件

# 网络隐藏
cat /proc/net/tcp             # 对应端口的行被替换为空格
cat /proc/net/tcp6            # 同上

# 直接访问仍有效
cat /proc/<PID>/status        # 进程信息仍可读
cat /path/to/secret.txt       # 文件内容仍可读
ss -tln                        # ss 使用 netlink，不受影响
```

## 测试结果

在 AWS EC2 Debian 11 (kernel 5.10.0-38, ami-0b1e6494acfc67a42) 上测试:

```
=== eBPF Process, File & Network Hider Demo ===
Target PID: 13483
Hide ports: [22]

--- cat /proc/net/tcp (HIDDEN) ---
  sl  local_address rem_address   st ...
                                              (空行 - 端口22连接已隐藏)

--- cat /proc/net/tcp6 (HIDDEN) ---
  sl  local_address ... rem_address ... st ...
                                              (空行 - 端口22连接已隐藏)

--- Events ---
[hide-net #1] Scrubbed port 22 (remote 48976) from PID 13522's read buffer
[hide-net #2] Scrubbed port 22 (remote 48976) from PID 13524's read buffer
[hide-net #3] Scrubbed port 22 (remote 0) from PID 13525's read buffer
```

## 局限性

1. **网络隐藏范围**: 仅影响读取 `/proc/net/tcp[6]` 的工具。`ss` 和现代 `netstat` 使用 netlink socket，不受影响
2. **时序竞争**: ringbuf → 用户态 → `/proc/pid/mem` 写入存在微秒级延迟，首次访问可能不隐藏
3. **文件名长度**: 文件名 > 7 字符时使用前缀匹配 + 用户态验证
4. **需要 root 权限**: 加载 eBPF + kprobe + 写入 `/proc/pid/mem`
5. **直接访问有效**: 知道路径/PID 仍可直接访问

## 对抗检测

此隐藏方式可被以下方法检测:

- `ss -tln` / `ss -tn` (使用 netlink 获取连接)
- `stat("/proc/<PID>")` / `stat("/path/to/file")` 直接访问
- `bpftool prog list` 查看已加载 eBPF 程序和 kprobe
- `bpftool map list` 查看活跃 BPF maps
- 审计 `/proc/net/tcp` 输出中的空行异常
- `dmesg` 中的 kprobe 注册日志

## 参考资料

- [cilium/ebpf](https://github.com/cilium/ebpf) — Go eBPF 库
- [Linux eBPF docs](https://docs.kernel.org/bpf/)
- [getdents64(2)](https://man7.org/linux/man-pages/man2/getdents64.2.html)
- [/proc/net/tcp](https://www.kernel.org/doc/html/latest/networking/proc_net_tcp.html)
