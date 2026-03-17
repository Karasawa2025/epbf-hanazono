# eBPF Process, File, Network & Service Hider Demo

利用 eBPF 技术隐藏 Linux 进程、文件、网络连接和 systemd 服务的概念验证（PoC）程序。通过 hook `getdents64`、`tcp4/6_seq_show`、`write` 等系统调用/内核函数，在常用工具的输出中隐藏指定目标。

> **⚠ 仅供安全研究和学术用途。请勿在生产环境中使用。**

## 功能

| 功能 | Hook 点 | 影响范围 |
|------|---------|---------|
| **进程隐藏** | `getdents64` tracepoint | `ps`、`top`、`ls /proc/` |
| **文件隐藏** | `getdents64` tracepoint | `ls`、`find`、`readdir()` |
| **网络连接隐藏** | `tcp4/6_seq_show` kprobe + `read` tracepoint | `cat /proc/net/tcp[6]` |
| **systemd 服务隐藏** | `write` tracepoint + `bpf_probe_write_user` + `getdents64` | `systemctl list-units/list-unit-files/status`、`ls` 服务目录 |
| **自身隐藏** | 组合上述 | 进程 + 二进制文件同时隐藏 |

## 原理

### 四层架构

```
┌──────────────────────────────────────────────────────┐
│                    Kernel Space                       │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │  eBPF Programs                                  │  │
│  │                                                 │  │
│  │  [tracepoint] sys_enter/exit_getdents64:        │  │
│  │    → 扫描 dirent buffer                        │  │
│  │    → u64 快速匹配 PID / hash map 匹配文件      │  │
│  │    → 含 .service 文件名匹配                     │  │
│  │                                                 │  │
│  │  [kprobe] tcp4/6_seq_show:                      │  │
│  │    → 读取 struct sock 端口信息                 │  │
│  │    → 匹配 hide_ports_map → 标记 tid            │  │
│  │                                                 │  │
│  │  [tracepoint] sys_enter/exit_read:              │  │
│  │    → 检测被标记的 tid                          │  │
│  │    → 发送 net_hide_event 到 ringbuf            │  │
│  │                                                 │  │
│  │  [tracepoint] sys_enter_write:                  │  │
│  │    → 拦截 systemctl 的 stdout write            │  │
│  │    → bpf_probe_write_user 直接修改缓冲区       │  │
│  │    → BPF tail call 实现大缓冲区迭代扫描        │  │
│  │                                                 │  │
│  │  [tracepoint] sys_exit_write:                   │  │
│  │    → 发送日志事件到 ringbuf                    │  │
│  └────────────────────┬────────────────────────────┘  │
│                       │ ringbuf events                 │
├───────────────────────┼───────────────────────────────┤
│                       ▼                                │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Go Userspace Program                           │  │
│  │                                                 │  │
│  │  → 接收 ringbuf 事件                           │  │
│  │  → 区分事件类型 (PID / FILE / NET / SVC)       │  │
│  │  → 通过 /proc/<caller_pid>/mem 修改:           │  │
│  │    - dirent: 扩展 prev d_reclen 跳过条目       │  │
│  │    - net: 用空格覆盖匹配端口的文本行           │  │
│  │  → SVC 事件仅用于日志（修改在 BPF 中完成）    │  │
│  └─────────────────────────────────────────────────┘  │
│                    User Space                          │
└──────────────────────────────────────────────────────┘
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

#### systemd 服务隐藏

**双重隐藏策略:**

1. **服务文件隐藏** (getdents64 复用):
   - 将 `.service` 文件名加入 `file_name_map`
   - `ls /etc/systemd/system/`、`ls /lib/systemd/system/` 看不到文件
   - 影响 `systemctl list-unit-files`（底层使用 getdents64 扫描目录）

2. **systemctl 输出过滤** (sys_enter_write + bpf_probe_write_user):
   - 在 `sys_enter_write` 中拦截 comm="systemctl" 进程对 fd=1 (stdout) 的写操作
   - **在 write 系统调用执行前**，通过 `bpf_probe_write_user` 直接修改用户态缓冲区
   - 使用 `svc_name_map`（8字节前缀匹配）定位服务名在缓冲区中的位置
   - 匹配后用空格覆盖整行内容（保留换行符），使输出布局不变
   - 使用 **BPF tail call** (PROG_ARRAY map) 实现大缓冲区迭代扫描，每次处理 128 字节
   - 最大 tail call 深度 33 × 128 = 4224 字节，覆盖 systemctl 的完整输出
   - 影响 `systemctl list-units`、`systemctl status`

### 为什么使用 bpf_probe_write_user

systemctl 的 stdout `write()` 系统调用执行后，数据立即被内核拷贝到终端设备。使用 ringbuf → 用户态 → `/proc/pid/mem` 的异步方案无法在数据到达终端前完成修改。

因此，systemd 服务隐藏使用了 `bpf_probe_write_user` 在 `sys_enter_write` tracepoint 中**同步修改**用户态缓冲区，确保内核拷贝的是已经被清洗的数据。

进程/文件/网络隐藏仍使用 ringbuf + `/proc/pid/mem` 的用户态方案。

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
| Linux kernel | 5.8+ (需 BTF + kprobe + bpf_probe_write_user 支持) |
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

# 隐藏 systemd 服务（同时隐藏服务文件 + systemctl 输出）
sudo ./ebpf-hide-proc -hide-service my-backdoor.service

# 组合隐藏
sudo ./ebpf-hide-proc -hide-self-file -hide-file payload.bin -hide-port 4444 -hide-service my-backdoor.service
```

### 4. 验证

```bash
# 进程隐藏
ps aux | grep <PID>                              # 找不到

# 文件隐藏
ls -la /path/to/dir/                             # 看不到隐藏的文件

# 网络隐藏
cat /proc/net/tcp                                 # 对应端口的行被替换为空格

# 服务隐藏
systemctl list-units --type=service | grep xxx    # 找不到
systemctl list-unit-files --type=service          # 找不到
ls /etc/systemd/system/xxx.service                # 找不到
systemctl status xxx.service                      # 服务名行被清空

# 直接访问仍有效
cat /proc/<PID>/status                            # 进程信息仍可读
cat /path/to/secret.txt                           # 文件内容仍可读
ss -tln                                            # ss 使用 netlink，不受影响
systemctl is-active xxx.service                    # 服务状态仍可查
```

## BPF Maps 清单

| Map | 类型 | 用途 |
|-----|------|------|
| `args_map` | HASH | per-tid getdents64 dirent pointer |
| `pid_val_map` / `pid_mask_map` | ARRAY | PID 匹配值和掩码 |
| `file_name_map` | HASH | 文件名 8 字节前缀 → 1 |
| `hide_ports_map` | HASH | 端口号 → 1 |
| `net_match_map` | HASH | per-tid tcp_seq_show 匹配结果 |
| `read_args_map` | HASH | per-tid read() buf pointer |
| `write_args_map` | HASH | per-tid write() buf pointer |
| `svc_comm_map` | HASH | 进程 comm 前 8 字节 → 1 (filter) |
| `svc_name_map` | HASH | 服务名前 8 字节 → 1 (match) |
| `svc_progs` | PROG_ARRAY | tail call 目标程序 |
| `svc_state` | PERCPU_ARRAY | per-CPU 扫描状态 |
| `feature_map` | ARRAY | 功能开关 [pid, file, net, svc] |
| `events` | RINGBUF | 事件通道 (256KB) |

## 测试结果

在 AWS EC2 Debian 11 (kernel 5.10.0-38, ami-0b1e6494acfc67a42) 上测试:

```
=== eBPF Process, File, Network & Service Hider Demo ===
Target PID: 18081
Hide files: [ebpf-hide-proc test-hidden.service]
Hide services: [test-hidden.service]

--- systemctl list-units (HIDDEN) ---
  (test-hidden.service 不在列表中)

--- systemctl list-unit-files (HIDDEN) ---
  (test-hidden.service 不在列表中)

--- ls /etc/systemd/system/ (HIDDEN) ---
  (test-hidden.service 不在目录列表中)

--- systemctl status (HIDDEN) ---
  (服务名行被空白覆盖)

--- systemctl is-active (仍可查询) ---
  active

--- Events ---
[hide-svc #1] BPF scrubbed service output from PID 18123 (3494 bytes)
[hide-file #1] Removed 'test-hidden.service' from PID 18125's readdir
```

## 局限性

1. **网络隐藏范围**: 仅影响读取 `/proc/net/tcp[6]` 的工具。`ss` 和现代 `netstat` 使用 netlink socket，不受影响
2. **时序竞争**: 进程/文件/网络隐藏使用 ringbuf → 用户态方案，存在微秒级延迟
3. **服务隐藏缓冲区限制**: BPF tail call 最多扫描 ~4KB 的 write 缓冲区。超大的 systemctl 输出中末尾的服务可能无法隐藏
4. **文件名长度**: 文件名 > 7 字符时使用前缀匹配，可能产生误匹配
5. **需要 root 权限**: 加载 eBPF + kprobe + bpf_probe_write_user
6. **直接访问有效**: 知道路径/PID/服务名仍可直接查询

## 对抗检测

此隐藏方式可被以下方法检测:

- `ss -tln` / `ss -tn` (使用 netlink 获取连接)
- `stat("/proc/<PID>")` / `stat("/path/to/file")` 直接访问
- `systemctl is-active <service>` / `systemctl show <service>` (D-Bus 查询不受影响)
- `bpftool prog list` 查看已加载 eBPF 程序和 kprobe
- `bpftool map list` 查看活跃 BPF maps
- 审计 `/proc/net/tcp` 输出中的空行异常
- 审计 `systemctl list-units` 输出中的空白行异常
- `dmesg` 中的 kprobe 注册日志和 `bpf_probe_write_user` 警告

## 参考资料

- [cilium/ebpf](https://github.com/cilium/ebpf) — Go eBPF 库
- [Linux eBPF docs](https://docs.kernel.org/bpf/)
- [getdents64(2)](https://man7.org/linux/man-pages/man2/getdents64.2.html)
- [/proc/net/tcp](https://www.kernel.org/doc/html/latest/networking/proc_net_tcp.html)
- [bpf_probe_write_user](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) — BPF 用户态内存写入
- [BPF tail calls](https://docs.kernel.org/bpf/classic_vs_extended.html#tail-calls) — 程序链式调用
