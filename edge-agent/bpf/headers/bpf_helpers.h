/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Minimal BPF helpers header for Q-EDR eBPF programs.
 * Provides helper function declarations and map/program macros
 * compatible with the cilium/ebpf bpf2go toolchain.
 */

#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include "vmlinux.h"

/* BPF helper function return type */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Section attribute for BPF programs */
#define SEC(name) __attribute__((section(name), used))

/* Map definition macro */
struct {
	__uint(type, 0);
	__uint(max_entries, 0);
	__type(key, int);
	__type(value, int);
} __attribute__((preserve_access_index));

/* Clang built-in for BPF */
#define __bpf_unreachable() __builtin_trap()

/* Character/string operations */
#define bpf_memcpy __builtin_memcpy
#define bpf_memset __builtin_memset

/* Helper function IDs - these map to kernel BPF helper functions */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
static long (*bpf_probe_read_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 45;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;
static __u64 (*bpf_get_current_task)(void) = (void *) 35;
static long (*bpf_probe_read_kernel_str2)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *) 125;

/* License declaration macro */
#define LICENSE(name) char _license[] SEC("license") = name

/* Force emitting a global */
#define __always_inline inline __attribute__((always_inline))

/* Ring buffer flags */
#define BPF_RB_NO_WAKEUP  (1ULL << 0)
#define BPF_RB_FORCE_WAKEUP (1ULL << 1)

/* Map update flags */
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

#endif /* __BPF_HELPERS_H__ */
