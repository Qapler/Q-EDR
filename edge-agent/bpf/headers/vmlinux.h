/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Minimal vmlinux type subset for Q-EDR eBPF programs.
 *
 * These definitions provide the kernel types needed by our eBPF probes
 * without requiring a full vmlinux.h generated from BTF. This allows
 * development and compilation on systems without BTF support.
 *
 * For production use with CO-RE, generate vmlinux.h from a target kernel:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;

typedef signed char    __s8;
typedef signed short   __s16;
typedef signed int     __s32;
typedef signed long long __s64;

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef _Bool bool;

#define true  1
#define false 0
#define NULL  ((void *)0)

/* BPF helper definitions */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* Address families */
#define AF_UNSPEC   0
#define AF_UNIX     1
#define AF_INET     2
#define AF_INET6    10

/* Socket types */
#define SOCK_STREAM    1
#define SOCK_DGRAM     2
#define SOCK_SEQPACKET 5

/* TCP states */
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,
	TCP_NEW_SYN_RECV,
	TCP_MAX_STATES
};

/* Open flags */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR     0x0002
#define O_CREAT    0x0040
#define O_EXCL     0x0080
#define O_TRUNC    0x0200
#define O_APPEND   0x0400
#define O_NONBLOCK 0x0800
#define O_DIRECTORY 0x10000

/* unlinkat flags */
#define AT_REMOVEDIR 0x200
#define AT_FDCWD     (-100)

/* IPC flags */
#define IPC_CREAT  0x0200
#define IPC_EXCL   0x0400
#define IPC_PRIVATE 0

/* Tracepoint context structures */
struct trace_entry {
	unsigned short type;
	unsigned char  flags;
	unsigned char  preempt_count;
	int            pid;
};

/* Task structure fields we need */
struct task_struct {
	int pid;
	int tgid;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
