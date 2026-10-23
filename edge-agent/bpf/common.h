/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Q-EDR common eBPF definitions shared across all probes.
 *
 * Defines the event structures that are passed from kernel eBPF programs
 * to user-space Go code via ring buffers. These structures must be kept
 * in sync with the corresponding Go types in the collector packages.
 */

#ifndef __QEDR_COMMON_H__
#define __QEDR_COMMON_H__

#include "headers/bpf_helpers.h"

/* Maximum string lengths in eBPF events */
#define MAX_COMM_LEN     16
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN     256
#define MAX_ARGV_LEN     256  /* First N bytes of argv concatenated */

/* Event type identifiers — must match Go constants */
#define EVENT_PROCESS_EXEC  1
#define EVENT_PROCESS_FORK  2
#define EVENT_PROCESS_EXIT  3
#define EVENT_NET_CONNECT   10
#define EVENT_NET_ACCEPT    11
#define EVENT_NET_BIND      12
#define EVENT_NET_CLOSE     13
#define EVENT_IPC_PIPE      20
#define EVENT_IPC_SOCKETPAIR 21
#define EVENT_IPC_SHMGET    22
#define EVENT_IPC_SHMAT     23
#define EVENT_IPC_MSGGET    24
#define EVENT_IPC_MSGSND    25
#define EVENT_IPC_MSGRCV    26
#define EVENT_IPC_SEMGET    27
#define EVENT_IPC_SEMOP     28
#define EVENT_FS_OPEN       30
#define EVENT_FS_WRITE      31
#define EVENT_FS_RENAME     32
#define EVENT_FS_UNLINK     33
#define EVENT_FS_MKDIR      34
#define EVENT_FS_CHMOD      35
#define EVENT_FS_CHOWN      36

/* Common event header — prepended to all events */
struct event_header {
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u64 timestamp_ns;  /* bpf_ktime_get_boot_ns() */
	__u64 cgroup_id;
	char  comm[MAX_COMM_LEN];
};

/* ========== Process Events ========== */

struct process_exec_event {
	struct event_header hdr;
	char filename[MAX_FILENAME_LEN];
	char argv[MAX_ARGV_LEN];
	__u32 argv_len;
	__s32 ret_code;
};

struct process_fork_event {
	struct event_header hdr;
	__u32 child_pid;
	__u32 child_tid;
	__u64 clone_flags;
	char  child_comm[MAX_COMM_LEN];
};

struct process_exit_event {
	struct event_header hdr;
	__s32 exit_code;
	__s32 signal;
	__u64 start_time_ns;
};

/* ========== Network Events ========== */

struct network_event {
	struct event_header hdr;
	__u16 family;     /* AF_INET, AF_INET6, AF_UNIX */
	__u16 protocol;   /* IPPROTO_TCP, IPPROTO_UDP */
	__u16 sport;      /* Source/local port */
	__u16 dport;      /* Dest/remote port */
	__u32 saddr[4];   /* Source address (v4 in [0], v6 in [0-3]) */
	__u32 daddr[4];   /* Dest address */
	__s32 ret_code;
	__s32 socket_fd;
	__s32 old_state;  /* For state change events */
	__s32 new_state;
	__s32 backlog;    /* For listen events */
};

/* ========== IPC Events ========== */

struct ipc_event {
	struct event_header hdr;
	__s32 fd0;        /* First FD (pipe read, socketpair fd0) */
	__s32 fd1;        /* Second FD (pipe write, socketpair fd1) */
	__s32 key;        /* SysV IPC key */
	__s32 ipc_id;     /* SysV IPC ID (shmid, msgid, semid) */
	__u64 size;       /* SHM size or message size */
	__s64 msg_type;   /* Message type for msgsnd/msgrcv */
	__s32 nsems;      /* Number of semaphores */
	__s32 nsops;      /* Number of semaphore operations */
	__s32 flags;      /* IPC flags */
	__s32 ret_code;
	__u16 family;     /* For socketpair: AF_UNIX */
	__u16 sock_type;  /* For socketpair: SOCK_STREAM, etc. */
	__s32 protocol;   /* For socketpair */
};

/* ========== Filesystem Events ========== */

struct fs_event {
	struct event_header hdr;
	char  path[MAX_PATH_LEN];
	char  path2[MAX_PATH_LEN]; /* For rename: new path */
	__s32 dir_fd;
	__s32 dir_fd2;    /* For rename: new dir fd */
	__s32 flags;
	__u32 mode;
	__s32 fd;
	__s32 ret_code;
	__u64 count;      /* Bytes requested (for write) */
	__s64 written;    /* Bytes written (for write) */
	__s32 owner_id;   /* For chown */
	__s32 group_id;   /* For chown */
};

#endif /* __QEDR_COMMON_H__ */
