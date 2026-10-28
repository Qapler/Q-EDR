// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Q-EDR IPC Telemetry eBPF Probes
 *
 * Observes IPC activity via syscall tracepoints:
 *   - syscalls/sys_exit_pipe2      → pipe creation
 *   - syscalls/sys_exit_socketpair → UNIX socket pair creation
 *   - syscalls/sys_enter_shmget    → shared memory creation/access
 *   - syscalls/sys_enter_shmat     → shared memory attach
 *   - syscalls/sys_enter_msgget    → message queue creation/access
 *   - syscalls/sys_enter_msgsnd    → message queue send
 *   - syscalls/sys_enter_msgrcv    → message queue receive
 *   - syscalls/sys_enter_semget    → semaphore creation
 *   - syscalls/sys_enter_semop     → semaphore operation
 */

#include "common.h"

/*
 * Syscall tracepoint records store every argument in an 8-byte slot starting
 * at offset 16 (see /sys/kernel/tracing/events/syscalls/<name>/format), so int
 * arguments that follow other ints are declared 64-bit and narrowed on read.
 */

/* Force emitting event structs into BTF so bpf2go -type can generate Go types. */
const struct ipc_event *unused_ipc_event __attribute__((unused));

/* Ring buffer for IPC events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MB */
} ipc_events SEC(".maps");

/* Temp storage for pipe2 enter→exit correlation */
struct pipe_args {
	__u64 fildes; /* User pointer to int[2] (as u64: bpf2go can't map pointers) */
	__s32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct pipe_args);
} pipe_args_map SEC(".maps");

/* Temp storage for socketpair enter→exit */
struct socketpair_args {
	__u64 usockvec; /* User pointer to int[2] (as u64: bpf2go can't map pointers) */
	__u16 family;
	__u16 type;
	__s32 protocol;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct socketpair_args);
} socketpair_args_map SEC(".maps");

/* ========== Pipe Events ========== */

struct sys_enter_pipe2_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	const void *fildes;
	__s32 flags;
};

SEC("tracepoint/syscalls/sys_enter_pipe2")
int tracepoint__syscalls__sys_enter_pipe2(struct sys_enter_pipe2_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pipe_args args = {
		.fildes = (__u64)ctx->fildes,
		.flags = ctx->flags,
	};
	bpf_map_update_elem(&pipe_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

struct sys_exit_pipe2_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_pipe2")
int tracepoint__syscalls__sys_exit_pipe2(struct sys_exit_pipe2_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pipe_args *args;

	args = bpf_map_lookup_elem(&pipe_args_map, &pid_tgid);
	if (!args)
		return 0;

	if (ctx->ret != 0)
		goto cleanup;

	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_header(&evt->hdr, EVENT_IPC_PIPE);

	/* Read the pipe FDs from user memory */
	int fds[2] = {-1, -1};
	bpf_probe_read_user(fds, sizeof(fds), (const void *)args->fildes);
	evt->fd0 = fds[0]; /* read end */
	evt->fd1 = fds[1]; /* write end */
	evt->flags = args->flags;
	evt->ret_code = (__s32)ctx->ret;
	evt->key = 0;
	evt->ipc_id = 0;
	evt->size = 0;
	evt->msg_type = 0;
	evt->nsems = 0;
	evt->nsops = 0;
	evt->family = 0;
	evt->sock_type = 0;
	evt->protocol = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&pipe_args_map, &pid_tgid);
	return 0;
}

/* ========== Socketpair Events ========== */

struct sys_enter_socketpair_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s64 family;
	__s64 type;
	__s64 protocol;
	const void *usockvec;
};

SEC("tracepoint/syscalls/sys_enter_socketpair")
int tracepoint__syscalls__sys_enter_socketpair(struct sys_enter_socketpair_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct socketpair_args args = {
		.usockvec = (__u64)ctx->usockvec,
		.family = (__u16)ctx->family,
		.type = (__u16)ctx->type,
		.protocol = (__s32)ctx->protocol,
	};
	bpf_map_update_elem(&socketpair_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

struct sys_exit_socketpair_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_socketpair")
int tracepoint__syscalls__sys_exit_socketpair(struct sys_exit_socketpair_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct socketpair_args *args;

	args = bpf_map_lookup_elem(&socketpair_args_map, &pid_tgid);
	if (!args)
		return 0;

	if (ctx->ret != 0)
		goto cleanup;

	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_header(&evt->hdr, EVENT_IPC_SOCKETPAIR);

	int fds[2] = {-1, -1};
	bpf_probe_read_user(fds, sizeof(fds), (const void *)args->usockvec);
	evt->fd0 = fds[0];
	evt->fd1 = fds[1];
	evt->family = args->family;
	evt->sock_type = args->type;
	evt->protocol = args->protocol;
	evt->flags = 0;
	evt->ret_code = 0;
	evt->key = 0;
	evt->ipc_id = 0;
	evt->size = 0;
	evt->msg_type = 0;
	evt->nsems = 0;
	evt->nsops = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&socketpair_args_map, &pid_tgid);
	return 0;
}

/* ========== SysV Shared Memory ========== */

struct sys_enter_shmget_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 key;
	__u64 size;
	__s32 shmflg;
};

SEC("tracepoint/syscalls/sys_enter_shmget")
int tracepoint__syscalls__sys_enter_shmget(struct sys_enter_shmget_args *ctx) {
	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_IPC_SHMGET);
	evt->key = ctx->key;
	evt->size = ctx->size;
	evt->flags = ctx->shmflg;
	evt->fd0 = -1;
	evt->fd1 = -1;
	evt->ipc_id = 0;
	evt->msg_type = 0;
	evt->nsems = 0;
	evt->nsops = 0;
	evt->ret_code = 0;
	evt->family = 0;
	evt->sock_type = 0;
	evt->protocol = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========== SysV Message Queues ========== */

struct sys_enter_msgget_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s64 key;
	__s64 msgflg;
};

SEC("tracepoint/syscalls/sys_enter_msgget")
int tracepoint__syscalls__sys_enter_msgget(struct sys_enter_msgget_args *ctx) {
	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_IPC_MSGGET);
	evt->key = (__s32)ctx->key;
	evt->flags = (__s32)ctx->msgflg;
	evt->fd0 = -1;
	evt->fd1 = -1;
	evt->ipc_id = 0;
	evt->size = 0;
	evt->msg_type = 0;
	evt->nsems = 0;
	evt->nsops = 0;
	evt->ret_code = 0;
	evt->family = 0;
	evt->sock_type = 0;
	evt->protocol = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

struct sys_enter_msgsnd_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 msqid;
	const void *msgp;
	__u64 msgsz;
	__s32 msgflg;
};

SEC("tracepoint/syscalls/sys_enter_msgsnd")
int tracepoint__syscalls__sys_enter_msgsnd(struct sys_enter_msgsnd_args *ctx) {
	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_IPC_MSGSND);
	evt->ipc_id = ctx->msqid;
	evt->size = ctx->msgsz;
	evt->flags = ctx->msgflg;

	/* Read message type from user memory (first field of struct msgbuf) */
	__s64 mtype = 0;
	bpf_probe_read_user(&mtype, sizeof(mtype), ctx->msgp);
	evt->msg_type = mtype;

	evt->key = 0;
	evt->fd0 = -1;
	evt->fd1 = -1;
	evt->nsems = 0;
	evt->nsops = 0;
	evt->ret_code = 0;
	evt->family = 0;
	evt->sock_type = 0;
	evt->protocol = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========== SysV Semaphores ========== */

struct sys_enter_semget_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s64 key;
	__s64 nsems;
	__s64 semflg;
};

SEC("tracepoint/syscalls/sys_enter_semget")
int tracepoint__syscalls__sys_enter_semget(struct sys_enter_semget_args *ctx) {
	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_IPC_SEMGET);
	evt->key = (__s32)ctx->key;
	evt->nsems = (__s32)ctx->nsems;
	evt->flags = (__s32)ctx->semflg;
	evt->fd0 = -1;
	evt->fd1 = -1;
	evt->ipc_id = 0;
	evt->size = 0;
	evt->msg_type = 0;
	evt->nsops = 0;
	evt->ret_code = 0;
	evt->family = 0;
	evt->sock_type = 0;
	evt->protocol = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

struct sys_enter_semop_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 semid;
	const void *tsops;
	__u32 nsops;
};

/* glibc implements semop() with semtimedop(), whose leading arguments
 * (semid, tsops, nsops) share this layout; both tracepoints use this body. */
static __always_inline int handle_semop(struct sys_enter_semop_args *ctx) {
	struct ipc_event *evt;
	evt = bpf_ringbuf_reserve(&ipc_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_IPC_SEMOP);
	evt->ipc_id = ctx->semid;
	evt->nsops = (__s32)ctx->nsops;
	evt->key = 0;
	evt->fd0 = -1;
	evt->fd1 = -1;
	evt->size = 0;
	evt->msg_type = 0;
	evt->nsems = 0;
	evt->flags = 0;
	evt->ret_code = 0;
	evt->family = 0;
	evt->sock_type = 0;
	evt->protocol = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semop")
int tracepoint__syscalls__sys_enter_semop(struct sys_enter_semop_args *ctx) {
	return handle_semop(ctx);
}

SEC("tracepoint/syscalls/sys_enter_semtimedop")
int tracepoint__syscalls__sys_enter_semtimedop(struct sys_enter_semop_args *ctx) {
	return handle_semop(ctx);
}

LICENSE("Dual BSD/GPL");
