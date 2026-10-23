// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Q-EDR Process Telemetry eBPF Probes
 *
 * Attaches to stable kernel tracepoints to observe:
 *   - sched/sched_process_exec  → process execution
 *   - sched/sched_process_fork  → process creation
 *   - sched/sched_process_exit  → process termination
 *
 * Events are sent to user-space via a BPF ring buffer.
 */

#include "common.h"

/* Ring buffer for sending events to user-space */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} process_events SEC(".maps");

/* Helper to populate common event header fields */
static __always_inline void fill_header(struct event_header *hdr, __u32 event_type) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	hdr->event_type = event_type;
	hdr->pid = pid_tgid >> 32;       /* tgid = user-space PID */
	hdr->tid = (__u32)pid_tgid;      /* pid = kernel thread ID */
	hdr->uid = (__u32)uid_gid;
	hdr->gid = uid_gid >> 32;
	hdr->timestamp_ns = bpf_ktime_get_boot_ns();
	hdr->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(hdr->comm, sizeof(hdr->comm));

	/* PPID requires reading from the task_struct; set to 0 as fallback.
	 * User-space enriches PPID from /proc if needed. */
	hdr->ppid = 0;
}

/*
 * Tracepoint: sched/sched_process_exec
 *
 * Fires when a process calls execve() successfully.
 * Tracepoint format (from /sys/kernel/debug/tracing/events/sched/sched_process_exec/format):
 *   field: char filename[];  offset:8;  size:4;  signed:0;
 *   field: pid_t pid;        offset:12; size:4;  signed:1;
 *   field: pid_t old_pid;    offset:16; size:4;  signed:1;
 */
struct sched_process_exec_args {
	struct trace_entry ent;
	__u32 __data_loc_filename;
	__s32 pid;
	__s32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__process_exec(struct sched_process_exec_args *ctx) {
	struct process_exec_event *evt;

	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_PROCESS_EXEC);

	/* Read filename from tracepoint data location.
	 * The __data_loc format stores offset in low 16 bits, length in high 16 bits. */
	unsigned short off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(evt->filename, sizeof(evt->filename),
			   (void *)ctx + off);

	evt->argv_len = 0;
	evt->ret_code = 0; /* exec tracepoint fires on success */

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Tracepoint: sched/sched_process_fork
 *
 * Fires when a process calls fork/clone/vfork.
 * Format:
 *   field: char parent_comm[16]; offset:8;  size:16;
 *   field: pid_t parent_pid;     offset:24; size:4;
 *   field: char child_comm[16];  offset:28; size:16;
 *   field: pid_t child_pid;      offset:44; size:4;
 */
struct sched_process_fork_args {
	struct trace_entry ent;
	char   parent_comm[MAX_COMM_LEN];
	__s32  parent_pid;
	char   child_comm[MAX_COMM_LEN];
	__s32  child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__process_fork(struct sched_process_fork_args *ctx) {
	struct process_fork_event *evt;

	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_PROCESS_FORK);
	evt->hdr.ppid = evt->hdr.pid; /* Parent is the current process */

	evt->child_pid = ctx->child_pid;
	evt->child_tid = ctx->child_pid;
	evt->clone_flags = 0; /* Not available from this tracepoint */
	bpf_probe_read_kernel(evt->child_comm, sizeof(evt->child_comm),
			      ctx->child_comm);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Tracepoint: sched/sched_process_exit
 *
 * Fires when a process (or thread) exits.
 * Format:
 *   field: char comm[16]; offset:8;  size:16;
 *   field: pid_t pid;     offset:24; size:4;
 *   field: int prio;      offset:28; size:4;
 */
struct sched_process_exit_args {
	struct trace_entry ent;
	char  comm[MAX_COMM_LEN];
	__s32 pid;
	__s32 prio;
};

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__process_exit(struct sched_process_exit_args *ctx) {
	struct process_exit_event *evt;

	/* Only report thread-group leaders (PID == TID) to avoid
	 * duplicate exit events for multi-threaded processes. */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	if (pid != tid)
		return 0;

	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_PROCESS_EXIT);

	/* Exit code is not directly available from this tracepoint.
	 * Set to 0; user-space can attempt to read /proc before cleanup. */
	evt->exit_code = 0;
	evt->signal = 0;
	evt->start_time_ns = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

LICENSE("Dual BSD/GPL");
